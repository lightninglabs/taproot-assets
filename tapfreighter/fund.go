package tapfreighter

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"golang.org/x/exp/maps"
)

// createFundedPacketWithInputs funds a set of virtual transaction with the
// given inputs. A new vPacket is created for each tranche of the active asset
// (which is the one specified in the funding descriptor, which is either a
// single asset ID/tranche or group key with multiple tranches).
func createFundedPacketWithInputs(ctx context.Context, exporter proof.Exporter,
	keyRing KeyRing, addrBook AddrBook, fundDesc *tapsend.FundingDescriptor,
	vPktTemplate *tappsbt.VPacket,
	selectedCommitments []*AnchoredCommitment) (*FundedVPacket, error) {

	if vPktTemplate.ChainParams == nil {
		return nil, errors.New("chain params not set in virtual packet")
	}
	chainParams := vPktTemplate.ChainParams

	log.Infof("Selected %v asset inputs for send of %d to %s",
		len(selectedCommitments), fundDesc.Amount,
		&fundDesc.AssetSpecifier)

	var inputSum uint64
	inputProofs := make(
		map[asset.PrevID]*proof.Proof, len(selectedCommitments),
	)
	selectedCommitmentsByPrevID := make(
		map[asset.PrevID]*AnchoredCommitment, len(selectedCommitments),
	)
	for _, anchorAsset := range selectedCommitments {
		// We only use the inputs of assets of the same TAP commitment
		// as we want to fund for. These are the active assets that
		// we're going to distribute. All other assets are passive and
		// will be detected and added later.
		if anchorAsset.Asset.TapCommitmentKey() !=
			fundDesc.TapCommitmentKey() {

			continue
		}

		// We'll also include an inclusion proof for the input asset in
		// the virtual transaction. With that a signer can verify that
		// the asset was actually committed to in the anchor output.
		inputProof, err := fetchInputProof(
			ctx, exporter, anchorAsset.Asset,
			anchorAsset.AnchorPoint,
		)
		if err != nil {
			return nil, fmt.Errorf("error fetching input proof: %w",
				err)
		}

		inputSum += anchorAsset.Asset.Amount
		inputProofs[anchorAsset.PrevID()] = inputProof
		selectedCommitmentsByPrevID[anchorAsset.PrevID()] = anchorAsset
	}

	// We try to identify and annotate any script keys in the template that
	// might be ours.
	err := annotateLocalScriptKeys(ctx, vPktTemplate, addrBook)
	if err != nil {
		return nil, fmt.Errorf("error annotating local script "+
			"keys: %w", err)
	}

	allocations, interactive, err := tapsend.AllocationsFromTemplate(
		vPktTemplate, inputSum,
	)
	if err != nil {
		return nil, fmt.Errorf("error extracting allocations: %w", err)
	}

	allPackets, err := tapsend.DistributeCoins(
		maps.Values(inputProofs), allocations, chainParams, interactive,
		vPktTemplate.Version,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to distribute coins: %w", err)
	}

	// Add all the input information to the virtual packets and also make
	// sure we have proper change output keys for non-zero change outputs.
	for _, vPkt := range allPackets {
		for idx := range vPkt.Inputs {
			prevID := vPkt.Inputs[idx].PrevID
			assetInput, ok := selectedCommitmentsByPrevID[prevID]
			if !ok {
				return nil, fmt.Errorf("input commitment not "+
					"found for prevID %v", prevID)
			}

			inputProof, ok := inputProofs[prevID]
			if !ok {
				return nil, fmt.Errorf("input proof not found "+
					"for prevID %v", prevID)
			}

			err = createAndSetInput(
				vPkt, idx, assetInput, inputProof,
			)
			if err != nil {
				return nil, fmt.Errorf("unable to create and "+
					"set input: %w", err)
			}
		}

		err = deriveChangeOutputKey(ctx, vPkt, keyRing)
		if err != nil {
			return nil, fmt.Errorf("unable to derive change "+
				"output key: %w", err)
		}
	}

	// Before we can prepare output assets for our send, we need to generate
	// a new internal key for the anchor outputs. We assume any output that
	// hasn't got an internal key set is going to a local anchor, and we
	// provide the internal key for that.
	err = generateOutputAnchorInternalKeys(ctx, allPackets, keyRing)
	if err != nil {
		return nil, fmt.Errorf("unable to generate output anchor "+
			"internal keys: %w", err)
	}

	for _, vPkt := range allPackets {
		if err := tapsend.PrepareOutputAssets(ctx, vPkt); err != nil {
			log.Errorf("Error preparing output assets: %v, "+
				"packets: %v", err, limitSpewer.Sdump(vPkt))
			return nil, fmt.Errorf("unable to prepare outputs: %w",
				err)
		}
	}

	// Extract just the TAP commitments by input from the selected anchored
	// commitments.
	inputCommitments := make(
		tappsbt.InputCommitments, len(selectedCommitmentsByPrevID),
	)
	for prevID, anchorAsset := range selectedCommitmentsByPrevID {
		inputCommitments[prevID] = anchorAsset.Commitment
	}

	return &FundedVPacket{
		VPackets:         allPackets,
		InputCommitments: inputCommitments,
	}, nil
}

// annotateLocalScriptKeys annotates the local script keys in the given virtual
// packet with the full descriptor information.
func annotateLocalScriptKeys(ctx context.Context, vPkt *tappsbt.VPacket,
	addrBook AddrBook) error {

	// We want to know if we are sending to ourselves. We detect that by
	// looking at the key descriptor of the script key. Because that is not
	// part of addresses and might not be specified by the user through the
	// PSBT interface, we now attempt to detect all local script keys and
	// mark them as such by filling in the descriptor.
	for idx := range vPkt.Outputs {
		vOut := vPkt.Outputs[idx]

		tweakedKey, err := addrBook.FetchScriptKey(
			ctx, vOut.ScriptKey.PubKey,
		)
		switch {
		case err == nil:
			// We found a tweaked key for this output, so we'll
			// update the key with the full descriptor info.
			vOut.ScriptKey.TweakedScriptKey = tweakedKey

		case errors.Is(err, address.ErrScriptKeyNotFound):
			// This is not a local key, or at least we don't know of
			// it in the database.
			continue

		default:
			return fmt.Errorf("cannot fetch script key: %w", err)
		}
	}

	return nil
}

// deriveChangeOutputKey makes sure the change output has a proper key that goes
// back to the local node, assuming there is a change output and it isn't a
// zero-value tombstone.
func deriveChangeOutputKey(ctx context.Context, vPkt *tappsbt.VPacket,
	keyRing KeyRing) error {

	// If we don't have a split output then there's no change.
	if !vPkt.HasSplitRootOutput() {
		return nil
	}

	changeOut, err := vPkt.SplitRootOutput()
	if err != nil {
		return err
	}

	// Since we know we're going to receive some change back, we need to
	// make sure it is going to an address that we control. This should only
	// be the case where we create the default change output with the NUMS
	// key to avoid deriving too many keys prematurely. We don't need to
	// derive a new key if we only have passive assets to commit to, since
	// they all have their own script key and the output is more of a
	// placeholder to attach the passive assets to.
	unSpendable, err := changeOut.ScriptKey.IsUnSpendable()
	if err != nil {
		return fmt.Errorf("cannot determine if script key is "+
			"spendable: %w", err)
	}
	if unSpendable && changeOut.Amount > 0 {
		changeScriptKey, err := keyRing.DeriveNextKey(
			ctx, asset.TaprootAssetsKeyFamily,
		)
		if err != nil {
			return err
		}

		// We'll assume BIP-0086 everywhere, and use the tweaked
		// key from here on out.
		changeOut.ScriptKey = asset.NewScriptKeyBip86(
			changeScriptKey,
		)
	}

	return nil
}

// vOutAnchor is a helper struct that holds the anchor output information that
// might be set on a virtual output.
type vOutAnchor struct {
	internalKey     *btcec.PublicKey
	derivation      []*psbt.Bip32Derivation
	trDerivation    []*psbt.TaprootBip32Derivation
	siblingPreimage *commitment.TapscriptPreimage
}

// newVOutAnchor creates a new vOutAnchor from the given virtual output.
func newVOutAnchor(vOut *tappsbt.VOutput) vOutAnchor {
	return vOutAnchor{
		internalKey:     vOut.AnchorOutputInternalKey,
		derivation:      vOut.AnchorOutputBip32Derivation,
		trDerivation:    vOut.AnchorOutputTaprootBip32Derivation,
		siblingPreimage: vOut.AnchorOutputTapscriptSibling,
	}
}

// applyFields applies the anchor output information from the given vOutAnchor
// to the given virtual output.
func (a vOutAnchor) applyFields(vOut *tappsbt.VOutput) {
	vOut.AnchorOutputInternalKey = a.internalKey
	vOut.AnchorOutputBip32Derivation = a.derivation
	vOut.AnchorOutputTaprootBip32Derivation = a.trDerivation
	vOut.AnchorOutputTapscriptSibling = a.siblingPreimage
}

// generateOutputAnchorInternalKeys generates internal keys for the anchor
// outputs of the given virtual packets. If an output already has an internal
// key set, it will be used. If not, a new key will be derived and set.
// At the same time we make sure that we don't use different keys for the same
// anchor output index in case there are multiple packets.
func generateOutputAnchorInternalKeys(ctx context.Context,
	packets []*tappsbt.VPacket, keyRing KeyRing) error {

	// We need to make sure we don't use different keys for the same anchor
	// output index in case there are multiple packets. So we'll keep track
	// of any set keys here. This will be a merged set of existing and new
	// keys.
	anchorKeys := make(map[uint32]vOutAnchor)

	// extractAnchorKey is a helper function that extracts the anchor key
	// from a virtual output and makes sure it is consistent with the
	// existing anchor keys from previous outputs of the same or different
	// packets.
	extractAnchorKey := func(vOut *tappsbt.VOutput) error {
		if vOut.AnchorOutputInternalKey == nil {
			return nil
		}

		anchorIndex := vOut.AnchorOutputIndex
		anchorKey := vOut.AnchorOutputInternalKey

		// Handle the case where we already have an anchor defined for
		// this index.
		if _, ok := anchorKeys[anchorIndex]; ok {
			existingPubKey := anchorKeys[anchorIndex].internalKey
			if !existingPubKey.IsEqual(anchorKey) {
				return fmt.Errorf("anchor output index %d "+
					"already has a different internal key "+
					"set: %x", anchorIndex,
					existingPubKey.SerializeCompressed())
			}

			// The keys are the same, so this is already correct.
			return nil
		}

		// There is no anchor yet, so we add it to the map.
		anchorKeys[anchorIndex] = newVOutAnchor(vOut)

		return nil
	}

	// Do a first pass through all packets to collect all existing anchor
	// keys. At the same time we make sure we don't already have diverging
	// information.
	for _, vPkt := range packets {
		for _, vOut := range vPkt.Outputs {
			if err := extractAnchorKey(vOut); err != nil {
				return err
			}
		}
	}

	// We now do a second pass through all packets and set the internal keys
	// for all outputs that don't have one yet. If we don't have any key for
	// an output index, we create a new one.
	// nolint: lll
	for _, vPkt := range packets {
		for idx := range vPkt.Outputs {
			vOut := vPkt.Outputs[idx]
			anchorIndex := vOut.AnchorOutputIndex

			// Skip any outputs that already have an internal key.
			if vOut.AnchorOutputInternalKey != nil {
				continue
			}

			// Check if we can use an existing key for this output
			// index.
			existingAnchor, ok := anchorKeys[anchorIndex]
			if ok {
				existingAnchor.applyFields(vOut)

				continue
			}

			newInternalKey, err := keyRing.DeriveNextKey(
				ctx, asset.TaprootAssetsKeyFamily,
			)
			if err != nil {
				return err
			}
			vOut.SetAnchorInternalKey(
				newInternalKey, vPkt.ChainParams.HDCoinType,
			)

			// Store this anchor information in case we have other
			// outputs in other packets that need it.
			anchorKeys[anchorIndex] = newVOutAnchor(vOut)
		}
	}

	return nil
}

// createAndSetInput creates a virtual packet input for the given asset input
// and sets it on the given virtual packet.
func createAndSetInput(vPkt *tappsbt.VPacket, idx int,
	assetInput *AnchoredCommitment, inputProof *proof.Proof) error {

	internalKey := assetInput.InternalKey
	derivation, trDerivation := tappsbt.Bip32DerivationFromKeyDesc(
		internalKey, vPkt.ChainParams.HDCoinType,
	)

	anchorPkScript, anchorMerkleRoot, _, err := tapsend.AnchorOutputScript(
		internalKey.PubKey, assetInput.TapscriptSibling,
		assetInput.Commitment,
	)
	if err != nil {
		return fmt.Errorf("cannot calculate input asset pk script: %w",
			err)
	}

	// Check if this is the anchorPkScript (and indirectly the
	// anchorMerkleRoot) we expect. If not this might be a non-V2
	// commitment.
	anchorTxOut := inputProof.AnchorTx.TxOut[assetInput.AnchorPoint.Index]
	if !bytes.Equal(anchorTxOut.PkScript, anchorPkScript) {
		var err error

		inputCommitment, err := assetInput.Commitment.Downgrade()
		if err != nil {
			return fmt.Errorf("cannot downgrade commitment: %w",
				err)
		}

		//nolint:lll
		anchorPkScript, anchorMerkleRoot, _, err = tapsend.AnchorOutputScript(
			internalKey.PubKey, assetInput.TapscriptSibling,
			inputCommitment,
		)
		if err != nil {
			return fmt.Errorf("cannot calculate input asset "+
				"pkScript for commitment V0: %w", err)
		}

		if !bytes.Equal(anchorTxOut.PkScript, anchorPkScript) {
			// This matches neither version.
			return fmt.Errorf("%w: anchor input script "+
				"mismatch for anchor outpoint %v",
				tapsend.ErrInvalidAnchorInputInfo,
				assetInput.AnchorPoint)
		}
	}

	// Add some trace logging for easier debugging of what we expect to be
	// in the commitment we spend (we did the same when creating the output,
	// so differences should be apparent when debugging).
	tapsend.LogCommitment(
		"Input", idx, assetInput.Commitment, internalKey.PubKey,
		anchorPkScript, anchorMerkleRoot[:],
	)

	//nolint:lll
	tapscriptSiblingBytes, _, err := commitment.MaybeEncodeTapscriptPreimage(
		assetInput.TapscriptSibling,
	)
	if err != nil {
		return fmt.Errorf("cannot encode tapscript sibling: %w", err)
	}

	// At this point, we have a valid "coin" to spend in the commitment, so
	// we'll add the relevant information to the virtual TX's input.
	vPkt.Inputs[idx] = &tappsbt.VInput{
		PrevID: assetInput.PrevID(),
		Anchor: tappsbt.Anchor{
			Value:            assetInput.AnchorOutputValue,
			PkScript:         anchorPkScript,
			InternalKey:      internalKey.PubKey,
			MerkleRoot:       anchorMerkleRoot[:],
			TapscriptSibling: tapscriptSiblingBytes,
			Bip32Derivation:  []*psbt.Bip32Derivation{derivation},
			TrBip32Derivation: []*psbt.TaprootBip32Derivation{
				trDerivation,
			},
		},
		Proof: inputProof,
		PInput: psbt.PInput{
			SighashType: txscript.SigHashDefault,
		},
	}
	vPkt.SetInputAsset(idx, assetInput.Asset)

	inputAltLeaves, err := assetInput.Commitment.FetchAltLeaves()
	if err != nil {
		return fmt.Errorf("cannot fetch alt leaves from input: %w", err)
	}

	err = vPkt.Inputs[idx].SetAltLeaves(inputAltLeaves)
	if err != nil {
		return fmt.Errorf("cannot set alt leaves on vInput: %w", err)
	}

	return nil
}

// fetchInputProof fetches the proof for the given asset input from the archive.
func fetchInputProof(ctx context.Context, exporter proof.Exporter,
	inputAsset *asset.Asset, anchorPoint wire.OutPoint) (*proof.Proof,
	error) {

	assetID := inputAsset.ID()
	proofLocator := proof.Locator{
		AssetID:   &assetID,
		ScriptKey: *inputAsset.ScriptKey.PubKey,
		OutPoint:  &anchorPoint,
	}
	if inputAsset.GroupKey != nil {
		proofLocator.GroupKey = &inputAsset.GroupKey.GroupPubKey
	}
	inputProofBlob, err := exporter.FetchProof(ctx, proofLocator)
	if err != nil {
		return nil, fmt.Errorf("cannot fetch proof for input "+
			"asset: %w", err)
	}
	inputProofFile := &proof.File{}
	err = inputProofFile.Decode(bytes.NewReader(inputProofBlob))
	if err != nil {
		return nil, fmt.Errorf("cannot decode proof for input "+
			"asset: %w", err)
	}
	inputProof, err := inputProofFile.LastProof()
	if err != nil {
		return nil, fmt.Errorf("cannot get last proof for "+
			"input asset: %w", err)
	}

	return inputProof, nil
}
