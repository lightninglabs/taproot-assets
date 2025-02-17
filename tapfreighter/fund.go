package tapfreighter

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/tapsend"
)

// createFundedPacketWithInputs funds a set of virtual transaction with the
// given inputs. A new vPacket is created for each tranche of the active asset
// (which is the one specified in the funding descriptor, which is either a
// single asset ID/tranche or group key with multiple tranches).
func createFundedPacketWithInputs(ctx context.Context, exporter proof.Exporter,
	keyRing KeyRing, addrBook AddrBook, fundDesc *tapsend.FundingDescriptor,
	vPkt *tappsbt.VPacket,
	selectedCommitments []*AnchoredCommitment) (*FundedVPacket, error) {

	if vPkt.ChainParams == nil {
		return nil, errors.New("chain params not set in virtual packet")
	}

	log.Infof("Selected %v asset inputs for send of %d to %s",
		len(selectedCommitments), fundDesc.Amount,
		&fundDesc.AssetSpecifier)

	assetType := selectedCommitments[0].Asset.Type

	totalInputAmt := uint64(0)
	for _, anchorAsset := range selectedCommitments {
		// We only use the sum of all assets of the same TAP commitment
		// key to avoid counting passive assets as well. We'll filter
		// out the passive assets from the selected commitments in a
		// later step.
		if anchorAsset.Asset.TapCommitmentKey() !=
			fundDesc.TapCommitmentKey() {

			continue
		}

		totalInputAmt += anchorAsset.Asset.Amount
	}

	inputCommitments, err := setVPacketInputs(
		ctx, exporter, selectedCommitments, vPkt,
	)
	if err != nil {
		return nil, err
	}

	fullValue, err := tapsend.ValidateInputs(
		inputCommitments, assetType, fundDesc.AssetSpecifier,
		fundDesc.Amount,
	)
	if err != nil {
		return nil, err
	}

	// Make sure we'll recognize local script keys in the virtual packet
	// later on in the process by annotating them with the full descriptor
	// information.
	if err := annotateLocalScriptKeys(ctx, vPkt, addrBook); err != nil {
		return nil, err
	}

	// If we don't spend the full value, we need to create a change output.
	changeAmount := totalInputAmt - fundDesc.Amount
	err = createChangeOutput(ctx, vPkt, keyRing, fullValue, changeAmount)
	if err != nil {
		return nil, err
	}

	// Before we can prepare output assets for our send, we need to generate
	// a new internal key for the anchor outputs. We assume any output that
	// hasn't got an internal key set is going to a local anchor, and we
	// provide the internal key for that.
	for idx := range vPkt.Outputs {
		vOut := vPkt.Outputs[idx]
		if vOut.AnchorOutputInternalKey != nil {
			continue
		}

		newInternalKey, err := keyRing.DeriveNextKey(
			ctx, asset.TaprootAssetsKeyFamily,
		)
		if err != nil {
			return nil, err
		}
		vOut.SetAnchorInternalKey(
			newInternalKey, vPkt.ChainParams.HDCoinType,
		)
	}

	if err := tapsend.PrepareOutputAssets(ctx, vPkt); err != nil {
		return nil, fmt.Errorf("unable to prepare outputs: %w", err)
	}

	return &FundedVPacket{
		VPackets:         []*tappsbt.VPacket{vPkt},
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

// createChangeOutput creates a change output for the given virtual packet if
// it isn't fully spent.
func createChangeOutput(ctx context.Context, vPkt *tappsbt.VPacket,
	keyRing KeyRing, fullValue bool, changeAmount uint64) error {

	// If we're spending the full value, we don't need a change output. We
	// currently assume that if it's a full-value non-interactive spend that
	// the packet was created with the correct function in the tappsbt
	// packet that adds the NUMS script key output for the tombstone. If
	// the user doesn't set that, then an error will be returned from the
	// tapsend.PrepareOutputAssets function. But we should probably change
	// that and allow the user to specify a minimum packet template and add
	// whatever else is needed to it automatically.
	if fullValue {
		return nil
	}

	// We expect some change back, or have passive assets to commit to, so
	// let's make sure we create a transfer output.
	changeOut, err := vPkt.SplitRootOutput()
	if err != nil {
		lastOut := vPkt.Outputs[len(vPkt.Outputs)-1]
		splitOutIndex := lastOut.AnchorOutputIndex + 1
		changeOut = &tappsbt.VOutput{
			Type:              tappsbt.TypeSplitRoot,
			Interactive:       lastOut.Interactive,
			AnchorOutputIndex: splitOutIndex,

			// We want to handle deriving a real key in a
			// generic manner, so we'll do that just below.
			ScriptKey: asset.NUMSScriptKey,
		}

		vPkt.Outputs = append(vPkt.Outputs, changeOut)
	}

	// Since we know we're going to receive some change back, we
	// need to make sure it is going to an address that we control.
	// This should only be the case where we create the default
	// change output with the NUMS key to avoid deriving too many
	// keys prematurely. We don't need to derive a new key if we
	// only have passive assets to commit to, since they all have
	// their own script key and the output is more of a placeholder
	// to attach the passive assets to.
	unSpendable, err := changeOut.ScriptKey.IsUnSpendable()
	if err != nil {
		return fmt.Errorf("cannot determine if script key is "+
			"spendable: %w", err)
	}
	if unSpendable {
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

	// For existing change outputs, we'll just update the amount
	// since we might not have known what coin would've been
	// selected and how large the change would turn out to be.
	changeOut.Amount = changeAmount

	// The asset version of the output should be the max of the set
	// of input versions. We need to set this now as in
	// PrepareOutputAssets locators are created which includes the
	// version from the vOut. If we don't set it here, a v1 asset
	// spent that becomes change will be a v0 if combined with such
	// inputs.
	//
	// TODO(roasbeef): remove as not needed?
	maxVersion := func(maxVersion asset.Version,
		vInput *tappsbt.VInput) asset.Version {

		if vInput.Asset().Version > maxVersion {
			return vInput.Asset().Version
		}

		return maxVersion
	}
	changeOut.AssetVersion = fn.Reduce(vPkt.Inputs, maxVersion)

	return nil
}

// setVPacketInputs sets the inputs of the given vPkt to the given send eligible
// commitments. It also returns the assets that were used as inputs.
func setVPacketInputs(ctx context.Context, exporter proof.Exporter,
	eligibleCommitments []*AnchoredCommitment,
	vPkt *tappsbt.VPacket) (tappsbt.InputCommitments, error) {

	vPkt.Inputs = make([]*tappsbt.VInput, len(eligibleCommitments))
	inputCommitments := make(tappsbt.InputCommitments)

	for idx := range eligibleCommitments {
		// If the key found for the input UTXO cannot be identified as
		// belonging to the lnd wallet, we won't be able to sign for it.
		// This would happen if a user manually imported an asset that
		// was issued/received for/on another node. We should probably
		// not create asset entries for such imported assets in the
		// first place, as we won't be able to spend it anyway. But for
		// now we just put this check in place.
		assetInput := eligibleCommitments[idx]

		// We'll also include an inclusion proof for the input asset in
		// the virtual transaction. With that a signer can verify that
		// the asset was actually committed to in the anchor output.
		inputProof, err := fetchInputProof(
			ctx, exporter, assetInput.Asset, assetInput.AnchorPoint,
		)
		if err != nil {
			return nil, fmt.Errorf("error fetching input proof: %w",
				err)
		}

		// Create the virtual packet input including the chain anchor
		// information.
		err = createAndSetInput(
			vPkt, idx, assetInput, inputProof,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to create and set "+
				"input: %w", err)
		}

		prevID := vPkt.Inputs[idx].PrevID
		inputCommitments[prevID] = assetInput.Commitment
	}

	return inputCommitments, nil
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
	prevID := asset.PrevID{
		OutPoint: assetInput.AnchorPoint,
		ID:       assetInput.Asset.ID(),
		ScriptKey: asset.ToSerialized(
			assetInput.Asset.ScriptKey.PubKey,
		),
	}
	vPkt.Inputs[idx] = &tappsbt.VInput{
		PrevID: prevID,
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
