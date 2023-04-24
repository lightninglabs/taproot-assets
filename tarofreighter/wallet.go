package tarofreighter

import (
	"bytes"
	"context"
	"fmt"
	"sort"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/lightninglabs/taro/address"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/chanutils"
	"github.com/lightninglabs/taro/commitment"
	"github.com/lightninglabs/taro/mssmt"
	"github.com/lightninglabs/taro/proof"
	"github.com/lightninglabs/taro/tarogarden"
	"github.com/lightninglabs/taro/taropsbt"
	"github.com/lightninglabs/taro/taroscript"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
)

// AnchorTransaction is a type that holds all information about a BTC level
// anchor transaction that anchors multiple virtual asset transfer transactions.
type AnchorTransaction struct {
	// FundedPsbt is the funded anchor TX at the state before it was signed,
	// with all the UTXO information intact for later exclusion proof
	// creation.
	FundedPsbt *tarogarden.FundedPsbt

	// FinalTx is the fully signed and finalized anchor TX that can be
	// broadcast to the network.
	FinalTx *wire.MsgTx

	// TargetFeeRate is the fee rate that was used to fund the anchor TX.
	TargetFeeRate chainfee.SatPerKWeight

	// ChainFees is the actual, total amount of sats paid in chain fees by
	// the anchor TX.
	ChainFees int64

	// OutputCommitments is a map of all the Taro level commitments each
	// output of the anchor TX is committing to. This is the merged Taro
	// tree of all the virtual asset transfer transactions that are within
	// a single BTC level anchor output.
	OutputCommitments map[uint32]*commitment.TaroCommitment
}

// Wallet is an interface for funding and signing asset transfers.
type Wallet interface {
	// FundAddressSend funds a virtual transaction, selecting assets to
	// spend in order to pay the given address. It also returns supporting
	// data which assists in processing the virtual transaction: passive
	// asset re-anchors and the Taro level commitment of the selected
	// assets.
	FundAddressSend(ctx context.Context,
		receiverAddr address.Taro) (*FundedVPacket, error)

	// FundPacket funds a virtual transaction, selecting assets to spend
	// in order to pay the given recipient. The selected input is then added
	// to the given virtual transaction.
	FundPacket(ctx context.Context, fundDesc *taroscript.FundingDescriptor,
		vPkt *taropsbt.VPacket) (*FundedVPacket, error)

	// SignVirtualPacket signs the virtual transaction of the given packet
	// and returns the input indexes that were signed.
	SignVirtualPacket(vPkt *taropsbt.VPacket,
		optFuncs ...SignVirtualPacketOption) ([]uint32, error)

	// SignPassiveAssets creates and signs the passive asset packets for the
	// given input commitment and virtual packet that contains the active
	// asset transfer.
	SignPassiveAssets(inputCommitment *commitment.TaroCommitment,
		vPkt *taropsbt.VPacket) ([]*PassiveAssetReAnchor, error)

	// AnchorVirtualTransactions creates a BTC level anchor transaction that
	// anchors all the virtual transactions of the given packets (for both
	// sending and passive asset re-anchoring).
	//
	// This method returns both the funded anchor TX with all the output
	// information intact for later exclusion proof creation, and the fully
	// signed and finalized anchor TX along with the total amount of sats
	// paid in chain fees by the anchor TX.
	AnchorVirtualTransactions(ctx context.Context,
		params *AnchorVTxnsParams) (*AnchorTransaction, error)
}

// AnchorVTxnsParams holds all the parameters needed to create a BTC level
// anchor transaction that anchors multiple virtual transactions.
type AnchorVTxnsParams struct {
	// FeeRate is the fee rate that should be used to fund the anchor
	// transaction.
	FeeRate chainfee.SatPerKWeight

	// InputCommitments is a list of all the Taro level commitments of the
	// inputs that should be included in the anchor transaction.
	InputCommitments []*commitment.TaroCommitment

	// VPkts is a list of all the virtual transactions that should be
	// anchored by the anchor transaction.
	VPkts []*taropsbt.VPacket

	// PassiveAssetsVPkts is a list of all the virtual transactions which
	// re-anchor passive assets.
	PassiveAssetsVPkts []*taropsbt.VPacket
}

// NewCoinSelect creates a new CoinSelect.
func NewCoinSelect(coinLister CoinLister) *CoinSelect {
	return &CoinSelect{
		coinLister: coinLister,
	}
}

// CoinSelect selects asset coins to spend in order to fund a send
// transaction.
type CoinSelect struct {
	coinLister CoinLister
}

// ListEligibleCoins lists eligible commitments given a set of constraints.
func (s *CoinSelect) ListEligibleCoins(ctx context.Context,
	constraints CommitmentConstraints) ([]*AnchoredCommitment, error) {

	return s.coinLister.ListEligibleCoins(ctx, constraints)
}

// SelectForAmount selects a subset of the given eligible commitments which
// cumulatively sum to at least the minimum required amount. The selection
// strategy determines how the commitments are selected.
func (s *CoinSelect) SelectForAmount(minTotalAmount uint64,
	eligibleCommitments []*AnchoredCommitment,
	strategy MultiCommitmentSelectStrategy) ([]*AnchoredCommitment,
	error) {

	// Select the first subset of eligible commitments which cumulatively
	// sum to at least the minimum required amount.
	var selectedCommitments []*AnchoredCommitment
	amountSum := uint64(0)

	switch strategy {
	case PreferMaxAmount:
		// Sort eligible commitments from the largest amount to
		// smallest.
		sort.Slice(
			eligibleCommitments, func(i, j int) bool {
				isLess := eligibleCommitments[i].Asset.Amount <
					eligibleCommitments[j].Asset.Amount

				// Negate the result to sort in descending
				// order.
				return !isLess
			},
		)

		// Select the first subset of eligible commitments which
		// cumulatively sum to at least the minimum required amount.
		for _, anchoredCommitment := range eligibleCommitments {
			selectedCommitments = append(
				selectedCommitments, anchoredCommitment,
			)

			// Keep track of the total amount of assets we've seen
			// so far.
			amountSum += uint64(anchoredCommitment.Asset.Amount)
			if amountSum >= minTotalAmount {
				// At this point a target min amount was
				// specified and has been reached.
				break
			}
		}

	default:
		return nil, fmt.Errorf("unknown multi coin selection "+
			"strategy: %v", strategy)
	}

	// Having examined all the eligible commitments, return an error if the
	// minimal funding amount was not reached.
	if amountSum < minTotalAmount {
		return nil, ErrMatchingAssetsNotFound
	}
	return selectedCommitments, nil
}

var _ CoinSelector = (*CoinSelect)(nil)

// WalletConfig holds the configuration for a new Wallet.
type WalletConfig struct {
	// CoinSelector is the interface used to select input coins (assets)
	// for the transfer.
	CoinSelector CoinSelector

	// AssetProofs is used to write the proof files on disk for the
	// receiver during a transfer.
	//
	// TODO(roasbeef): replace with proof.Courier in the future/
	AssetProofs proof.Archiver

	// KeyRing is used to generate new keys throughout the transfer
	// process.
	KeyRing KeyRing

	// Signer implements the Taro level signing we need to sign a virtual
	// transaction.
	Signer Signer

	// TxValidator allows us to validate each Taro virtual transaction we
	// create.
	TxValidator taroscript.TxValidator

	// Wallet is used to fund+sign PSBTs for the transfer transaction.
	Wallet WalletAnchor

	// ChainParams is the chain params of the chain we operate on.
	ChainParams *address.ChainParams
}

// AssetWallet is an implementation of the Wallet interface that can create
// virtual transactions, sign them and commit them on-chain.
type AssetWallet struct {
	cfg *WalletConfig
}

// NewAssetWallet creates a new AssetWallet instance from the given
// configuration.
func NewAssetWallet(cfg *WalletConfig) *AssetWallet {
	return &AssetWallet{
		cfg: cfg,
	}
}

// FundedVPacket is the result from an attempt to fund a given taro address send
// request via a call to FundAddressSend.
type FundedVPacket struct {
	// VPacket is the virtual transaction that was created to fund the
	// transfer.
	VPacket *taropsbt.VPacket

	// TaroCommitment is the Taro level commitment associated with the
	// assets selected for this transfer.
	TaroCommitment *commitment.TaroCommitment
}

// FundAddressSend funds a virtual transaction, selecting assets to spend in
// order to pay the given address. It also returns supporting data which assists
// in processing the virtual transaction: passive asset re-anchors and the
// Taro level commitment of the selected assets.
//
// NOTE: This is part of the Wallet interface.
func (f *AssetWallet) FundAddressSend(ctx context.Context,
	receiverAddr address.Taro) (*FundedVPacket, error) {

	// We start by creating a new virtual transaction that will be used to
	// hold the asset transfer. Because sending to an address is always a
	// non-interactive process, we can use this function that always creates
	// a change output.
	vPkt := taropsbt.FromAddress(&receiverAddr, 1)

	fundDesc := &taroscript.FundingDescriptor{
		ID:       receiverAddr.AssetID,
		GroupKey: receiverAddr.GroupKey,
		Amount:   receiverAddr.Amount,
	}
	fundedVPkt, err := f.FundPacket(ctx, fundDesc, vPkt)
	if err != nil {
		return nil, err
	}

	return fundedVPkt, nil
}

// passiveAssetVPacket creates a virtual packet for the given passive asset.
func (f *AssetWallet) passiveAssetVPacket(passiveAsset *asset.Asset,
	anchorPoint wire.OutPoint, anchorOutputIndex uint32,
	internalKey *keychain.KeyDescriptor) *taropsbt.VPacket {

	// Specify virtual input.
	inputAsset := passiveAsset.Copy()
	inputPrevId := asset.PrevID{
		OutPoint: anchorPoint,
		ID:       inputAsset.ID(),
		ScriptKey: asset.ToSerialized(
			inputAsset.ScriptKey.PubKey,
		),
	}
	vInput := taropsbt.VInput{
		PrevID: inputPrevId,
	}

	// Specify virtual output.
	outputAsset := passiveAsset.Copy()

	// Clear the split commitment root, as we'll be transferring the
	// whole asset.
	outputAsset.SplitCommitmentRoot = nil

	// Clear the output asset witness data. We'll be creating a new witness.
	outputAsset.PrevWitnesses = []asset.Witness{{
		PrevID: &inputPrevId,
	}}

	vOutput := taropsbt.VOutput{
		Amount: outputAsset.Amount,

		// In this case, the receiver of the output is also the sender.
		// We therefore set interactive to true to indicate that the
		// receiver is aware of the transfer.
		Interactive: true,

		AnchorOutputIndex: anchorOutputIndex,
		ScriptKey:         outputAsset.ScriptKey,
		Asset:             outputAsset,
	}

	// Set output internal key.
	vOutput.SetAnchorInternalKey(
		*internalKey, f.cfg.ChainParams.HDCoinType,
	)

	// Create VPacket.
	vPacket := &taropsbt.VPacket{
		Inputs:      []*taropsbt.VInput{&vInput},
		Outputs:     []*taropsbt.VOutput{&vOutput},
		ChainParams: f.cfg.ChainParams,
	}

	// Set the input asset. The input asset proof is not provided as it is
	// not needed for the re-anchoring process.
	vPacket.SetInputAsset(0, inputAsset, nil)

	return vPacket
}

// FundPacket funds a virtual transaction, selecting assets to spend in order to
// pay the given recipient. The selected input is then added to the given
// virtual transaction.
func (f *AssetWallet) FundPacket(ctx context.Context,
	fundDesc *taroscript.FundingDescriptor,
	vPkt *taropsbt.VPacket) (*FundedVPacket, error) {

	// The input and address networks must match.
	if !address.IsForNet(vPkt.ChainParams.TaroHRP, f.cfg.ChainParams) {
		return nil, address.ErrMismatchedHRP
	}

	// We need to find a commitment that has enough assets to satisfy this
	// send request. We'll map the address to a set of constraints, so we
	// can use that to do Taro asset coin selection.
	constraints := CommitmentConstraints{
		GroupKey: fundDesc.GroupKey,
		AssetID:  &fundDesc.ID,
		MinAmt:   1,
	}
	eligibleCommitments, err := f.cfg.CoinSelector.ListEligibleCoins(
		ctx, constraints,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to complete coin selection: %w",
			err)
	}

	log.Infof("Identified %v eligible asset inputs for send of %d to %x",
		len(eligibleCommitments), fundDesc.Amount, fundDesc.ID[:])

	selectedCommitments, err := f.cfg.CoinSelector.SelectForAmount(
		fundDesc.Amount, eligibleCommitments, PreferMaxAmount,
	)
	if err != nil {
		return nil, err
	}
	log.Infof("Selected %v asset inputs for send of %d to %x",
		len(selectedCommitments), fundDesc.Amount, fundDesc.ID[:])

	assetType := selectedCommitments[0].Asset.Type

	// We'll take just the first commitment here as we need enough
	// to complete the send w/o merging inputs.
	//
	// TODO(ffranr): Remove selected commitment truncation.
	selectedCommitments = selectedCommitments[:1]
	assetInput := selectedCommitments[0]

	totalInputAmt := uint64(0)
	for _, anchorAsset := range selectedCommitments {
		totalInputAmt += anchorAsset.Asset.Amount
	}

	err = f.setVPacketInputs(ctx, selectedCommitments, vPkt)
	if err != nil {
		return nil, err
	}

	// Gather Taro commitments from the selected anchored assets.
	var selectedTaroCommitments []*commitment.TaroCommitment
	for _, selectedCommitment := range selectedCommitments {
		selectedTaroCommitments = append(
			selectedTaroCommitments, selectedCommitment.Commitment,
		)
	}

	senderScriptKey := vPkt.Inputs[0].Asset().ScriptKey.PubKey
	fullValue, err := taroscript.ValidateInputs(
		selectedTaroCommitments, senderScriptKey, assetType, fundDesc,
	)
	if err != nil {
		return nil, err
	}

	// For now, we just need to know _if_ there are any passive assets, so
	// we can create a change output if needed. We'll actually sign the
	// passive packets later.
	passiveCommitments, err := removeActiveCommitments(
		assetInput.Commitment, vPkt,
	)
	if err != nil {
		return nil, err
	}

	// We expect some change back, or have passive assets to commit to, so
	// let's make sure we create a transfer output.
	var changeOut *taropsbt.VOutput
	if !fullValue || len(passiveCommitments) > 0 {
		// Do we need to add a change output?
		changeOut, err = vPkt.SplitRootOutput()
		if err != nil {
			lastOut := vPkt.Outputs[len(vPkt.Outputs)-1]
			splitOutIndex := lastOut.AnchorOutputIndex + 1
			changeOut = &taropsbt.VOutput{
				IsSplitRoot:       true,
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
			return nil, fmt.Errorf("cannot determine if script "+
				"key is spendable: %w", err)
		}
		if unSpendable && !fullValue {
			changeScriptKey, err := f.cfg.KeyRing.DeriveNextKey(
				ctx, asset.TaroKeyFamily,
			)
			if err != nil {
				return nil, err
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
		changeOut.Amount = totalInputAmt - fundDesc.Amount
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

		newInternalKey, err := f.cfg.KeyRing.DeriveNextKey(
			ctx, asset.TaroKeyFamily,
		)
		if err != nil {
			return nil, err
		}
		vOut.SetAnchorInternalKey(
			newInternalKey, f.cfg.ChainParams.HDCoinType,
		)
	}

	if err := taroscript.PrepareOutputAssets(vPkt); err != nil {
		return nil, fmt.Errorf("unable to create split commit: %w", err)
	}

	return &FundedVPacket{
		VPacket:        vPkt,
		TaroCommitment: assetInput.Commitment,
	}, nil
}

// setVPacketInputs sets the inputs of the given vPkt to the given send eligible
// commitments. It also returns the assets that were used as inputs.
func (f *AssetWallet) setVPacketInputs(ctx context.Context,
	eligibleCommitments []*AnchoredCommitment,
	vPkt *taropsbt.VPacket) error {

	vPkt.Inputs = make([]*taropsbt.VInput, len(eligibleCommitments))

	for idx, assetInput := range eligibleCommitments {
		// If the key found for the input UTXO cannot be identified as
		// belonging to the lnd wallet, we won't be able to sign for it.
		// This would happen if a user manually imported an asset that
		// was issued/received for/on another node. We should probably
		// not create asset entries for such imported assets in the
		// first place, as we won't be able to spend it anyway. But for
		// now we just put this check in place.
		internalKey := assetInput.InternalKey
		if !f.cfg.KeyRing.IsLocalKey(ctx, internalKey) {
			return fmt.Errorf("invalid internal key family for "+
				"selected input, not known to lnd: "+
				"key=%x, fam=%v, idx=%v",
				internalKey.PubKey.SerializeCompressed(),
				internalKey.Family, internalKey.Index)
		}

		inBip32Derivation, inTrBip32Derivation :=
			taropsbt.Bip32DerivationFromKeyDesc(
				internalKey, f.cfg.ChainParams.HDCoinType,
			)

		anchorPkScript, anchorMerkleRoot, err := inputAnchorPkScript(
			assetInput,
		)
		if err != nil {
			return fmt.Errorf("cannot calculate input asset pk "+
				"script: %w", err)
		}

		log.Tracef("Input commitment taro_root=%x, internal_key=%x, "+
			"pk_script=%x, trimmed_merkle_root=%x",
			chanutils.ByteSlice(
				assetInput.Commitment.TapscriptRoot(nil),
			), internalKey.PubKey.SerializeCompressed(),
			anchorPkScript, anchorMerkleRoot[:])

		// We'll also include an inclusion proof for the input asset in
		// the virtual transaction. With that a signer can verify that
		// the asset was actually committed to in the anchor output.
		assetID := assetInput.Asset.ID()
		proofLocator := proof.Locator{
			AssetID:   &assetID,
			ScriptKey: *assetInput.Asset.ScriptKey.PubKey,
		}
		if assetInput.Asset.GroupKey != nil {
			proofLocator.GroupKey = &assetInput.Asset.GroupKey.GroupPubKey
		}
		inputProofBlob, err := f.cfg.AssetProofs.FetchProof(
			ctx, proofLocator,
		)
		if err != nil {
			return fmt.Errorf("cannot fetch proof for input "+
				"asset: %w", err)
		}
		inputProofFile := &proof.File{}
		err = inputProofFile.Decode(bytes.NewReader(inputProofBlob))
		if err != nil {
			return fmt.Errorf("cannot decode proof for input "+
				"asset: %w", err)
		}
		inputProof, err := inputProofFile.RawLastProof()
		if err != nil {
			return fmt.Errorf("cannot get last proof for input "+
				"asset: %w", err)
		}

		tapscriptSiblingBytes, _, err := commitment.MaybeEncodeTapscriptPreimage(
			assetInput.TapscriptSibling,
		)
		if err != nil {
			return fmt.Errorf("cannot encode tapscript sibling: %w",
				err)
		}

		// At this point, we have a valid "coin" to spend in the
		// commitment, so we'll add the relevant information to the
		// virtual TX's input.
		//
		// TODO(roasbeef): still need to add family key to PrevID.
		vPkt.Inputs[idx] = &taropsbt.VInput{
			PrevID: asset.PrevID{
				OutPoint: assetInput.AnchorPoint,
				ID:       assetInput.Asset.ID(),
				ScriptKey: asset.ToSerialized(
					assetInput.Asset.ScriptKey.PubKey,
				),
			},
			Anchor: taropsbt.Anchor{
				Value:            assetInput.AnchorOutputValue,
				PkScript:         anchorPkScript,
				InternalKey:      internalKey.PubKey,
				MerkleRoot:       anchorMerkleRoot,
				TapscriptSibling: tapscriptSiblingBytes,
				Bip32Derivation: []*psbt.Bip32Derivation{
					inBip32Derivation,
				},
				TrBip32Derivation: []*psbt.TaprootBip32Derivation{
					inTrBip32Derivation,
				},
			},
			PInput: psbt.PInput{
				SighashType: txscript.SigHashDefault,
			},
		}
		vPkt.SetInputAsset(idx, assetInput.Asset, inputProof)
	}

	return nil
}

// SignVirtualPacketOptions is a set of functional options that allow callers to
// further modify the virtual packet signing process.
type SignVirtualPacketOptions struct {
	// SkipInputProofVerify skips virtual input proof verification when true.
	SkipInputProofVerify bool
}

// defaultSignVirtualPacketOptions returns the set of default options for the
// virtual packet signing function.
func defaultSignVirtualPacketOptions() *SignVirtualPacketOptions {
	return &SignVirtualPacketOptions{}
}

// SignVirtualPacketOption is a functional option that allows a caller to modify
// the virtual packet signing process.
type SignVirtualPacketOption func(*SignVirtualPacketOptions)

// SkipInputProofVerify sets an optional argument flag such that
// SignVirtualPacket skips virtual input proof verification.
func SkipInputProofVerify() SignVirtualPacketOption {
	return func(o *SignVirtualPacketOptions) {
		o.SkipInputProofVerify = true
	}
}

// SignVirtualPacket signs the virtual transaction of the given packet and
// returns the input indexes that were signed (referring to the virtual
// transaction's inputs).
//
// NOTE: This is part of the Wallet interface.
func (f *AssetWallet) SignVirtualPacket(vPkt *taropsbt.VPacket,
	optFuncs ...SignVirtualPacketOption) ([]uint32, error) {

	opts := defaultSignVirtualPacketOptions()
	for _, optFunc := range optFuncs {
		optFunc(opts)
	}

	// Now we'll use the signer to sign all the inputs for the new taro
	// leaves. The witness data for each input will be assigned for us.
	signedInputs := make([]uint32, len(vPkt.Inputs))
	for idx := range vPkt.Inputs {
		// Conditionally skip the inclusion proof verification. We may
		// not need to verify the input proof if we're only using the
		// input to generate a new virtual output proof during
		// re-anchoring.
		if !opts.SkipInputProofVerify {
			// Before we sign the transaction, we want to make sure
			// the inclusion proof is valid and the asset is
			// actually committed in the anchor transaction.
			err := verifyInclusionProof(vPkt.Inputs[idx])
			if err != nil {
				return nil, fmt.Errorf("unable to verify "+
					"inclusion proof: %w", err)
			}
		}

		err := taroscript.SignVirtualTransaction(
			vPkt, idx, f.cfg.Signer, f.cfg.TxValidator,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to generate taro "+
				"witness data: %w", err)
		}

		signedInputs[idx] = uint32(idx)
	}

	return signedInputs, nil
}

// verifyInclusionProof verifies that the given virtual input's asset is
// actually committed in the anchor transaction.
func verifyInclusionProof(vIn *taropsbt.VInput) error {
	proofReader := bytes.NewReader(vIn.Proof())
	assetProof := &proof.Proof{}
	if err := assetProof.Decode(proofReader); err != nil {
		return fmt.Errorf("unable to decode asset proof: %w", err)
	}

	// Before we look at the inclusion proof, we'll make sure that the input
	// anchor information matches the proof's anchor transaction.
	//
	// TODO(guggero): Also check if the block is in the chain by calling
	// into ChainBridge.
	op := vIn.PrevID.OutPoint
	anchorTxHash := assetProof.AnchorTx.TxHash()

	if op.Hash != anchorTxHash {
		return fmt.Errorf("proof anchor tx hash %v doesn't match "+
			"input anchor outpoint %v in proof %x", anchorTxHash,
			op.Hash, vIn.Proof())
	}
	if op.Index >= uint32(len(assetProof.AnchorTx.TxOut)) {
		return fmt.Errorf("input anchor outpoint index out of range")
	}

	anchorTxOut := assetProof.AnchorTx.TxOut[op.Index]
	if !bytes.Equal(anchorTxOut.PkScript, vIn.Anchor.PkScript) {
		return fmt.Errorf("proof anchor tx pk script %x doesn't "+
			"match input anchor script %x in proof %x",
			anchorTxOut.PkScript, vIn.Anchor.PkScript, vIn.Proof())
	}

	anchorKey, err := proof.ExtractTaprootKeyFromScript(vIn.Anchor.PkScript)
	if err != nil {
		return fmt.Errorf("unable to parse anchor pk script %x "+
			"taproot key: %w", vIn.Anchor.PkScript, err)
	}

	inclusionProof := assetProof.InclusionProof
	proofKey, _, err := inclusionProof.DeriveByAssetInclusion(
		vIn.Asset(),
	)
	if err != nil {
		return fmt.Errorf("unable to derive inclusion proof: %w", err)
	}

	if !proofKey.IsEqual(anchorKey) {
		return fmt.Errorf("proof key doesn't match anchor key")
	}

	return nil
}

// removeActiveCommitments removes all active commitments from the given input
// commitment and only returns a tree of passive commitments.
func removeActiveCommitments(inputCommitment *commitment.TaroCommitment,
	vPkt *taropsbt.VPacket) (commitment.AssetCommitments, error) {

	// Gather passive assets found in the commitment. This creates a copy of
	// the commitment map, so we can remove things freely.
	passiveCommitments := inputCommitment.Commitments()

	// Remove input assets (the assets being spent) from list of assets to
	// re-sign.
	for _, vIn := range vPkt.Inputs {
		key := vIn.Asset().TaroCommitmentKey()
		assetCommitment, ok := passiveCommitments[key]
		if !ok {
			continue
		}

		// We need to make a copy in order to not modify the original
		// commitment, as the above call to get all commitments just
		// creates a new slice, but we still have a pointer to the
		// original asset commitment.
		var err error
		assetCommitment, err = assetCommitment.Copy()
		if err != nil {
			return nil, fmt.Errorf("unable to copy asset "+
				"commitment: %w", err)
		}

		// Now we can remove the asset from the commitment.
		err = assetCommitment.Delete(vIn.Asset())
		if err != nil {
			return nil, fmt.Errorf("unable to delete asset "+
				"commitment: %w", err)
		}

		// Since we're not returning the root Taro commitment but a map
		// of all asset commitments, we need to prune the asset
		// commitment manually if it is empty now.
		rootHash := assetCommitment.TreeRoot.NodeHash()
		if rootHash == mssmt.EmptyTreeRootHash {
			delete(passiveCommitments, key)

			continue
		}

		// There are other leaves of this asset in our asset tree, let's
		// now update our passive commitment map so these will be
		// carried along.
		passiveCommitments[key] = assetCommitment
	}

	return passiveCommitments, nil
}

// SignPassiveAssets creates and signs the passive asset packets for the given
// input commitment and virtual packet that contains the active asset transfer.
func (f *AssetWallet) SignPassiveAssets(
	inputCommitment *commitment.TaroCommitment,
	vPkt *taropsbt.VPacket) ([]*PassiveAssetReAnchor, error) {

	passiveCommitments, err := removeActiveCommitments(
		inputCommitment, vPkt,
	)
	if err != nil {
		return nil, err
	}
	if len(passiveCommitments) == 0 {
		return nil, nil
	}

	// When there are left over passive assets, we know we have a change
	// output present, since we created one in a previous step if there
	// was none to begin with.
	anchorPoint := vPkt.Inputs[0].PrevID.OutPoint
	changeOut, err := vPkt.SplitRootOutput()
	if err != nil {
		return nil, fmt.Errorf("missing split root output for passive "+
			"assets: %w", err)
	}

	changeInternalKey, err := changeOut.AnchorKeyToDesc()
	if err != nil {
		return nil, fmt.Errorf("unable to get change internal key: %w",
			err)
	}

	var passiveAssets []*PassiveAssetReAnchor
	for _, passiveCommitment := range passiveCommitments {
		for _, passiveAsset := range passiveCommitment.Assets() {
			passivePkt := f.passiveAssetVPacket(
				passiveAsset, anchorPoint,
				changeOut.AnchorOutputIndex,
				&changeInternalKey,
			)
			reAnchor := &PassiveAssetReAnchor{
				VPacket:         passivePkt,
				GenesisID:       passiveAsset.ID(),
				PrevAnchorPoint: anchorPoint,
				ScriptKey:       passiveAsset.ScriptKey,
			}
			passiveAssets = append(passiveAssets, reAnchor)
		}
	}

	// Sign all the passive assets virtual packets.
	for _, passiveAsset := range passiveAssets {
		_, err := f.SignVirtualPacket(
			passiveAsset.VPacket, SkipInputProofVerify(),
		)
		if err != nil {
			return nil, fmt.Errorf("unable to sign passive asset "+
				"virtual packet: %w", err)
		}
	}

	return passiveAssets, nil
}

// AnchorVirtualTransactions creates a BTC level anchor transaction that anchors
// all the virtual transactions of the given packets (for both sending and
// passive asset re-anchoring).
//
// This method returns both the funded anchor TX with all the output information
// intact for later exclusion proof creation, and the fully signed and finalized
// anchor TX along with the total amount of sats paid in chain fees by the
// anchor TX.
func (f *AssetWallet) AnchorVirtualTransactions(ctx context.Context,
	params *AnchorVTxnsParams) (*AnchorTransaction, error) {

	// We currently only support anchoring a single virtual transaction.
	//
	// TODO(guggero): Support merging and anchoring multiple virtual
	// transactions.
	if len(params.VPkts) != 1 || len(params.InputCommitments) != 1 {
		return nil, fmt.Errorf("only a single virtual transaction is " +
			"supported for now")
	}
	vPacket := params.VPkts[0]
	inputCommitment := params.InputCommitments[0]

	outputCommitments, err := taroscript.CreateOutputCommitments(
		inputCommitment, vPacket, params.PassiveAssetsVPkts,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to create new output "+
			"commitments: %w", err)
	}

	// Construct our template PSBT to commits to the set of dummy locators
	// we use to make fee estimation work.
	sendPacket, err := taroscript.CreateAnchorTx(vPacket.Outputs)
	if err != nil {
		return nil, fmt.Errorf("error creating anchor TX: %w", err)
	}

	anchorPkt, err := f.cfg.Wallet.FundPsbt(
		ctx, sendPacket, 1, params.FeeRate,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to fund psbt: %w", err)
	}

	// TODO(roasbeef): also want to log the total fee to disk for
	// accounting, etc.

	// Move the change output to the highest-index output, so that
	// we don't overwrite it when embedding our Taro commitments.
	//
	// TODO(jhb): Do we need richer handling for the change output?
	// We could reassign the change value to our Taro change output
	// and remove the change output entirely.
	adjustFundedPsbt(&anchorPkt, int64(vPacket.Inputs[0].Anchor.Value))

	log.Infof("Received funded PSBT packet: %v", spew.Sdump(anchorPkt.Pkt))

	// We need the PSBT output information in the unsigned packet later to
	// create the exclusion proofs. So we continue on a copy of the PSBT
	// because those fields get removed when we sign it.
	signAnchorPkt, err := copyPsbt(anchorPkt.Pkt)
	if err != nil {
		return nil, fmt.Errorf("unable to copy PSBT: %w", err)
	}

	// First, we'll update the PSBT packets to insert the _real_ outputs we
	// need to commit to the asset transfer.
	mergedCommitments, err := taroscript.UpdateTaprootOutputKeys(
		signAnchorPkt, vPacket, outputCommitments,
	)
	if err != nil {
		return nil, fmt.Errorf("error updating taproot output keys: %w",
			err)
	}

	// Now that all the real outputs are in the PSBT, we'll also
	// add our anchor input as well, since the wallet can sign for
	// it itself.
	err = addAnchorPsbtInput(
		signAnchorPkt, vPacket, params.FeeRate,
		f.cfg.ChainParams.Params,
	)
	if err != nil {
		return nil, fmt.Errorf("error adding anchor input: %w", err)
	}
	anchorPkt.Pkt = signAnchorPkt

	// With all the input and output information in the packet, we
	// can now ask lnd to sign it, and then extract the final
	// version ourselves.
	log.Debugf("Signing PSBT: %s", spew.Sdump(signAnchorPkt))
	signedPsbt, err := f.cfg.Wallet.SignPsbt(ctx, signAnchorPkt)
	if err != nil {
		return nil, fmt.Errorf("unable to sign psbt: %w", err)
	}
	log.Debugf("Got signed PSBT: %s", spew.Sdump(signedPsbt))

	// Before we finalize, we need to calculate the actual, final fees that
	// we pay.
	chainFees, err := tarogarden.GetTxFee(signedPsbt)
	if err != nil {
		return nil, fmt.Errorf("unable to get on-chain fees for psbt: "+
			"%w", err)
	}

	err = psbt.MaybeFinalizeAll(signedPsbt)
	if err != nil {
		return nil, fmt.Errorf("unable to finalize psbt: %w", err)
	}

	// Extract the final packet from the PSBT transaction (has all sigs
	// included).
	finalTx, err := psbt.Extract(signedPsbt)
	if err != nil {
		return nil, fmt.Errorf("unable to extract psbt: %w", err)
	}

	return &AnchorTransaction{
		FundedPsbt:        &anchorPkt,
		FinalTx:           finalTx,
		TargetFeeRate:     params.FeeRate,
		ChainFees:         chainFees,
		OutputCommitments: mergedCommitments,
	}, nil
}

// inputAnchorPkScript returns the top-level Taproot output script of the input
// anchor output as well as the Taro script root of the output (the Taproot
// tweak).
func inputAnchorPkScript(assetInput *AnchoredCommitment) ([]byte, []byte,
	error) {

	// If any of the assets were received non-interactively, then the Taro
	// tree of the input anchor output was built with asset leaves that had
	// empty SplitCommitments. We need to replicate this here as well.
	inputCommitment, err := trimSplitWitnesses(assetInput.Commitment)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to trim split "+
			"witnesses: %w", err)
	}

	// Decode the Tapscript sibling preimage if there was one, so we can
	// arrive at the correct merkle root hash.
	var siblingHash *chainhash.Hash
	if assetInput.TapscriptSibling != nil {
		siblingHash, err = assetInput.TapscriptSibling.TapHash()
		if err != nil {
			return nil, nil, err
		}
	}

	merkleRoot := inputCommitment.TapscriptRoot(siblingHash)
	anchorPubKey := txscript.ComputeTaprootOutputKey(
		assetInput.InternalKey.PubKey, merkleRoot[:],
	)

	pkScript, err := taroscript.PayToTaprootScript(anchorPubKey)
	return pkScript, merkleRoot[:], err
}

// trimSplitWitnesses returns a copy of the input commitment in which all assets
// with a split commitment witness have their SplitCommitment field set to nil.
func trimSplitWitnesses(
	original *commitment.TaroCommitment) (*commitment.TaroCommitment,
	error) {

	// If the input asset was received non-interactively, then the Taro tree
	// of the input anchor output was built with asset leaves that had empty
	// SplitCommitments. However, the SplitCommitment field was
	// populated when the transfer of the input asset was verified.
	// To recompute the correct output script, we need to build a Taro tree
	// from the input asset without any SplitCommitment.
	taroCommitmentCopy, err := original.Copy()
	if err != nil {
		return nil, err
	}

	allAssets := taroCommitmentCopy.CommittedAssets()
	for _, inputAsset := range allAssets {
		inputAssetCopy := inputAsset.Copy()

		// Assets received via non-interactive split should have one
		// witness, with an empty PrevID and a SplitCommitment present.
		if inputAssetCopy.HasSplitCommitmentWitness() &&
			*inputAssetCopy.PrevWitnesses[0].PrevID == asset.ZeroPrevID {

			inputAssetCopy.PrevWitnesses[0].SplitCommitment = nil

			// Build the new Taro tree by first updating the asset
			// commitment tree with the new asset leaf, and then the
			// top-level Taro tree.
			inputCommitments := taroCommitmentCopy.Commitments()
			inputCommitmentKey := inputAssetCopy.TaroCommitmentKey()
			inputAssetTree := inputCommitments[inputCommitmentKey]
			err = inputAssetTree.Upsert(inputAssetCopy)
			if err != nil {
				return nil, err
			}

			err = taroCommitmentCopy.Upsert(inputAssetTree)
			if err != nil {
				return nil, err
			}
		}
	}

	return taroCommitmentCopy, nil
}

// adjustFundedPsbt takes a funded PSBT which may have used BIP-0069 sorting,
// and creates a new one with outputs shuffled such that the change output is
// the last output.
func adjustFundedPsbt(fPkt *tarogarden.FundedPsbt, anchorInputValue int64) {
	// If there is no change there's nothing we need to do.
	changeIndex := fPkt.ChangeOutputIndex
	if changeIndex == -1 {
		return
	}

	// Store the script and value of the change output.
	maxOutputIndex := len(fPkt.Pkt.UnsignedTx.TxOut) - 1
	changeOutput := fPkt.Pkt.UnsignedTx.TxOut[changeIndex]

	// Overwrite the existing change output, and restore in at the
	// highest-index output.
	fPkt.Pkt.UnsignedTx.TxOut[changeIndex] = createDummyOutput()
	fPkt.Pkt.UnsignedTx.TxOut[maxOutputIndex].PkScript = changeOutput.PkScript
	fPkt.Pkt.UnsignedTx.TxOut[maxOutputIndex].Value = changeOutput.Value

	// Since we're adding the input of the anchor output of our prior asset
	// later, we need to add this value here, so we don't lose the amount
	// to fees.
	fPkt.Pkt.UnsignedTx.TxOut[maxOutputIndex].Value += anchorInputValue

	// If the change output already is the last output, we don't need to
	// overwrite anything in the PSBT outputs.
	if changeIndex == int32(maxOutputIndex) {
		return
	}

	// We also need to re-assign the PSBT level output information.
	changeOutputInfo := fPkt.Pkt.Outputs[changeIndex]
	fPkt.Pkt.Outputs[maxOutputIndex] = psbt.POutput{
		RedeemScript:           changeOutputInfo.RedeemScript,
		WitnessScript:          changeOutputInfo.WitnessScript,
		Bip32Derivation:        changeOutputInfo.Bip32Derivation,
		TaprootInternalKey:     changeOutputInfo.TaprootInternalKey,
		TaprootTapTree:         changeOutputInfo.TaprootTapTree,
		TaprootBip32Derivation: changeOutputInfo.TaprootBip32Derivation,
	}
	fPkt.Pkt.Outputs[changeIndex] = psbt.POutput{}
	fPkt.ChangeOutputIndex = int32(maxOutputIndex)
}

// addAnchorPsbtInput adds the input anchor information to the PSBT packet.
// This is called after the PSBT has been funded, but before signing.
func addAnchorPsbtInput(btcPkt *psbt.Packet, vPkt *taropsbt.VPacket,
	feeRate chainfee.SatPerKWeight, params *chaincfg.Params) error {

	// With the BIP-0032 information completed, we'll now add the
	// information as a partial input and also add the input to the unsigned
	// transaction.
	vIn := vPkt.Inputs[0]
	btcPkt.Inputs = append(btcPkt.Inputs, psbt.PInput{
		WitnessUtxo: &wire.TxOut{
			Value:    int64(vIn.Anchor.Value),
			PkScript: vIn.Anchor.PkScript,
		},
		SighashType:            vIn.Anchor.SigHashType,
		Bip32Derivation:        vIn.Anchor.Bip32Derivation,
		TaprootBip32Derivation: vIn.Anchor.TrBip32Derivation,
		TaprootInternalKey: schnorr.SerializePubKey(
			vIn.Anchor.InternalKey,
		),
		TaprootMerkleRoot: vIn.Anchor.MerkleRoot,
	})
	btcPkt.UnsignedTx.TxIn = append(
		btcPkt.UnsignedTx.TxIn, &wire.TxIn{
			PreviousOutPoint: vIn.PrevID.OutPoint,
		},
	)

	// Now that we've added an extra input, we'll want to re-calculate the
	// total weight of the transaction, so we can ensure we're paying
	// enough in fees.
	var (
		weightEstimator     input.TxWeightEstimator
		inputAmt, outputAmt int64
	)
	for _, pIn := range btcPkt.Inputs {
		inputAmt += pIn.WitnessUtxo.Value

		inputPkScript := pIn.WitnessUtxo.PkScript
		switch {
		case txscript.IsPayToWitnessPubKeyHash(inputPkScript):
			weightEstimator.AddP2WKHInput()

		case txscript.IsPayToScriptHash(inputPkScript):
			weightEstimator.AddNestedP2WKHInput()

		case txscript.IsPayToTaproot(inputPkScript):
			weightEstimator.AddTaprootKeySpendInput(
				txscript.SigHashDefault,
			)
		default:
			return fmt.Errorf("unknown pkScript: %x",
				inputPkScript)
		}
	}
	for _, txOut := range btcPkt.UnsignedTx.TxOut {
		outputAmt += txOut.Value

		addrType, _, _, err := txscript.ExtractPkScriptAddrs(
			txOut.PkScript, params,
		)
		if err != nil {
			return err
		}

		switch addrType {
		case txscript.WitnessV0PubKeyHashTy:
			weightEstimator.AddP2WKHOutput()

		case txscript.WitnessV0ScriptHashTy:
			weightEstimator.AddP2WSHOutput()

		case txscript.WitnessV1TaprootTy:
			weightEstimator.AddP2TROutput()
		default:
			return fmt.Errorf("unknwon pkscript: %x",
				txOut.PkScript)
		}
	}

	// With this, we can now calculate the total fee we need to pay. We'll
	// also make sure to round up the required fee to the floor.
	totalWeight := int64(weightEstimator.Weight())
	requiredFee := feeRate.FeeForWeight(totalWeight)

	// Given the current fee (which doesn't account for our input) and the
	// total fee we want to pay, we'll adjust the wallet's change output
	// accordingly.
	//
	// Earlier in adjustFundedPsbt we set wallet's change output to be the
	// very last output in the transaction.
	lastIdx := len(btcPkt.UnsignedTx.TxOut) - 1
	currentFee := inputAmt - outputAmt
	feeDelta := int64(requiredFee) - currentFee
	btcPkt.UnsignedTx.TxOut[lastIdx].Value -= feeDelta

	log.Infof("Adjusting send pkt by delta of %v from %d sats to %d sats",
		feeDelta, currentFee, requiredFee)

	return nil
}

// copyPsbt creates a deep copy of a PSBT packet by serializing and
// de-serializing it.
func copyPsbt(packet *psbt.Packet) (*psbt.Packet, error) {
	var buf bytes.Buffer
	if err := packet.Serialize(&buf); err != nil {
		return nil, err
	}

	return psbt.NewFromRawBytes(&buf, false)
}
