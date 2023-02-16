package tarofreighter

import (
	"bytes"
	"context"
	"fmt"

	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/lightninglabs/taro/address"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/commitment"
	"github.com/lightninglabs/taro/proof"
	"github.com/lightninglabs/taro/taropsbt"
	"github.com/lightninglabs/taro/taroscript"
)

// Wallet is an interface for funding and signing asset transfers.
type Wallet interface {
	// SelectCommitments funds a virtual transaction, selecting assets to
	// spend that match the given commitment constraints.
	SelectCommitments(ctx context.Context,
		constraints CommitmentConstraints,
		receiverAddr address.Taro) (*taropsbt.VPacket,
		*commitment.TaroCommitment, error)
}

// WalletConfig holds the configuration for a new Wallet.
type WalletConfig struct {
	// CoinSelector is the interface used to select input coins (assets)
	// for the transfer.
	CoinSelector CommitmentSelector

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

// SelectCommitments funds a virtual transaction, selecting assets to spend that
// match the given commitment constraints.
//
// NOTE: This is part of the Wallet interface.
func (f *AssetWallet) SelectCommitments(ctx context.Context,
	constraints CommitmentConstraints,
	receiverAddr address.Taro) (*taropsbt.VPacket,
	*commitment.TaroCommitment, error) {

	eligibleCommitments, err := f.cfg.CoinSelector.SelectCommitment(
		ctx, constraints,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to complete coin "+
			"selection: %w", err)
	}

	receiverScriptKey := &receiverAddr.ScriptKey
	log.Infof("Selected %v possible asset inputs for send to %x",
		len(eligibleCommitments),
		receiverScriptKey.SerializeCompressed())

	// We'll take just the first commitment here as we need enough
	// to complete the send w/o merging inputs.
	assetInput := eligibleCommitments[0]

	// If the key found for the input UTXO is not from the Taro key family,
	// something has gone wrong with the DB.
	internalKey := assetInput.InternalKey
	if internalKey.Family != asset.TaroKeyFamily {
		return nil, nil, fmt.Errorf("invalid internal key family "+
			"for selected input: %v %v", internalKey.Family,
			internalKey.Index)
	}

	inBip32Derivation, inTrBip32Derivation :=
		taropsbt.Bip32DerivationFromKeyDesc(
			internalKey, receiverAddr.ChainParams.HDCoinType,
		)

	anchorPkScript, anchorMerkleRoot, err := inputAnchorPkScript(assetInput)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot calculate input asset pk "+
			"script: %w", err)
	}

	// We'll also include an inclusion proof for the input asset in the
	// virtual transaction. With that a signer can verify that the asset was
	// actually committed to in the anchor output.
	assetID := assetInput.Asset.ID()
	proofLocator := proof.Locator{
		AssetID:   &assetID,
		ScriptKey: *assetInput.Asset.ScriptKey.PubKey,
	}
	if assetInput.Asset.GroupKey != nil {
		proofLocator.GroupKey = &assetInput.Asset.GroupKey.GroupPubKey
	}
	inputProofBlob, err := f.cfg.AssetProofs.FetchProof(ctx, proofLocator)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot fetch proof for input "+
			"asset: %w", err)
	}
	inputProofFile := &proof.File{}
	err = inputProofFile.Decode(bytes.NewReader(inputProofBlob))
	if err != nil {
		return nil, nil, fmt.Errorf("cannot decode proof for input "+
			"asset: %w", err)
	}
	inputProof, err := inputProofFile.RawLastProof()
	if err != nil {
		return nil, nil, fmt.Errorf("cannot get last proof for input "+
			"asset: %w", err)
	}

	// At this point, we have a valid "coin" to spend in the commitment, so
	// we'll add the relevant information to the virtual TX's input.
	//
	// TODO(roasbeef): still need to add family key to PrevID.
	vPkt := &taropsbt.VPacket{
		Outputs: make([]*taropsbt.VOutput, 2),
	}
	vPkt.Inputs = []*taropsbt.VInput{{
		PrevID: asset.PrevID{
			OutPoint: assetInput.AnchorPoint,
			ID:       assetInput.Asset.ID(),
			ScriptKey: asset.ToSerialized(
				assetInput.Asset.ScriptKey.PubKey,
			),
		},
		Anchor: taropsbt.Anchor{
			Value:             assetInput.AnchorOutputValue,
			PkScript:          anchorPkScript,
			InternalKey:       internalKey.PubKey,
			MerkleRoot:        anchorMerkleRoot,
			Bip32Derivation:   inBip32Derivation,
			TrBip32Derivation: inTrBip32Derivation,
		},
		PInput: psbt.PInput{
			SighashType: txscript.SigHashDefault,
		},
	}}
	vPkt.SetInputAsset(0, assetInput.Asset, inputProof)

	// We'll validate the selected input and commitment. From this we'll
	// gain the asset that we'll use as an input and info w.r.t if we need
	// to use an un-spendable zero-value root.
	inputAsset, fullValue, err := taroscript.IsValidInput(
		assetInput.Commitment, receiverAddr,
		*vPkt.Inputs[0].Asset().ScriptKey.PubKey, *f.cfg.ChainParams,
	)
	if err != nil {
		return nil, nil, err
	}

	// If we are sending the full value of the input asset, or sending a
	// collectible, we will need to create a split with un-spendable change.
	vPkt.Outputs[0] = &taropsbt.VOutput{
		Amount:            0,
		IsSplitRoot:       true,
		AnchorOutputIndex: 0,
		ScriptKey:         asset.NUMSScriptKey,
	}
	if !fullValue {
		senderScriptKey, err := f.cfg.KeyRing.DeriveNextKey(
			ctx, asset.TaroKeyFamily,
		)
		if err != nil {
			return nil, nil, err
		}

		// We'll assume BIP 86 everywhere, and use the tweaked key from
		// here on out.
		vPkt.Outputs[0].Amount = inputAsset.Amount - receiverAddr.Amount
		vPkt.Outputs[0].ScriptKey = asset.NewScriptKeyBIP0086(
			senderScriptKey,
		)
	}

	vPkt.Outputs[1] = &taropsbt.VOutput{
		Amount:            receiverAddr.Amount,
		Interactive:       false,
		AnchorOutputIndex: 1,
		ScriptKey:         asset.NewScriptKey(&receiverAddr.ScriptKey),
	}

	if err := taroscript.PrepareOutputAssets(vPkt); err != nil {
		return nil, nil, fmt.Errorf("unable to create split commit: %w",
			err)
	}

	return vPkt, assetInput.Commitment, nil
}

// inputAnchorPkScript returns the top-level Taproot output script of the input
// anchor output as well as the Taro script root of the output (the Taproot
// tweak).
func inputAnchorPkScript(assetInput *AnchoredCommitment) ([]byte, []byte,
	error) {

	// If the input asset was received non-interactively, then the Taro tree
	// of the input anchor output was built with asset leaves that had empty
	// SplitCommitments. However, the SplitCommitment field was
	// populated when the transfer of the input asset was verified.
	// To recompute the correct output script, we need to build a Taro tree
	// from the input asset without any SplitCommitment.
	inputAssetCopy := assetInput.Asset.Copy()
	inputAnchorCommitmentCopy, err := assetInput.Commitment.Copy()
	if err != nil {
		return nil, nil, err
	}

	// Assets received via non-interactive split should have one witness,
	// with an empty PrevID and a SplitCommitment present.
	if inputAssetCopy.HasSplitCommitmentWitness() &&
		*inputAssetCopy.PrevWitnesses[0].PrevID == asset.ZeroPrevID {

		inputAssetCopy.PrevWitnesses[0].SplitCommitment = nil

		// Build the new Taro tree by first updating the asset
		// commitment tree with the new asset leaf, and then the
		// top-level Taro tree.
		inputCommitments := inputAnchorCommitmentCopy.Commitments()
		inputCommitmentKey := inputAssetCopy.TaroCommitmentKey()
		inputAssetTree := inputCommitments[inputCommitmentKey]
		err = inputAssetTree.Upsert(inputAssetCopy)
		if err != nil {
			return nil, nil, err
		}

		err = inputAnchorCommitmentCopy.Upsert(inputAssetTree)
		if err != nil {
			return nil, nil, err
		}
	}

	taroScriptRoot := inputAnchorCommitmentCopy.TapscriptRoot(nil)
	anchorPubKey := txscript.ComputeTaprootOutputKey(
		assetInput.InternalKey.PubKey, taroScriptRoot[:],
	)

	pkScript, err := taroscript.PayToTaprootScript(anchorPubKey)
	return pkScript, taroScriptRoot[:], err
}
