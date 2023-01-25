package tarofreighter

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/lightninglabs/taro/address"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/commitment"
	"github.com/lightninglabs/taro/taropsbt"
	"github.com/lightninglabs/taro/taroscript"
)

// Wallet is an interface for funding and signing asset transfers.
type Wallet interface {
	// FundAddressSend funds a virtual transaction, selecting assets to
	// spend in order to pay the given address.
	FundAddressSend(ctx context.Context,
		receiverAddr address.Taro) (*taropsbt.VPacket,
		*commitment.TaroCommitment, error)

	// SignVirtualPacket signs the virtual transaction of the given packet.
	SignVirtualPacket(packet *taropsbt.VPacket) error
}

// WalletConfig holds the configuration for a new Wallet.
type WalletConfig struct {
	// CoinSelector is the interface used to select input coins (assets)
	// for the transfer.
	CoinSelector CommitmentSelector

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

// FundAddressSend funds a virtual transaction, selecting assets to spend in
// order to pay the given address.
//
// NOTE: This is part of the Wallet interface.
func (f *AssetWallet) FundAddressSend(ctx context.Context,
	receiverAddr address.Taro) (*taropsbt.VPacket,
	*commitment.TaroCommitment, error) {

	// We start by creating a new virtual transaction that will be used to
	// hold the asset transfer. Because sending to an address is always a
	// non-interactive process, we can use this function that always creates
	// a change output.
	pkt := taropsbt.FromAddress(&receiverAddr)

	// We need to find a commitment that has enough assets to satisfy this
	// send request. We'll map the address to a set of constraints, so we
	// can use that to do Taro asset coin selection.
	//
	// TODO(roasbeef): send logic assumes just one input (no merges) so we
	// pass in the amount here to ensure we have enough to send
	assetID := receiverAddr.ID()
	constraints := CommitmentConstraints{
		GroupKey: receiverAddr.GroupKey,
		AssetID:  &assetID,
		MinAmt:   receiverAddr.Amount,
	}

	eligibleCommitments, err := f.cfg.CoinSelector.SelectCommitment(
		ctx, constraints,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to complete coin "+
			"selection: %w", err)
	}

	log.Infof("Selected %v possible asset inputs for send to %x",
		len(eligibleCommitments),
		receiverAddr.ScriptKey.SerializeCompressed())

	// We'll take just the first commitment here as we need enough
	// to complete the send w/o merging inputs.
	assetInput := eligibleCommitments[0]

	// If the key found for the input UTXO is not from the Taro key family,
	// something has gone wrong with the DB.
	internalKey := assetInput.InternalKey
	if internalKey.Family != taroscript.TaroKeyFamily {
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

	// At this point, we have a valid "coin" to spend in the commitment, so
	// we'll add the relevant information to the virtual TX's input.
	//
	// TODO(roasbeef): still need to add family key to PrevID.
	pkt.Input = &taropsbt.VInput{
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
	}
	pkt.SetInputAsset(assetInput.Asset)

	// We'll validate the selected input and commitment. From this we'll
	// gain the asset that we'll use as an input and info w.r.t if we need
	// to use an un-spendable zero-value root.
	inputAsset, fullValue, err := taroscript.IsValidInput(
		assetInput.Commitment, receiverAddr,
		*pkt.Input.Asset().ScriptKey.PubKey, *f.cfg.ChainParams,
	)
	if err != nil {
		return nil, nil, err
	}

	// We expect some change back, so let's create a script key to receive
	// the change on.
	if !fullValue {
		senderScriptKey, err := f.cfg.KeyRing.DeriveNextKey(
			ctx, taroscript.TaroKeyFamily,
		)
		if err != nil {
			return nil, nil, err
		}

		// We'll assume BIP 86 everywhere, and use the tweaked key from
		// here on out.
		pkt.Outputs[0].Amount = inputAsset.Amount - receiverAddr.Amount
		pkt.Outputs[0].ScriptKey = asset.NewScriptKeyBIP0086(
			senderScriptKey,
		)
	}

	// Before we can prepare output assets for our send, we need to generate
	// a new internal key for the anchor output of the asset change output.
	changeInternalKey, err := f.cfg.KeyRing.DeriveNextKey(
		ctx, taroscript.TaroKeyFamily,
	)
	if err != nil {
		return nil, nil, err
	}
	pkt.Outputs[0].SetAnchorInternalKey(
		changeInternalKey, receiverAddr.ChainParams.HDCoinType,
	)

	err = taroscript.PrepareOutputAssets(pkt.Input, pkt.Outputs)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create split commit: %w",
			err)
	}

	return pkt, assetInput.Commitment, nil
}

// SignVirtualPacket signs the virtual transaction of the given packet.
//
// NOTE: This is part of the Wallet interface.
func (f *AssetWallet) SignVirtualPacket(packet *taropsbt.VPacket) error {
	// Now we'll use the signer to sign all the inputs for the new
	// taro leaves. The witness data for each input will be
	// assigned for us.
	err := taroscript.SignVirtualTransaction(
		packet.Input, packet.Outputs, f.cfg.Signer, f.cfg.TxValidator,
	)
	if err != nil {
		return fmt.Errorf("unable to generate taro witness data: %w",
			err)
	}

	return nil
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
		err = inputAssetTree.Update(inputAssetCopy, false)
		if err != nil {
			return nil, nil, err
		}

		err = inputAnchorCommitmentCopy.Update(inputAssetTree, false)
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
