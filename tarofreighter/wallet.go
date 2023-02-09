package tarofreighter

import (
	"bytes"
	"context"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/lightninglabs/taro/address"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/commitment"
	"github.com/lightninglabs/taro/proof"
	"github.com/lightninglabs/taro/tarogarden"
	"github.com/lightninglabs/taro/taropsbt"
	"github.com/lightninglabs/taro/taroscript"
	"github.com/lightningnetwork/lnd/input"
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
	// spend in order to pay the given address.
	FundAddressSend(ctx context.Context,
		receiverAddr address.Taro) (*taropsbt.VPacket,
		*commitment.TaroCommitment, error)

	// FundPacket funds a virtual transaction, selecting assets to spend
	// in order to pay the given recipient. The selected input is then added
	// to the given virtual transaction.
	FundPacket(ctx context.Context, fundDesc *taroscript.FundingDescriptor,
		receiverScriptKey *btcec.PublicKey,
		vPkt *taropsbt.VPacket) (*commitment.TaroCommitment, error)

	// SignVirtualPacket signs the virtual transaction of the given packet
	// and returns the input indexes that were signed.
	SignVirtualPacket(vPkt *taropsbt.VPacket) ([]uint32, error)

	// AnchorVirtualTransactions creates a BTC level anchor transaction that
	// anchors all the virtual transactions of the given packets. This
	// method returns both the funded anchor TX with all the output
	// information intact for later exclusion proof creation, and the fully
	// signed and finalized anchor TX along with the total amount of sats
	// paid in chain fees by the anchor TX
	AnchorVirtualTransactions(ctx context.Context,
		feeRate chainfee.SatPerKWeight,
		inputCommitments []*commitment.TaroCommitment,
		vPkts []*taropsbt.VPacket) (*AnchorTransaction, error)
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
	vPkt := taropsbt.FromAddress(&receiverAddr, 1)

	fundDesc := &taroscript.FundingDescriptor{
		ID:       receiverAddr.ID(),
		GroupKey: receiverAddr.GroupKey,
		Amount:   receiverAddr.Amount,
	}
	inputCommitment, err := f.FundPacket(
		ctx, fundDesc, &receiverAddr.ScriptKey, vPkt,
	)
	if err != nil {
		return nil, nil, err
	}

	return vPkt, inputCommitment, nil
}

// FundPacket funds a virtual transaction, selecting assets to spend in order to
// pay the given recipient. The selected input is then added to the given
// virtual transaction.
func (f *AssetWallet) FundPacket(ctx context.Context,
	fundDesc *taroscript.FundingDescriptor,
	receiverScriptKey *btcec.PublicKey,
	vPkt *taropsbt.VPacket) (*commitment.TaroCommitment, error) {

	// The input and address networks must match.
	if !address.IsForNet(vPkt.ChainParams.TaroHRP, f.cfg.ChainParams) {
		return nil, address.ErrMismatchedHRP
	}

	// We need to find a commitment that has enough assets to satisfy this
	// send request. We'll map the address to a set of constraints, so we
	// can use that to do Taro asset coin selection.
	//
	// TODO(roasbeef): send logic assumes just one input (no merges) so we
	// pass in the amount here to ensure we have enough to send
	constraints := CommitmentConstraints{
		GroupKey: fundDesc.GroupKey,
		AssetID:  &fundDesc.ID,
		MinAmt:   fundDesc.Amount,
	}
	eligibleCommitments, err := f.cfg.CoinSelector.SelectCommitment(
		ctx, constraints,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to complete coin "+
			"selection: %w", err)
	}

	log.Infof("Selected %v possible asset inputs for send to %x",
		len(eligibleCommitments), receiverScriptKey.SerializeCompressed())

	// We'll take just the first commitment here as we need enough
	// to complete the send w/o merging inputs.
	assetInput := eligibleCommitments[0]

	// If the key found for the input UTXO is not from the Taro key family,
	// something has gone wrong with the DB.
	internalKey := assetInput.InternalKey
	if internalKey.Family != asset.TaroKeyFamily {
		return nil, fmt.Errorf("invalid internal key family "+
			"for selected input: %v %v", internalKey.Family,
			internalKey.Index)
	}

	inBip32Derivation, inTrBip32Derivation :=
		taropsbt.Bip32DerivationFromKeyDesc(
			internalKey, f.cfg.ChainParams.HDCoinType,
		)

	anchorPkScript, anchorMerkleRoot, err := inputAnchorPkScript(assetInput)
	if err != nil {
		return nil, fmt.Errorf("cannot calculate input asset pk "+
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
		return nil, fmt.Errorf("cannot fetch proof for input asset: %w",
			err)
	}
	inputProofFile := &proof.File{}
	err = inputProofFile.Decode(bytes.NewReader(inputProofBlob))
	if err != nil {
		return nil, fmt.Errorf("cannot decode proof for input asset: "+
			"%w", err)
	}
	inputProof, err := inputProofFile.RawLastProof()
	if err != nil {
		return nil, fmt.Errorf("cannot get last proof for input "+
			"asset: %w", err)
	}

	// At this point, we have a valid "coin" to spend in the commitment, so
	// we'll add the relevant information to the virtual TX's input.
	//
	// TODO(roasbeef): still need to add family key to PrevID.
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
		assetInput.Commitment, fundDesc,
		*vPkt.Inputs[0].Asset().ScriptKey.PubKey,
	)
	if err != nil {
		return nil, err
	}

	// We expect some change back, so let's create a script key to receive
	// the change on.
	if !fullValue {
		senderScriptKey, err := f.cfg.KeyRing.DeriveNextKey(
			ctx, asset.TaroKeyFamily,
		)
		if err != nil {
			return nil, err
		}

		// We'll assume BIP 86 everywhere, and use the tweaked key from
		// here on out.
		vPkt.Outputs[0].Amount = inputAsset.Amount - fundDesc.Amount
		vPkt.Outputs[0].ScriptKey = asset.NewScriptKeyBIP0086(
			senderScriptKey,
		)
	}

	// Before we can prepare output assets for our send, we need to generate
	// a new internal key for the anchor output of the asset change output.
	changeInternalKey, err := f.cfg.KeyRing.DeriveNextKey(
		ctx, asset.TaroKeyFamily,
	)
	if err != nil {
		return nil, err
	}
	vPkt.Outputs[0].SetAnchorInternalKey(
		changeInternalKey, f.cfg.ChainParams.HDCoinType,
	)

	if err := taroscript.PrepareOutputAssets(vPkt); err != nil {
		return nil, fmt.Errorf("unable to create split commit: %w",
			err)
	}

	return assetInput.Commitment, nil
}

// SignVirtualPacket signs the virtual transaction of the given packet and
// returns the input indexes that were signed (referring to the virtual
// transaction's inputs).
//
// NOTE: This is part of the Wallet interface.
func (f *AssetWallet) SignVirtualPacket(vPkt *taropsbt.VPacket) ([]uint32,
	error) {

	// Now we'll use the signer to sign all the inputs for the new taro
	// leaves. The witness data for each input will be assigned for us.
	signedInputs := make([]uint32, len(vPkt.Inputs))
	for idx := range vPkt.Inputs {
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

// AnchorVirtualTransactions creates a BTC level anchor transaction that
// anchors all the virtual transactions of the given packets. This method
// returns both the funded anchor TX with all the output information intact for
// later exclusion proof creation, and the fully signed and finalized anchor TX
// along with the total amount of sats paid in chain fees by the anchor TX.
//
// NOTE: This is part of the Wallet interface.
func (f *AssetWallet) AnchorVirtualTransactions(ctx context.Context,
	feeRate chainfee.SatPerKWeight,
	inputCommitments []*commitment.TaroCommitment,
	vPkts []*taropsbt.VPacket) (*AnchorTransaction, error) {

	// We currently only support anchoring a single virtual transaction.
	//
	// TODO(guggero): Support merging and anchoring multiple virtual
	// transactions.
	if len(vPkts) != 1 || len(inputCommitments) != 1 {
		return nil, fmt.Errorf("only a single virtual transaction is " +
			"supported for now")
	}
	vPacket := vPkts[0]
	inputCommitment := inputCommitments[0]

	outputCommitments, err := taroscript.CreateOutputCommitments(
		inputCommitment, vPacket,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to create new output "+
			"commitments: %w", err)
	}

	// Construct our template PSBT to commits to the set of dummy
	// locators we use to make fee estimation work.
	sendPacket, err := taroscript.CreateAnchorTx(vPacket.Outputs)
	if err != nil {
		return nil, fmt.Errorf("error creating anchor TX: %w", err)
	}

	anchorPkt, err := f.cfg.Wallet.FundPsbt(ctx, sendPacket, 1, feeRate)
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
		signAnchorPkt, vPacket, feeRate, f.cfg.ChainParams.Params,
	)
	if err != nil {
		return nil, fmt.Errorf("error adding anchor input: %w", err)
	}

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
		TargetFeeRate:     feeRate,
		ChainFees:         chainFees,
		OutputCommitments: mergedCommitments,
	}, nil
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

// adjustFundedPsbt takes a funded PSBT which may have used BIP 69 sorting, and
// creates a new one with outputs shuffled such that the change output is the
// last output.
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

	// With the BIP 32 information completed, we'll now add the information
	// as a partial input and also add the input to the unsigned
	// transaction.
	vIn := vPkt.Inputs[0]
	btcPkt.Inputs = append(btcPkt.Inputs, psbt.PInput{
		WitnessUtxo: &wire.TxOut{
			Value:    int64(vIn.Anchor.Value),
			PkScript: vIn.Anchor.PkScript,
		},
		SighashType: vIn.Anchor.SigHashType,
		Bip32Derivation: []*psbt.Bip32Derivation{
			vIn.Anchor.Bip32Derivation,
		},
		TaprootBip32Derivation: []*psbt.TaprootBip32Derivation{
			vIn.Anchor.TrBip32Derivation,
		},
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
