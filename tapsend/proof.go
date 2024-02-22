package tapsend

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
)

// FundedPsbt represents a fully funded PSBT transaction.
type FundedPsbt struct {
	// Pkt is the PSBT packet itself.
	Pkt *psbt.Packet

	// ChangeOutputIndex denotes which output in the PSBT packet is the
	// change output. We use this to figure out which output will store our
	// Taproot Asset commitment (the non-change output).
	ChangeOutputIndex int32

	// ChainFees is the amount in sats paid in on-chain fees for this
	// transaction.
	ChainFees int64

	// LockedUTXOs is the set of UTXOs that were locked to create the PSBT
	// packet.
	LockedUTXOs []wire.OutPoint
}

// AnchorTransaction is a type that holds all information about a BTC level
// anchor transaction that anchors multiple virtual asset transfer transactions.
type AnchorTransaction struct {
	// FundedPsbt is the funded anchor TX at the state before it was signed,
	// with all the UTXO information intact for later exclusion proof
	// creation.
	FundedPsbt *FundedPsbt

	// FinalTx is the fully signed and finalized anchor TX that can be
	// broadcast to the network.
	FinalTx *wire.MsgTx

	// TargetFeeRate is the fee rate that was used to fund the anchor TX.
	TargetFeeRate chainfee.SatPerKWeight

	// ChainFees is the actual, total amount of sats paid in chain fees by
	// the anchor TX.
	ChainFees int64
}

// CreateProofSuffix creates the new proof for the given output. This is the
// final state transition that will be added to the proofs of the receiver. The
// proof returned will have all the Taproot Asset level proof information, but
// contains dummy data for the on-chain part.
func CreateProofSuffix(anchorTx *AnchorTransaction, vPacket *tappsbt.VPacket,
	outputCommitments tappsbt.OutputCommitments, outIndex int,
	allAnchoredVPackets []*tappsbt.VPacket) (*proof.Proof, error) {

	inputPrevID := vPacket.Inputs[0].PrevID

	params, err := proofParams(
		anchorTx, vPacket, outputCommitments, outIndex,
		allAnchoredVPackets,
	)
	if err != nil {
		return nil, err
	}

	isAnchor := func(anchorOutputIndex uint32) bool {
		// Does the current virtual packet anchor into this output?
		for outIdx := range vPacket.Outputs {
			vOut := vPacket.Outputs[outIdx]
			if vOut.AnchorOutputIndex == anchorOutputIndex {
				return true
			}
		}

		// Maybe any of the other anchored virtual packets anchor into
		// this output?
		for _, vPkt := range allAnchoredVPackets {
			for _, vOut := range vPkt.Outputs {
				if vOut.AnchorOutputIndex == anchorOutputIndex {
					return true
				}
			}
		}

		// No virtual packet anchors into this output, it must be a
		// pure BTC output.
		return false
	}

	// We also need to account for any P2TR change outputs.
	if len(anchorTx.FundedPsbt.Pkt.UnsignedTx.TxOut) > 1 {
		err := proof.AddExclusionProofs(
			&params.BaseProofParams, anchorTx.FundedPsbt.Pkt,
			isAnchor,
		)
		if err != nil {
			return nil, fmt.Errorf("error adding exclusion "+
				"proof for output %d: %w", outIndex, err)
		}
	}

	proofSuffix, err := proof.CreateTransitionProof(
		inputPrevID.OutPoint, params,
	)
	if err != nil {
		return nil, err
	}

	return proofSuffix, nil
}

// newParams is used to create a set of new params for the final state
// transition.
func newParams(anchorTx *AnchorTransaction, a *asset.Asset, outputIndex int,
	internalKey *btcec.PublicKey, taprootAssetRoot *commitment.TapCommitment,
	siblingPreimage *commitment.TapscriptPreimage) *proof.TransitionParams {

	return &proof.TransitionParams{
		BaseProofParams: proof.BaseProofParams{
			Block: &wire.MsgBlock{
				Transactions: []*wire.MsgTx{
					anchorTx.FinalTx,
				},
			},
			Tx:               anchorTx.FinalTx,
			TxIndex:          0,
			OutputIndex:      outputIndex,
			InternalKey:      internalKey,
			TaprootAssetRoot: taprootAssetRoot,
			TapscriptSibling: siblingPreimage,
		},
		NewAsset: a,
	}
}

// proofParams creates the set of parameters that will be used to create the
// proofs for the sender and receiver.
func proofParams(anchorTx *AnchorTransaction, vPkt *tappsbt.VPacket,
	outputCommitments tappsbt.OutputCommitments, outIndex int,
	allAnchoredVPackets []*tappsbt.VPacket) (*proof.TransitionParams, error) {

	isSplit, err := vPkt.HasSplitCommitment()
	if err != nil {
		return nil, err
	}

	allVirtualOutputs := append([]*tappsbt.VOutput{}, vPkt.Outputs...)
	for _, otherVPkt := range allAnchoredVPackets {
		allVirtualOutputs = append(
			allVirtualOutputs, otherVPkt.Outputs...,
		)
	}

	// Is this the split root? Then we need exclusion proofs from all the
	// split outputs. We can also use this path for interactive full value
	// send case, where we also just commit to an asset that has a TX
	// witness. We just need an inclusion proof and the exclusion proofs for
	// any other outputs.
	if vPkt.Outputs[outIndex].Type.IsSplitRoot() || !isSplit {
		rootOut := vPkt.Outputs[outIndex]
		rootIndex := rootOut.AnchorOutputIndex
		rootTapTree := outputCommitments[rootIndex]

		rootParams := newParams(
			anchorTx, rootOut.Asset, int(rootIndex),
			rootOut.AnchorOutputInternalKey, rootTapTree,
			rootOut.AnchorOutputTapscriptSibling,
		)

		// Add exclusion proofs for all the other outputs.
		err = addOtherOutputExclusionProofs(
			allVirtualOutputs, rootOut.Asset, rootParams,
			outputCommitments,
		)
		if err != nil {
			return nil, err
		}

		return rootParams, nil
	}

	// If this isn't the split root, then we need an exclusion proof from
	// just the split root.
	splitRootOut, err := vPkt.SplitRootOutput()
	if err != nil {
		return nil, fmt.Errorf("error getting split root output: %w",
			err)
	}

	splitRootIndex := splitRootOut.AnchorOutputIndex
	splitRootTree := outputCommitments[splitRootIndex]

	splitOut := vPkt.Outputs[outIndex]
	splitIndex := splitOut.AnchorOutputIndex
	splitTapTree := outputCommitments[splitIndex]

	_, splitRootExclusionProof, err := splitRootTree.Proof(
		splitOut.Asset.TapCommitmentKey(),
		splitOut.Asset.AssetCommitmentKey(),
	)
	if err != nil {
		return nil, err
	}

	splitRootPreimage := splitRootOut.AnchorOutputTapscriptSibling
	splitParams := newParams(
		anchorTx, splitOut.Asset, int(splitIndex),
		splitOut.AnchorOutputInternalKey, splitTapTree,
		splitOut.AnchorOutputTapscriptSibling,
	)
	splitParams.RootOutputIndex = splitRootIndex
	splitParams.RootInternalKey = splitRootOut.AnchorOutputInternalKey
	splitParams.RootTaprootAssetTree = splitRootTree
	splitParams.ExclusionProofs = []proof.TaprootProof{{
		OutputIndex: splitRootIndex,
		InternalKey: splitRootOut.AnchorOutputInternalKey,
		CommitmentProof: &proof.CommitmentProof{
			Proof:              *splitRootExclusionProof,
			TapSiblingPreimage: splitRootPreimage,
		},
	}}

	// Add exclusion proofs for all the other outputs.
	err = addOtherOutputExclusionProofs(
		allVirtualOutputs, splitOut.Asset, splitParams,
		outputCommitments,
	)
	if err != nil {
		return nil, err
	}

	return splitParams, nil
}

// addOtherOutputExclusionProofs adds exclusion proofs for all the outputs that
// are asset outputs but haven't been processed yet (the skip function needs to
// return false for not yet processed outputs, otherwise they'll be skipped).
func addOtherOutputExclusionProofs(outputs []*tappsbt.VOutput,
	asset *asset.Asset, params *proof.TransitionParams,
	outputCommitments map[uint32]*commitment.TapCommitment) error {

	for idx := range outputs {
		vOut := outputs[idx]

		haveIProof := params.HaveInclusionProof(vOut.AnchorOutputIndex)
		haveEProof := params.HaveExclusionProof(vOut.AnchorOutputIndex)
		if haveIProof || haveEProof {
			continue
		}

		outIndex := vOut.AnchorOutputIndex
		tapTree := outputCommitments[outIndex]

		_, splitExclusionProof, err := tapTree.Proof(
			asset.TapCommitmentKey(),
			asset.AssetCommitmentKey(),
		)
		if err != nil {
			return err
		}

		log.Tracef("Generated exclusion proof for anchor output index "+
			"%d with asset_id=%v, taproot_asset_root=%x, "+
			"internal_key=%x", outIndex, asset.ID(),
			fn.ByteSlice(tapTree.TapscriptRoot(nil)),
			vOut.AnchorOutputInternalKey.SerializeCompressed())

		siblingPreimage := vOut.AnchorOutputTapscriptSibling
		exclusionProof := proof.TaprootProof{
			OutputIndex: outIndex,
			InternalKey: vOut.AnchorOutputInternalKey,
			CommitmentProof: &proof.CommitmentProof{
				Proof:              *splitExclusionProof,
				TapSiblingPreimage: siblingPreimage,
			},
		}
		params.ExclusionProofs = append(
			params.ExclusionProofs, exclusionProof,
		)
	}

	return nil
}
