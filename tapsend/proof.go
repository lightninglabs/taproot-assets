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

// Copy creates a deep copy of the FundedPsbt.
func (f *FundedPsbt) Copy() *FundedPsbt {
	newFundedPsbt := &FundedPsbt{
		ChangeOutputIndex: f.ChangeOutputIndex,
		ChainFees:         f.ChainFees,
		LockedUTXOs:       fn.CopySlice(f.LockedUTXOs),
	}

	if f.Pkt != nil {
		newFundedPsbt.Pkt = &psbt.Packet{
			UnsignedTx: f.Pkt.UnsignedTx.Copy(),
			Inputs:     fn.CopySlice(f.Pkt.Inputs),
			Outputs:    fn.CopySlice(f.Pkt.Outputs),
			Unknowns:   fn.CopySlice(f.Pkt.Unknowns),
		}
	}

	return newFundedPsbt
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

// Copy creates a deep copy of the AnchorTransaction.
func (a *AnchorTransaction) Copy() *AnchorTransaction {
	newAnchorTx := &AnchorTransaction{
		TargetFeeRate: a.TargetFeeRate,
		ChainFees:     a.ChainFees,
	}

	if a.FundedPsbt != nil {
		newAnchorTx.FundedPsbt = a.FundedPsbt.Copy()
	}

	if a.FinalTx != nil {
		newAnchorTx.FinalTx = a.FinalTx.Copy()
	}

	return newAnchorTx
}

// IsAnchor is a function type that can be used to determine if a given BTC
// transaction output at the given index is an anchor for committing assets.
type IsAnchor func(anchorOutputIndex uint32) bool

// ExclusionProofGenerator is a function type that can be used to generate
// exclusion proofs for any BTC transaction outputs that don't carry any assets.
// The function should add the exclusion proofs to the given target proof
// parameters.
type ExclusionProofGenerator func(target *proof.BaseProofParams,
	isAnchor IsAnchor) error

// CreateProofSuffix creates a new proof for the given virtual transaction
// output indicated with outIndex within vPacket. This is the final state
// transition that will be added to the proofs of the receiver. The proof
// returned will have all the Taproot Asset level proof information, but
// contains dummy data for the on-chain part and potentially the anchor
// transaction itself, if chainTx is not yet fully final. Only the outputs of
// chainTx need to be final and correspond to the PSBT outputs given as
// finalTxPacketOutputs.
func CreateProofSuffix(chainTx *wire.MsgTx, finalTxPacketOutputs []psbt.POutput,
	vPacket *tappsbt.VPacket, outputCommitments tappsbt.OutputCommitments,
	outIndex int, allAnchoredVPackets []*tappsbt.VPacket) (*proof.Proof,
	error) {

	return CreateProofSuffixCustom(
		chainTx, vPacket, outputCommitments, outIndex,
		allAnchoredVPackets, func(target *proof.BaseProofParams,
			isAnchor IsAnchor) error {

			// Nothing to do if there is only one output, as we
			// know we commit assets at this point, so the single
			// output must be an asset commitment output.
			if len(chainTx.TxOut) <= 1 {
				return nil
			}

			return proof.AddExclusionProofs(
				target, chainTx, finalTxPacketOutputs,
				isAnchor,
			)
		},
	)
}

// CreateProofSuffixCustom creates the new proof for the given virtual
// transaction output indicated with outIndex within vPacket. This is the final
// state transition that will be added to the proofs of the receiver. The proof
// returned will have all the Taproot Asset level proof information, but
// contains dummy data for the on-chain part and potentially the anchor
// transaction itself, if chainTx is not yet fully final or even nil. If chainTx
// is nil, it must be set on the proof later manually to make the proof valid.
// The exclusion proof generator function must add an exclusion proof for each
// P2TR on-chain output that is NOT an asset commitment (e.g. P2TR change
// outputs or other pure BTC P2TR outputs).
func CreateProofSuffixCustom(finalTx *wire.MsgTx, vPacket *tappsbt.VPacket,
	outputCommitments tappsbt.OutputCommitments, outIndex int,
	allAnchoredVPackets []*tappsbt.VPacket,
	genExclusionProofs ExclusionProofGenerator) (*proof.Proof, error) {

	inputPrevID := vPacket.Inputs[0].PrevID

	params, err := proofParams(
		finalTx, vPacket, outputCommitments, outIndex,
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

	// We also need to account for any P2TR change outputs or other pure
	// BTC P2TR outputs (for example a commitment CPFP anchor output).
	err = genExclusionProofs(&params.BaseProofParams, isAnchor)
	if err != nil {
		return nil, fmt.Errorf("error adding exclusion proof for "+
			"output %d: %w", outIndex, err)
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
func newParams(finalTx *wire.MsgTx, a *asset.Asset, outputIndex int,
	internalKey *btcec.PublicKey, taprootAssetRoot *commitment.TapCommitment,
	siblingPreimage *commitment.TapscriptPreimage) *proof.TransitionParams {

	return &proof.TransitionParams{
		BaseProofParams: proof.BaseProofParams{
			Block: &wire.MsgBlock{
				Transactions: []*wire.MsgTx{
					finalTx,
				},
			},
			Tx:               finalTx,
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
func proofParams(finalTx *wire.MsgTx, vPkt *tappsbt.VPacket,
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
			finalTx, rootOut.Asset, int(rootIndex),
			rootOut.AnchorOutputInternalKey, rootTapTree,
			rootOut.AnchorOutputTapscriptSibling,
		)

		// Add exclusion proofs for all the other outputs.
		err = addOtherOutputExclusionProofs(
			allVirtualOutputs, rootOut.Asset, rootParams,
			outputCommitments,
		)

		// Add STXO exclusion proofs for all the other outputs, for all
		// STXOs spent by _all_ VOutputs that anchor in this output.
		// First Collect all STXOs for this anchor output. Then add
		// exclusion proofs for all the other anchor outputs. Add these
		// in proofParams in tapsend/proof.go Those proofParams end up
		// in `CreateTransitionProof` in tapsend/append.go, where we
		// create the basic proof template. There we drop the STXO
		// exclusion proofs in proof.UnknownOddTypes.
		err := addSTXOExclusionProofs(
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
		finalTx, splitOut.Asset, int(splitIndex),
		splitOut.AnchorOutputInternalKey, splitTapTree,
		splitOut.AnchorOutputTapscriptSibling,
	)
	splitParams.RootOutputIndex = splitRootIndex
	splitParams.RootInternalKey = splitRootOut.AnchorOutputInternalKey
	splitParams.RootTapscriptSibling = splitRootPreimage
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

// addSTXOExclusionProofs adds exclusion proofs for all the STXOs of the asset,
// for all the outputs that are asset outputs but haven't been processed yet,
// otherwise they'll be skipped. This should only be called after
// `addOtherOutputExclusionProofs` because it depends on
// `params.ExclusionProofs` already being set.
func addSTXOExclusionProofs(outputs []*tappsbt.VOutput,
	newAsset *asset.Asset, params *proof.TransitionParams,
	outputCommitments map[uint32]*commitment.TapCommitment) error {

	stxoAssets, err := asset.CollectSTXO(newAsset)
	if err != nil {
		return fmt.Errorf("error collecting STXO assets: %w", err)
	}

	for idx := range outputs {
		vOut := outputs[idx]

		outIndex := vOut.AnchorOutputIndex

		// We can use `HaveInclusionProof` here because it is just a
		// check on whether we are processing our own anchor output.
		haveIProof := params.HaveInclusionProof(outIndex)
		haveEProof := params.HaveSTXOExclusionProof(outIndex)
		if haveIProof || haveEProof {
			continue
		}

		tapTree := outputCommitments[outIndex]

		for idx := range stxoAssets {
			stxoAsset := stxoAssets[idx].(*asset.Asset)
			pubKey := stxoAsset.ScriptKey.PubKey
			identifier := asset.ToSerialized(pubKey)

			_, exclusionProof, err := tapTree.Proof(
				stxoAsset.TapCommitmentKey(),
				stxoAsset.AssetCommitmentKey(),
			)
			if err != nil {
				return err
			}

			// Find the exclusion proofs for this output.
			var eProof *proof.TaprootProof
			for idx := range params.ExclusionProofs {
				e := params.ExclusionProofs[idx]
				if e.OutputIndex == outIndex {
					eProof = &params.ExclusionProofs[idx]
					break
				}
			}
			if eProof == nil {
				return fmt.Errorf("no exclusion proof for "+
					"output %d", outIndex)
			}

			// There aren't any assets in that output, we can skip
			// creating exclusion proofs for it.
			if eProof.CommitmentProof == nil {
				continue
			}

			commitmentProof := eProof.CommitmentProof

			// Confirm that we are creating the stxo proofs for the
			// asset that is being created. We do this by confirming
			// that the exclusion proof for the newly created asset
			// is already present.
			_, err = eProof.DeriveByAssetExclusion(
				newAsset.AssetCommitmentKey(),
				newAsset.TapCommitmentKey(),
			)
			if err != nil {
				return fmt.Errorf("v1 proof for newly created "+
					"asset not found during creation of "+
					"stxo proofs: %w", err)
			}

			//nolint:lll
			if commitmentProof.STXOProofs == nil {
				commitmentProof.STXOProofs = make(
					map[asset.SerializedKey]commitment.Proof,
				)
			}

			commitmentProof.STXOProofs[identifier] = *exclusionProof
		}
	}

	return nil
}

// addOtherOutputExclusionProofs adds exclusion proofs for all the outputs that
// are asset outputs but haven't been processed yet, otherwise they'll be
// skipped.
func addOtherOutputExclusionProofs(outputs []*tappsbt.VOutput,
	asset *asset.Asset, params *proof.TransitionParams,
	outputCommitments map[uint32]*commitment.TapCommitment) error {

	for idx := range outputs {
		vOut := outputs[idx]

		outIndex := vOut.AnchorOutputIndex
		haveIProof := params.HaveInclusionProof(outIndex)
		haveEProof := params.HaveExclusionProof(outIndex)
		if haveIProof || haveEProof {
			continue
		}

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
