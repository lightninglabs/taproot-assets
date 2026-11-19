package tapsend

import (
	"fmt"

	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tappsbt"
)

// ValidateAnchoredPackets checks that the virtual packets exactly spend the
// asset commitments of the anchor transaction's inputs and neither create nor
// destroy asset units. purgedAssets holds, per anchor input, the un-spendable
// assets of its commitment that the packets do not carry over.
func ValidateAnchoredPackets(anchorPkt *psbt.Packet,
	vPackets []*tappsbt.VPacket,
	purgedAssets map[wire.OutPoint][]*asset.Asset) error {

	// At this point all the virtual packet inputs and outputs should fully
	// match the BTC level anchor transaction. Version 0 assets should also
	// be signed now.
	if err := AssertInputAnchorsEqual(vPackets); err != nil {
		return fmt.Errorf("input anchors don't match: %w", err)
	}
	if err := AssertOutputAnchorsEqual(vPackets); err != nil {
		return fmt.Errorf("output anchors don't match: %w", err)
	}
	err := ValidateAnchorInputs(anchorPkt, vPackets, purgedAssets)
	if err != nil {
		return fmt.Errorf("error validating anchor inputs: %w", err)
	}

	// The witness of a split only signs the split commitment root, so we
	// make sure each split root asset is the one its split tree commits
	// to. Otherwise a split root could be changed after signing, for
	// example to point to another script key at the same amount.
	if err := ValidateSplitRootLocators(vPackets); err != nil {
		return fmt.Errorf("error validating split roots: %w", err)
	}

	// Now that we know the packet inputs match the anchored assets, we can
	// also check that we don't inflate or deflate the asset supply with the
	// active and passive assets. We explicitly don't look at the pruned
	// assets. We have already made sure that the total sum of all inputs
	// that was committed to in the input anchor is accounted for with the
	// active, passive and pruned assets. Now we just need to make sure the
	// active and passive transfers don't create or destroy assets.
	inputBalances := make(map[asset.ID]uint64)
	outputBalances := make(map[asset.ID]uint64)
	for _, vPkt := range vPackets {
		for _, vIn := range vPkt.Inputs {
			inputBalances[vIn.Asset().ID()] += vIn.Asset().Amount
		}
		for _, vOut := range vPkt.Outputs {
			outputBalances[vOut.Asset.ID()] += vOut.Asset.Amount
		}
	}
	for assetID, inputBalance := range inputBalances {
		outputBalance := outputBalances[assetID]
		if inputBalance != outputBalance {
			return fmt.Errorf("input and output balances don't "+
				"match for asset %x: %d != %d", assetID[:],
				inputBalance, outputBalance)
		}
	}

	return nil
}

// CommitPackets commits the virtual packets to the funded anchor packet. It
// creates the output commitments, writes them into the anchor outputs and
// sets the transition proof suffix of every virtual output.
func CommitPackets(anchorPkt *psbt.Packet, vPackets []*tappsbt.VPacket,
	proofOpts ...proof.GenOption) error {

	outputCommitments, err := CreateOutputCommitments(
		vPackets, WithSpenderLeaves(),
	)
	if err != nil {
		return fmt.Errorf("unable to create new output "+
			"commitments: %w", err)
	}

	for _, vPkt := range vPackets {
		err = UpdateTaprootOutputKeys(
			anchorPkt, vPkt, outputCommitments,
		)
		if err != nil {
			return fmt.Errorf("error updating taproot output "+
				"keys: %w", err)
		}
	}

	// We're done creating the output commitments, we can now create the
	// transition proof suffixes.
	for idx := range vPackets {
		vPkt := vPackets[idx]

		for vOutIdx := range vPkt.Outputs {
			proofSuffix, err := CreateProofSuffix(
				anchorPkt.UnsignedTx, anchorPkt.Outputs, vPkt,
				outputCommitments, vOutIdx, vPackets,
				proofOpts...,
			)
			if err != nil {
				return fmt.Errorf("unable to create "+
					"proof suffix for output %d of vPSBT "+
					"%d: %w", vOutIdx, idx, err)
			}

			vPkt.Outputs[vOutIdx].ProofSuffix = proofSuffix
		}
	}

	return nil
}
