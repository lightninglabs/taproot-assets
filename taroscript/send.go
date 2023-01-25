package taroscript

import (
	"errors"
	"fmt"
	"math"

	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/commitment"
	"github.com/lightninglabs/taro/taropsbt"
)

var (
	// ErrInvalidCollectibleSplit is returned when a collectible is split
	// into more than two outputs.
	ErrInvalidCollectibleSplit = errors.New(
		"fund: invalid collectible split",
	)

	// ErrInvalidChangeOutputLocation is returned when the change output is
	// not at the expected location (index 0).
	ErrInvalidChangeOutputLocation = errors.New(
		"fund: invalid change output location, should be index 0",
	)

	// ErrInvalidSplitAmounts is returned when the split amounts don't add
	// up to the amount of the asset being spent.
	ErrInvalidSplitAmounts = errors.New(
		"fund: invalid split amounts, sum doesn't match input",
	)
)

// PrepareOutputAssets prepares the assets of the given outputs depending on
// the amounts set on the transaction. If a split is necessary (non-interactive
// or partial amount send) it computes a split commitment with the given input
// and spend information. The input MUST be checked as valid beforehand and the
// change output is expected to be declared as such (and be at index 0).
func PrepareOutputAssets(input *taropsbt.VInput,
	outputs []*taropsbt.VOutput) error {

	// This should be caught way earlier but just to make sure that we never
	// overflow when converting the input amount to int64 we check this
	// again.
	inputAsset := input.Asset()
	if inputAsset.Amount > math.MaxInt64 {
		return fmt.Errorf("amount int64 overflow")
	}

	// A collectible cannot be split into individual pieces. So there can
	// only be a tombstone and a recipient output.
	if inputAsset.Type == asset.Collectible && len(outputs) > 2 {
		return ErrInvalidCollectibleSplit
	}

	var (
		residualAmount = inputAsset.Amount
		splitLocators  = make([]*commitment.SplitLocator, len(outputs))
	)
	for idx := range outputs {
		vOut := outputs[idx]

		// We assume the first output is the change output (or
		// tombstone if there is no change in a non-interactive send).
		if idx == 0 {
			// The change output should always be at index 0.
			if !vOut.IsChange {
				return ErrInvalidChangeOutputLocation
			}

			// A zero-amount change output (tombstone) must spend to
			// the un-spendable NUMS script key.
			if vOut.Amount == 0 &&
				!vOut.ScriptKey.PubKey.IsEqual(asset.NUMSPubKey) {

				return commitment.ErrInvalidScriptKey
			}
		} else {
			if vOut.IsChange {
				return ErrInvalidChangeOutputLocation
			}
		}

		residualAmount -= vOut.Amount

		locator := vOut.SplitLocator(inputAsset.ID())
		splitLocators[idx] = &locator
	}

	// We should now have exactly zero value left over after splitting.
	if residualAmount != 0 {
		return ErrInvalidSplitAmounts
	}

	// If we have an interactive full value send, we don't need a tomb stone
	// at all.
	inputIDCopy := input.PrevID
	if interactiveFullValueSend(input, outputs) {
		// We'll now create a new copy of the old asset, swapping out
		// the script key. We blank out the tweaked key information as
		// this is now an external asset.
		outputs[1].Asset = inputAsset.Copy()
		outputs[1].Asset.ScriptKey = outputs[1].ScriptKey

		// Record the PrevID of the input asset in a Witness for the new
		// asset. This Witness still needs a valid signature for the new
		// asset to be valid.
		//
		// TODO(roasbeef): when we fix #121, then this should also be a
		// ZeroPrevID
		outputs[1].Asset.PrevWitnesses = []asset.Witness{
			{
				PrevID:          &inputIDCopy,
				TxWitness:       nil,
				SplitCommitment: nil,
			},
		}

		// We are done, since we don't need to create a split
		// commitment.
		return nil
	}

	splitCommitment, err := commitment.NewSplitCommitment(
		inputAsset, input.PrevID.OutPoint, splitLocators[0],
		splitLocators[1:]...,
	)
	if err != nil {
		return err
	}

	// Assign each of the split assets to their respective outputs.
	input.IsSplit = true
	for idx := range outputs {
		// The change output for a split asset send always gets the root
		// asset committed, even if it's a zero value (tombstone) split
		// output for the sender.
		if outputs[idx].IsChange {
			outputs[idx].Asset = splitCommitment.RootAsset.Copy()
			continue
		}

		locator := splitLocators[idx]
		splitAsset, ok := splitCommitment.SplitAssets[*locator]
		if !ok {
			return fmt.Errorf("invalid split, asset for locator "+
				"%v not found", locator)
		}

		outputs[idx].Asset = &splitAsset.Asset
		outputs[idx].Asset.ScriptKey = outputs[idx].ScriptKey
	}

	return nil
}

// interactiveFullValueSend returns true if the given outputs spend the input
// fully and interactively.
func interactiveFullValueSend(input *taropsbt.VInput,
	outputs []*taropsbt.VOutput) bool {

	return len(outputs) == 2 &&
		outputs[1].Amount == input.Asset().Amount &&
		outputs[1].Interactive
}
