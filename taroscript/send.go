package taroscript

import (
	"errors"
	"fmt"
	"math"

	"github.com/btcsuite/btcd/txscript"
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
// or partial amount send) it computes a split commitment with the given inputs
// and spend information. The inputs MUST be checked as valid beforehand and the
// change output is expected to be declared as such (and be at index 0).
func PrepareOutputAssets(vPkt *taropsbt.VPacket) error {
	// We currently only support a single input.
	//
	// TODO(guggero): Support multiple inputs.
	if len(vPkt.Inputs) != 1 {
		return fmt.Errorf("only a single input is currently supported")
	}
	input := vPkt.Inputs[0]
	outputs := vPkt.Outputs

	// This should be caught way earlier but just to make sure that we never
	// overflow when converting the input amount to int64 we check this
	// again.
	inputAsset := input.Asset()
	if inputAsset.Amount > math.MaxInt64 {
		return fmt.Errorf("amount int64 overflow")
	}

	// Do some general sanity checks on the outputs, these should be
	// independent of the number of outputs.
	for idx := range outputs {
		vOut := outputs[idx]

		// This method returns an error if the script key's public key
		// isn't set, which should be the case right now.
		isUnSpendable, err := vOut.ScriptKey.IsUnSpendable()
		if err != nil {
			return fmt.Errorf("output %d has invalid script key: "+
				"%w", idx, err)
		}

		switch {
		// Only the split root can be un-spendable.
		case !vOut.IsSplitRoot && isUnSpendable:
			return commitment.ErrInvalidScriptKey

		// Only the split root can have a zero amount.
		case !vOut.IsSplitRoot && vOut.Amount == 0:
			return commitment.ErrZeroSplitAmount

		// Interactive outputs can't be un-spendable, since there is no
		// need for a tombstone output and burns work in a different
		// way.
		case vOut.Interactive && isUnSpendable:
			return commitment.ErrInvalidScriptKey

		// Interactive outputs can't have a zero amount.
		case vOut.Interactive && vOut.Amount == 0:
			return commitment.ErrZeroSplitAmount
		}
	}

	switch {
	// We need at least one output.
	case len(outputs) == 0:
		return fmt.Errorf("no outputs specified in virtual packet")

	// A single output implies an interactive send. The value should be
	// equal to the input amount and the script key should be a spendable
	// one.
	case len(outputs) == 1:
		vOut := outputs[0]

		if vOut.IsSplitRoot {
			return fmt.Errorf("single output cannot be split root")
		}
		if !vOut.Interactive {
			return fmt.Errorf("single output must be interactive")
		}

		if vOut.Amount != inputAsset.Amount {
			return ErrInvalidSplitAmounts
		}

	// A two output transaction must have the change at index 0 if it is a
	// non-interactive send.
	case len(outputs) == 2:
		// A collectible cannot be split into individual pieces. So for
		// a two output transaction to be a valid collectible send, it
		// needs to be a non-interactive send where we expect there to
		// be a tombstone output for the split root.
		if inputAsset.Type == asset.Collectible {
			if !vPkt.HasSplitRootOutput() {
				return ErrInvalidCollectibleSplit
			}
			if vPkt.HasInteractiveOutput() {
				return ErrInvalidCollectibleSplit
			}

			rootOut, err := vPkt.SplitRootOutput()
			if err != nil {
				return ErrInvalidCollectibleSplit
			}
			recipientOut, err := vPkt.FirstNonSplitRootOutput()
			if err != nil {
				return ErrInvalidCollectibleSplit
			}

			if rootOut.Amount != 0 {
				return ErrInvalidCollectibleSplit
			}
			if recipientOut.Amount != 1 {
				return ErrInvalidCollectibleSplit
			}

			// We already checked this for each output in the loop
			// above, so we can ignore the error. The only
			// additional check here is that the split root output
			// MUST be un-spendable, since there cannot be a change
			// amount from a collectible.
			rootUnSpendable, _ := rootOut.ScriptKey.IsUnSpendable()
			if !rootUnSpendable {
				return ErrInvalidCollectibleSplit
			}
		}

	// For any other number of outputs, we can't really assert that much
	// more, since it might be mixed interactive and non-interactive
	// transfer.
	default:
	}

	var (
		residualAmount = inputAsset.Amount
		splitLocators  = make([]*commitment.SplitLocator, len(outputs))
		inputAssetID   = inputAsset.ID()
	)
	for idx := range outputs {
		residualAmount -= outputs[idx].Amount

		locator := outputs[idx].SplitLocator(inputAssetID)
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
		outputs[0].Asset = inputAsset.Copy()
		outputs[0].Asset.ScriptKey = outputs[0].ScriptKey

		// Record the PrevID of the input asset in a Witness for the new
		// asset. This Witness still needs a valid signature for the new
		// asset to be valid.
		outputs[0].Asset.PrevWitnesses = []asset.Witness{
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
	for idx := range outputs {
		locator := splitLocators[idx]
		vOut := outputs[idx]

		splitAsset, ok := splitCommitment.SplitAssets[*locator]
		if !ok {
			return fmt.Errorf("invalid split, asset for locator "+
				"%v not found", locator)
		}

		// The change output should be marked as the split root, even if
		// it's a zero value (tombstone) split output for the sender.
		if vOut.IsSplitRoot {
			vOut.Asset = splitCommitment.RootAsset.Copy()
			vOut.SplitAsset = &splitAsset.Asset
			vOut.SplitAsset.ScriptKey = vOut.ScriptKey

			continue
		}

		vOut.Asset = &splitAsset.Asset
		vOut.Asset.ScriptKey = vOut.ScriptKey
	}

	return nil
}

// SignVirtualTransaction updates the new asset (the root asset located at the
// change output in case of a non-interactive or partial amount send or the
// full asset in case of an interactive full amount send) by creating a
// signature over the asset transfer, verifying the transfer with the Taro VM,
// and attaching that signature to the new Asset.
//
// TODO(guggero): We also need to take into account any other assets that were
// in the same commitment as the asset we spend. We need to re-sign those as
// well and place them in the change output of this transaction.
// See https://github.com/lightninglabs/taro/issues/241.
func SignVirtualTransaction(vPkt *taropsbt.VPacket, inputIdx int,
	signer Signer, validator TxValidator) error {

	// We currently only support a single input.
	//
	// TODO(guggero): Support multiple inputs.
	if len(vPkt.Inputs) != 1 || inputIdx != 0 {
		return fmt.Errorf("only a single input is currently supported")
	}
	input := vPkt.Inputs[0]
	outputs := vPkt.Outputs

	// If this is a split transfer, it means that the asset to be signed is
	// the root asset, which is located at the change output.
	isSplit, err := vPkt.HasSplitCommitment()
	if err != nil {
		return err
	}

	prevAssets := commitment.InputSet{
		input.PrevID: input.Asset(),
	}
	newAsset := outputs[0].Asset

	// Create a Taro virtual transaction representing the asset transfer.
	virtualTx, _, err := VirtualTx(newAsset, prevAssets)
	if err != nil {
		return err
	}

	// For each input asset leaf, we need to produce a witness. Update the
	// input of the virtual TX, generate a witness, and attach it to the
	// copy of the new Asset.
	virtualTxCopy := VirtualTxWithInput(
		virtualTx, input.Asset(), uint32(inputIdx), nil,
	)
	newWitness, err := SignTaprootKeySpend(
		*input.Asset().ScriptKey.RawKey.PubKey, virtualTxCopy,
		input.Asset(), inputIdx, txscript.SigHashDefault, signer,
	)
	if err != nil {
		return err
	}

	newAsset.PrevWitnesses[inputIdx].TxWitness = *newWitness

	// Create an instance of the Taro VM and validate the transfer.
	verifySpend := func(splitAssets []*commitment.SplitAsset) error {
		newAssetCopy := newAsset.Copy()
		return validator.Execute(newAssetCopy, splitAssets, prevAssets)
	}

	// If the transfer contains no asset splits, we only need to validate
	// the new asset with its witness attached, then we can exit early.
	if !isSplit {
		return verifySpend(nil)
	}

	// If the transfer includes an asset split, we have to validate each
	// split asset to ensure that our new Asset is committing to a valid
	// SplitCommitment.
	splitAssets := make([]*commitment.SplitAsset, len(outputs))
	for idx := range outputs {
		splitAssets[idx] = &commitment.SplitAsset{
			Asset:       *outputs[idx].Asset,
			OutputIndex: outputs[idx].AnchorOutputIndex,
		}

		// The output that houses the root asset in case of a split has
		// a special field for the split asset, which actually contains
		// the split commitment proof. We need to use that one for the
		// validation, as the root asset is already validated as the
		// newAsset.
		if outputs[idx].IsSplitRoot {
			splitAssets[idx].Asset = *outputs[idx].SplitAsset
		}
	}
	if err := verifySpend(splitAssets); err != nil {
		return err
	}

	// Update each split asset to store the root asset with the witness
	// attached, so the receiver can verify inclusion of the root asset.
	for idx := range outputs {
		splitAsset := outputs[idx].Asset

		// The output that houses the root asset in case of a split has
		// a special field for the split asset. That asset is no longer
		// needed (and isn't committed to anywhere), but in order for it
		// to be validated externally, we still want to include it and
		// therefore also want to update it with the signed root asset.
		if outputs[idx].IsSplitRoot {
			splitAsset = outputs[idx].SplitAsset
		}

		splitCommitment := splitAsset.PrevWitnesses[0].SplitCommitment
		splitCommitment.RootAsset = *newAsset.Copy()
	}

	return nil
}

// CreateOutputCommitments creates the final set of TaroCommitments representing
// the asset send. The input TaroCommitment must be set.
func CreateOutputCommitments(inputTaroCommitment *commitment.TaroCommitment,
	vPkt *taropsbt.VPacket) ([]*commitment.TaroCommitment, error) {

	// We currently only support a single input.
	//
	// TODO(guggero): Support multiple inputs.
	if len(vPkt.Inputs) != 1 {
		return nil, fmt.Errorf("only a single input is currently " +
			"supported")
	}
	input := vPkt.Inputs[0]
	outputs := vPkt.Outputs
	inputAsset := input.Asset().Copy()

	// Remove the spent Asset from the AssetCommitment of the sender. Fail
	// if the input AssetCommitment or Asset were not in the input
	// TaroCommitment.
	inputTaroCommitmentCopy, err := inputTaroCommitment.Copy()
	if err != nil {
		return nil, err
	}

	inputCommitments := inputTaroCommitmentCopy.Commitments()
	inputCommitment, ok := inputCommitments[inputAsset.TaroCommitmentKey()]
	if !ok {
		return nil, ErrMissingAssetCommitment
	}

	// Just a sanity check that the asset we're spending really was in the
	// list of input assets.
	_, ok = inputCommitment.Assets()[inputAsset.AssetCommitmentKey()]
	if !ok {
		return nil, ErrMissingInputAsset
	}

	// Remove the input asset from the asset commitment tree.
	if err := inputCommitment.Delete(inputAsset); err != nil {
		return nil, err
	}

	outputCommitments := make([]*commitment.TaroCommitment, len(outputs))
	for idx := range outputs {
		vOut := outputs[idx]

		// The output that houses the split root will carry along the
		// existing Taro commitment of the sender.
		if vOut.IsSplitRoot {
			err := inputCommitment.Upsert(vOut.Asset)
			if err != nil {
				return nil, err
			}

			// Update the top-level TaroCommitment of the change
			// output (sender). This'll effectively commit to all
			// the new spend details.
			//
			// TODO(jhb): Add emptiness check for changeCommitment,
			// to prune the AssetCommitment entirely when possible.
			err = inputTaroCommitmentCopy.Upsert(inputCommitment)
			if err != nil {
				return nil, err
			}

			outputCommitments[idx] = inputTaroCommitmentCopy

			continue
		}

		// If the receiver of this output is receiving through an
		// address (non-interactive), we need to blank out the split
		// commitment proof, as the receiver doesn't know of this
		// information yet. The final commitment will be to a leaf
		// without the split commitment proof, that proof will be
		// delivered in the proof file as part of the non-interactive
		// send.
		committedAsset := vOut.Asset
		if !outputs[idx].Interactive {
			committedAsset = committedAsset.Copy()
			committedAsset.PrevWitnesses[0].SplitCommitment = nil
		}

		// This is a new output which only commits to a single asset
		// leaf.
		sendCommitment, err := commitment.NewAssetCommitment(
			committedAsset,
		)
		if err != nil {
			return nil, err
		}
		outputCommitments[idx], err = commitment.NewTaroCommitment(
			sendCommitment,
		)
		if err != nil {
			return nil, err
		}
	}

	return outputCommitments, nil
}

// interactiveFullValueSend returns true if there is exactly one output that
// spends the input fully and interactively.
func interactiveFullValueSend(input *taropsbt.VInput,
	outputs []*taropsbt.VOutput) bool {

	return len(outputs) == 1 &&
		outputs[0].Amount == input.Asset().Amount &&
		outputs[0].Interactive
}
