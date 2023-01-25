package taroscript

import (
	"errors"
	"fmt"
	"math"
	"sort"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/commitment"
	"github.com/lightninglabs/taro/taropsbt"
	"golang.org/x/exp/slices"
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

// SignVirtualTransaction updates the new asset (the root asset located at the
// change output in case of a non-interactive or partial amount send or the
// full asset in case of an interactive full amount send) by creating a
// signature over the asset transfer, verifying the transfer with the Taro VM,
// and attaching that signature to the new Asset.
func SignVirtualTransaction(input *taropsbt.VInput, outputs []*taropsbt.VOutput,
	signer Signer, validator TxValidator) error {

	prevAssets := commitment.InputSet{
		input.PrevID: input.Asset(),
	}
	newAsset := outputs[1].Asset
	if input.IsSplit {
		newAsset = outputs[0].Asset
	}

	// Create a Taro virtual transaction representing the asset transfer.
	virtualTx, _, err := VirtualTx(newAsset, prevAssets)
	if err != nil {
		return err
	}

	// For each input asset leaf, we need to produce a witness. Update the
	// input of the virtual TX, generate a witness, and attach it to the
	// copy of the new Asset.
	//
	// TODO(guggero): I think this is wrong... We shouldn't look at
	// PrevWitnesses of the single asset we spend but instead have multiple
	// inputs if we want to spend multiple coins of the same asset?
	prevWitnessCount := len(newAsset.PrevWitnesses)
	for idx := 0; idx < prevWitnessCount; idx++ {
		prevAssetID := newAsset.PrevWitnesses[idx].PrevID
		prevAsset := prevAssets[*prevAssetID]
		virtualTxCopy := VirtualTxWithInput(
			virtualTx, prevAsset, uint32(idx), nil,
		)

		newWitness, err := SignTaprootKeySpend(
			*input.Asset().ScriptKey.RawKey.PubKey, virtualTxCopy,
			prevAsset, 0, txscript.SigHashDefault, signer,
		)
		if err != nil {
			return err
		}

		newAsset.PrevWitnesses[idx].TxWitness = *newWitness
	}

	// Create an instance of the Taro VM and validate the transfer.
	verifySpend := func(splitAssets []*commitment.SplitAsset) error {
		newAssetCopy := newAsset.Copy()
		err := validator.Execute(newAssetCopy, splitAssets, prevAssets)
		if err != nil {
			return err
		}
		return nil
	}

	// If the transfer contains no asset splits, we only need to validate
	// the new asset with its witness attached.
	if !input.IsSplit {
		if err := verifySpend(nil); err != nil {
			return err
		}

		return nil
	}

	// If the transfer includes an asset split, we have to validate each
	// split asset to ensure that our new Asset is committing to
	// a valid SplitCommitment.
	splitAssets := make([]*commitment.SplitAsset, 0, len(outputs)-1)
	for idx := range outputs {
		if outputs[idx].IsChange || outputs[idx].Interactive {
			continue
		}

		splitAssets = append(splitAssets, &commitment.SplitAsset{
			Asset:       *outputs[idx].Asset,
			OutputIndex: outputs[idx].AnchorOutputIndex,
		})
	}
	if err := verifySpend(splitAssets); err != nil {
		return err
	}

	// Update each split asset to store the root asset with the witness
	// attached, so the receiver can verify inclusion of the root asset.
	for idx := range outputs {
		if outputs[idx].IsChange || outputs[idx].Interactive {
			continue
		}

		splitAsset := outputs[idx].Asset
		splitCommitment := splitAsset.PrevWitnesses[0].SplitCommitment
		splitCommitment.RootAsset = *newAsset.Copy()
	}

	return nil
}

// CreateOutputCommitments creates the final set of TaroCommitments representing
// the asset send. The input TaroCommitment must be set.
func CreateOutputCommitments(inputCommitment *commitment.TaroCommitment,
	input *taropsbt.VInput,
	outputs []*taropsbt.VOutput) ([]*commitment.TaroCommitment, error) {

	inputAsset := input.Asset()

	// Remove the spent Asset from the AssetCommitment of the sender. Fail
	// if the input AssetCommitment or Asset were not in the input
	// TaroCommitment.
	changeTaroCommitment, err := inputCommitment.Copy()
	if err != nil {
		return nil, err
	}

	inputCommitments := changeTaroCommitment.Commitments()
	changeCommitment, ok := inputCommitments[inputAsset.TaroCommitmentKey()]
	if !ok {
		return nil, ErrMissingAssetCommitment
	}

	// Just a sanity check that the asset we're spending really was in the
	// list of input assets.
	_, ok = changeCommitment.Assets()[inputAsset.AssetCommitmentKey()]
	if !ok {
		return nil, ErrMissingInputAsset
	}

	// Remove the input asset from the asset commitment tree.
	if err := changeCommitment.Update(inputAsset, true); err != nil {
		return nil, err
	}

	// If there was a split, we need to include the root asset in the change
	// commitment, which is stored in the change output.
	if input.IsSplit {
		err := changeCommitment.Update(outputs[0].Asset, false)
		if err != nil {
			return nil, err
		}
	}

	outputCommitments := make([]*commitment.TaroCommitment, len(outputs))
	for idx := range outputs {
		vOut := outputs[idx]

		// The change output was already committed to above.
		if vOut.IsChange {
			// Update the top-level TaroCommitment of the change
			// output (sender). This'll effectively commit to all
			// the new spend details.
			//
			// TODO(jhb): Add emptiness check for changeCommitment,
			// to prune the AssetCommitment entirely when possible.
			err = changeTaroCommitment.Update(
				changeCommitment, false,
			)
			if err != nil {
				return nil, err
			}

			outputCommitments[idx] = changeTaroCommitment

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

// AreValidAnchorOutputIndexes checks a set of virtual outputs for the minimum
// number of outputs, and tests if the external indexes could be used for a
// Taro-only spend, i.e. a TX that does not need other outputs added to be
// valid.
func AreValidAnchorOutputIndexes(outputs []*taropsbt.VOutput) (bool, error) {
	// Sanity check the output indexes provided by the sender. There must be
	// at least two indexes; one for the receiver, and one for the change
	// commitment for the sender.
	if len(outputs) < 2 {
		return false, ErrInvalidOutputIndexes
	}

	// If the indexes start from 0 and form a continuous range, then the
	// resulting TX would be valid without any changes (Taro-only spend).
	taroOnlySpend := true
	sortedCopy := slices.Clone(outputs)
	sort.Slice(sortedCopy, func(i, j int) bool {
		return sortedCopy[i].AnchorOutputIndex <
			sortedCopy[j].AnchorOutputIndex
	})
	for i := 0; i < len(sortedCopy); i++ {
		if sortedCopy[i].AnchorOutputIndex != uint32(i) {
			taroOnlySpend = false
			break
		}
	}

	return taroOnlySpend, nil
}

// CreateAnchorTx creates a template BTC anchor TX with dummy outputs.
func CreateAnchorTx(outputs []*taropsbt.VOutput) (*psbt.Packet, error) {
	// Check if our outputs are valid, and if we will need to add extra
	// outputs to fill in the gaps between outputs.
	taroOnlySpend, err := AreValidAnchorOutputIndexes(outputs)
	if err != nil {
		return nil, err
	}

	// Calculate the number of outputs we need for our template TX.
	maxOutputIndex := uint32(len(outputs))

	// If there is a gap in our outputs, we need to find the
	// largest output index to properly size our template TX.
	if !taroOnlySpend {
		maxOutputIndex = 0
		for _, out := range outputs {
			if out.AnchorOutputIndex > maxOutputIndex {
				maxOutputIndex = out.AnchorOutputIndex
			}
		}

		// Output indexes are 0-indexed, so we need to increment this
		// to account for the 0th output.
		maxOutputIndex++
	}

	txTemplate := wire.NewMsgTx(2)
	for i := uint32(0); i < maxOutputIndex; i++ {
		txTemplate.AddTxOut(createDummyOutput())
	}

	spendPkt, err := psbt.NewFromUnsignedTx(txTemplate)
	if err != nil {
		return nil, fmt.Errorf("unable to make psbt packet: %w", err)
	}

	return spendPkt, nil
}

// UpdateTaprootOutputKeys updates a PSBT with outputs embedding TaroCommitments
// involved in an asset send. The sender must attach the Bitcoin input holding
// the corresponding Taro input asset to this PSBT before finalizing the TX.
// Locators MUST be checked beforehand.
func UpdateTaprootOutputKeys(btcPacket *psbt.Packet,
	outputs []*taropsbt.VOutput,
	outputCommitments []*commitment.TaroCommitment) error {

	// Add the commitment outputs to the BTC level PSBT now.
	for idx := range outputs {
		vOut := outputs[idx]
		outputCommitment := outputCommitments[idx]

		// The external output index cannot be out of bounds of the
		// actual TX outputs. This should be checked earlier and is just
		// a final safeguard here.
		if vOut.AnchorOutputIndex >= uint32(len(btcPacket.Outputs)) {
			return ErrInvalidOutputIndexes
		}

		btcOut := btcPacket.Outputs[vOut.AnchorOutputIndex]
		internalKey, err := schnorr.ParsePubKey(
			btcOut.TaprootInternalKey,
		)
		if err != nil {
			return err
		}

		// The commitment must be defined at this point.
		//
		// TODO(guggero): Merge multiple Taro level commitments that use
		// the same external output index.
		if outputCommitment == nil {
			return ErrMissingTaroCommitment
		}

		// Create the scripts corresponding to the receiver's
		// TaroCommitment.
		//
		// NOTE: We currently default to the Taro commitment having no
		// sibling in the Tapscript tree. Any sibling would need to be
		// checked to verify that it is not also a Taro commitment.
		script, err := PayToAddrScript(
			*internalKey, nil, *outputCommitment,
		)
		if err != nil {
			return err
		}

		btcTxOut := btcPacket.UnsignedTx.TxOut[vOut.AnchorOutputIndex]
		btcTxOut.PkScript = script
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
