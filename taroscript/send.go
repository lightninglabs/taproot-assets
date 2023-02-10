package taroscript

import (
	"errors"
	"fmt"
	"math"
	"sort"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/commitment"
	"github.com/lightninglabs/taro/taropsbt"
	"golang.org/x/exp/slices"
)

const (
	// DummyAmtSats is the default amount of sats we'll use in Bitcoin
	// outputs embedding Taro commitments. This value just needs to be
	// greater than dust, and we assume that this value is updated to match
	// the input asset bearing UTXOs before finalizing the transfer TX.
	DummyAmtSats = btcutil.Amount(1_000)

	// SendConfTarget is the confirmation target we'll use to query for
	// a fee estimate.
	SendConfTarget = 6
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

	// ErrMissingInputAsset is an error returned when we attempt to spend
	// to a Taro address from an input that does not contain
	// the matching asset.
	ErrMissingInputAsset = errors.New(
		"send: Input does not contain requested asset",
	)

	// ErrInsufficientInputAsset is an error returned when we attempt
	// to spend to a Taro address from an input that contains
	// insufficient asset funds.
	ErrInsufficientInputAsset = errors.New(
		"send: Input asset value is insufficient",
	)

	// ErrInvalidOutputIndexes is an error returned when we attempt to spend
	// to Bitcoin output indexes that do not start at 0 or
	// are not continuous.
	ErrInvalidOutputIndexes = errors.New(
		"send: Output indexes not starting at 0 and continuous",
	)

	// ErrMissingSplitAsset is an error returned when we attempt to look up
	// a split asset in a map and the specified asset is not found.
	ErrMissingSplitAsset = errors.New(
		"send: split asset not found",
	)

	// ErrMissingAssetCommitment is an error returned when we attempt to
	// look up an Asset commitment in a map and the specified commitment
	// is not found.
	ErrMissingAssetCommitment = errors.New(
		"send: Asset commitment not found",
	)

	// ErrMissingTaroCommitment is an error returned when we attempt to
	// look up a Taro commitment in a map and the specified commitment
	// is not found.
	ErrMissingTaroCommitment = errors.New(
		"send: Taro commitment not found",
	)
)

// createDummyOutput creates a new Bitcoin transaction output that is later
// used to embed a Taro commitment.
func createDummyOutput() *wire.TxOut {
	// The dummy PkScript is the same size as an encoded P2TR output.
	newOutput := wire.TxOut{
		Value:    int64(DummyAmtSats),
		PkScript: make([]byte, 34),
	}
	return &newOutput
}

// FundingDescriptor describes the information that is needed to select and
// verify input assets in order to send to a specific recipient. It is a subset
// of the information contained in a Taro address.
type FundingDescriptor struct {
	// ID is the asset ID of the asset being transferred.
	ID asset.ID

	// GroupKey is the optional group key of the asset to transfer.
	GroupKey *btcec.PublicKey

	// Amount is the amount of the asset to transfer.
	Amount uint64
}

// TaroCommitmentKey is the key that maps to the root commitment for the asset
// group specified by a recipient descriptor.
func (r *FundingDescriptor) TaroCommitmentKey() [32]byte {
	return asset.TaroCommitmentKey(r.ID, r.GroupKey)
}

// DescribeRecipients extracts the recipient descriptors from a Taro PSBT.
func DescribeRecipients(vPkt *taropsbt.VPacket) (*FundingDescriptor,
	error) {

	if len(vPkt.Outputs) < 1 {
		return nil, fmt.Errorf("packet must have at least one output")
	}

	if len(vPkt.Inputs) != 1 {
		return nil, fmt.Errorf("only one input is currently supported")
	}

	desc := &FundingDescriptor{
		ID: vPkt.Inputs[0].PrevID.ID,
	}
	for idx := range vPkt.Outputs {
		desc.Amount += vPkt.Outputs[idx].Amount
	}

	return desc, nil
}

// IsValidInput verifies that the Taro commitment of the input contains an asset
// that could be spent to the given recipient.
func IsValidInput(input *commitment.TaroCommitment, desc *FundingDescriptor,
	inputScriptKey btcec.PublicKey) (*asset.Asset, bool, error) {

	fullValue := false

	// The top-level Taro tree must have a non-empty asset tree at the leaf
	// specified in the address.
	inputCommitments := input.Commitments()
	assetCommitment, ok := inputCommitments[desc.TaroCommitmentKey()]
	if !ok {
		return nil, fullValue, fmt.Errorf("input commitment does "+
			"not contain asset_id=%x: %w", desc.TaroCommitmentKey(),
			ErrMissingInputAsset)
	}

	// The asset tree must have a non-empty Asset at the location
	// specified by the sender's script key.
	assetCommitmentKey := asset.AssetCommitmentKey(
		desc.ID, &inputScriptKey, desc.GroupKey == nil,
	)
	inputAsset, _, err := assetCommitment.AssetProof(assetCommitmentKey)
	if err != nil {
		return nil, fullValue, err
	}

	if inputAsset == nil {
		return nil, fullValue, fmt.Errorf("input commitment does not "+
			"contain leaf with script_key=%x: %w",
			inputScriptKey.SerializeCompressed(),
			ErrMissingInputAsset)
	}

	// For Normal assets, we also check that the input asset amount is
	// at least as large as the amount specified in the address.
	// If the input amount is exactly the amount specified in the address,
	// the spend must use an unspendable zero-value root split.
	if inputAsset.Type == asset.Normal {
		if inputAsset.Amount < desc.Amount {
			return nil, fullValue, ErrInsufficientInputAsset
		}

		if inputAsset.Amount == desc.Amount {
			fullValue = true
		}
	} else {
		// Collectible assets always require the spending split to use an
		// unspendable zero-value root split.
		fullValue = true
	}

	return inputAsset, fullValue, nil
}

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

	// Sign the virtual transaction based on the input script information
	// (key spend or script spend).
	newWitness, err := CreateTaprootSignature(
		input, virtualTxCopy, inputIdx, signer,
	)
	if err != nil {
		return fmt.Errorf("error creating taproot signature: %w", err)
	}

	newAsset.PrevWitnesses[inputIdx].TxWitness = newWitness

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

// AreValidAnchorOutputIndexes checks a set of virtual outputs for the minimum
// number of outputs, and tests if the external indexes could be used for a
// Taro-only spend, i.e. a TX that does not need other outputs added to be
// valid.
func AreValidAnchorOutputIndexes(outputs []*taropsbt.VOutput) (bool, error) {
	// Sanity check the output indexes provided by the sender. There must be
	// at least one output.
	if len(outputs) < 1 {
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

	for i := range outputs {
		out := outputs[i]

		psbtOut := &spendPkt.Outputs[out.AnchorOutputIndex]
		psbtOut.TaprootInternalKey = schnorr.SerializePubKey(
			out.AnchorOutputInternalKey,
		)
		if out.AnchorOutputBip32Derivation != nil {
			psbtOut.Bip32Derivation = append(
				psbtOut.Bip32Derivation,
				out.AnchorOutputBip32Derivation,
			)
		}
		if out.AnchorOutputTaprootBip32Derivation != nil {
			psbtOut.TaprootBip32Derivation = append(
				psbtOut.TaprootBip32Derivation,
				out.AnchorOutputTaprootBip32Derivation,
			)
		}
	}

	return spendPkt, nil
}

// UpdateTaprootOutputKeys updates a PSBT with outputs embedding TaroCommitments
// involved in an asset send. The sender must attach the Bitcoin input holding
// the corresponding Taro input asset to this PSBT before finalizing the TX.
// Locators MUST be checked beforehand.
func UpdateTaprootOutputKeys(btcPacket *psbt.Packet, vPkt *taropsbt.VPacket,
	outputCommitments []*commitment.TaroCommitment) (
	map[uint32]*commitment.TaroCommitment, error) {

	// Add the commitment outputs to the BTC level PSBT now.
	mergedCommitments := make(map[uint32]*commitment.TaroCommitment)
	for idx := range vPkt.Outputs {
		vOut := vPkt.Outputs[idx]
		outputCommitment := outputCommitments[idx]

		// The commitment must be defined at this point.
		//
		// TODO(guggero): Merge multiple Taro level commitments that use
		// the same external output index.
		if outputCommitment == nil {
			return nil, ErrMissingTaroCommitment
		}
		mergedCommitments[vOut.AnchorOutputIndex] = outputCommitment

		// The external output index cannot be out of bounds of the
		// actual TX outputs. This should be checked earlier and is just
		// a final safeguard here.
		if vOut.AnchorOutputIndex >= uint32(len(btcPacket.Outputs)) {
			return nil, ErrInvalidOutputIndexes
		}

		btcOut := btcPacket.Outputs[vOut.AnchorOutputIndex]
		internalKey, err := schnorr.ParsePubKey(
			btcOut.TaprootInternalKey,
		)
		if err != nil {
			return nil, err
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
			return nil, err
		}

		btcTxOut := btcPacket.UnsignedTx.TxOut[vOut.AnchorOutputIndex]
		btcTxOut.PkScript = script
	}

	return mergedCommitments, nil
}

// interactiveFullValueSend returns true if there is exactly one output that
// spends the input fully and interactively.
func interactiveFullValueSend(input *taropsbt.VInput,
	outputs []*taropsbt.VOutput) bool {

	return len(outputs) == 1 &&
		outputs[0].Amount == input.Asset().Amount &&
		outputs[0].Interactive
}
