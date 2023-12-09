package tapscript

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/bits"
	"reflect"
	"sort"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btclog"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"golang.org/x/exp/slices"
)

const (
	// DummyAmtSats is the default amount of sats we'll use in Bitcoin
	// outputs embedding Taproot Asset commitments. This value just needs to
	// be greater than dust, and we assume that this value is updated to
	// match the input asset bearing UTXOs before finalizing the transfer
	// TX.
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
	// to a Taproot Asset address from an input that does not contain
	// the matching asset.
	ErrMissingInputAsset = errors.New(
		"send: Input does not contain requested asset",
	)

	// ErrInsufficientInputAssets is an error returned when we attempt
	// to spend to a Taproot Asset address from a set of inputs which
	// contain an insufficient amount of total funds.
	ErrInsufficientInputAssets = errors.New(
		"send: Input assets total funds is insufficient",
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

	// ErrMissingTapCommitment is an error returned when we attempt to look
	// up a Taproot Asset commitment in a map and the specified commitment
	// is not found.
	ErrMissingTapCommitment = errors.New(
		"send: Taproot Asset commitment not found",
	)

	// ErrInvalidAnchorInfo is an error returned when the anchor output
	// information on a virtual transaction output is invalid.
	ErrInvalidAnchorInfo = errors.New(
		"send: invalid anchor output info",
	)
)

var (
	// GenesisDummyScript is a dummy script that we'll use to fund the
	// initial PSBT packet that'll create initial set of assets. It's the
	// same size as a encoded P2TR output and has a valid P2TR prefix.
	GenesisDummyScript = append(
		[]byte{txscript.OP_1, 0x20}, bytes.Repeat([]byte{0x00}, 32)...,
	)
)

// createDummyOutput creates a new Bitcoin transaction output that is later
// used to embed a Taproot Asset commitment.
func createDummyOutput() *wire.TxOut {
	// The dummy PkScript is the same size as an encoded P2TR output and has
	// a valid P2TR prefix.
	newOutput := wire.TxOut{
		Value:    int64(DummyAmtSats),
		PkScript: GenesisDummyScript,
	}
	return &newOutput
}

// AssetGroupQuerier is an interface that allows us to query for asset groups by
// asset ID.
type AssetGroupQuerier interface {
	// QueryAssetGroup attempts to locate the asset group information
	// (genesis + group key) associated with a given asset.
	QueryAssetGroup(context.Context, asset.ID) (*asset.AssetGroup, error)
}

// FundingDescriptor describes the information that is needed to select and
// verify input assets in order to send to a specific recipient. It is a subset
// of the information contained in a Taproot Asset address.
type FundingDescriptor struct {
	// ID is the asset ID of the asset being transferred.
	ID asset.ID

	// GroupKey is the optional group key of the asset to transfer.
	GroupKey *btcec.PublicKey

	// Amount is the amount of the asset to transfer.
	Amount uint64
}

// TapCommitmentKey is the key that maps to the root commitment for the asset
// group specified by a recipient descriptor.
func (r *FundingDescriptor) TapCommitmentKey() [32]byte {
	return asset.TapCommitmentKey(r.ID, r.GroupKey)
}

// DescribeRecipients extracts the recipient descriptors from a Taproot Asset
// PSBT.
func DescribeRecipients(ctx context.Context, vPkt *tappsbt.VPacket,
	groupQuerier AssetGroupQuerier) (*FundingDescriptor, error) {

	if len(vPkt.Outputs) < 1 {
		return nil, fmt.Errorf("packet must have at least one output")
	}

	if len(vPkt.Inputs) != 1 {
		return nil, fmt.Errorf("only one input is currently supported")
	}
	firstInput := vPkt.Inputs[0]

	var groupPubKey *btcec.PublicKey
	groupKey, err := groupQuerier.QueryAssetGroup(ctx, firstInput.PrevID.ID)
	switch {
	case err == nil && groupKey.GroupKey != nil:
		groupPubKey = &groupKey.GroupPubKey

	case err != nil:
		return nil, fmt.Errorf("unable to query asset group: %v", err)
	}

	desc := &FundingDescriptor{
		ID:       firstInput.PrevID.ID,
		GroupKey: groupPubKey,
	}
	for idx := range vPkt.Outputs {
		desc.Amount += vPkt.Outputs[idx].Amount
	}

	return desc, nil
}

// DescribeAddrs extracts the recipient descriptors from a list of Taproot Asset
// addresses.
func DescribeAddrs(addrs []*address.Tap) (*FundingDescriptor, error) {
	if len(addrs) < 1 {
		return nil, fmt.Errorf("at least one address must be specified")
	}

	firstAddr := addrs[0]
	desc := &FundingDescriptor{
		ID:       firstAddr.AssetID,
		GroupKey: firstAddr.GroupKey,
	}
	for idx := range addrs {
		desc.Amount += addrs[idx].Amount
	}

	return desc, nil
}

// AssetFromTapCommitment uses a script key to extract an asset from a given
// Taproot Asset commitment.
func AssetFromTapCommitment(tapCommitment *commitment.TapCommitment,
	desc *FundingDescriptor, inputScriptKey btcec.PublicKey) (*asset.Asset,
	error) {

	// The top-level Taproot Asset tree must have a non-empty asset tree at
	// the leaf specified by the funding descriptor's asset (group) specific
	// commitment locator.
	assetCommitments := tapCommitment.Commitments()
	assetCommitment, ok := assetCommitments[desc.TapCommitmentKey()]
	if !ok {
		return nil, fmt.Errorf("input commitment does "+
			"not contain asset_id=%x: %w", desc.TapCommitmentKey(),
			ErrMissingInputAsset)
	}

	// The asset tree must have a non-empty Asset at the location
	// specified by the sender's script key.
	assetCommitmentKey := asset.AssetCommitmentKey(
		desc.ID, &inputScriptKey, desc.GroupKey == nil,
	)
	inputAsset, ok := assetCommitment.Asset(assetCommitmentKey)
	if !ok {
		return nil, fmt.Errorf("input commitment does not "+
			"contain leaf with script_key=%x: %w",
			inputScriptKey.SerializeCompressed(),
			ErrMissingInputAsset)
	}

	return inputAsset, nil
}

// ValidateInputs validates a set of inputs against a funding request. It
// returns true if the inputs would be spent fully, otherwise false.
func ValidateInputs(inputCommitments tappsbt.InputCommitments,
	inputsScriptKeys []*btcec.PublicKey, expectedAssetType asset.Type,
	desc *FundingDescriptor) (bool, error) {

	// Extract the input assets from the input commitments.
	inputAssets := make([]*asset.Asset, len(inputsScriptKeys))
	for inputIndex := range inputCommitments {
		tapCommitment := inputCommitments[inputIndex]
		senderScriptKey := inputsScriptKeys[inputIndex]

		// Gain the asset that we'll use as an input and in the process
		// validate the selected input and commitment.
		inputAsset, err := AssetFromTapCommitment(
			tapCommitment, desc, *senderScriptKey,
		)
		if err != nil {
			return false, err
		}

		// Ensure input asset has the expected type.
		if inputAsset.Type != expectedAssetType {
			return false, fmt.Errorf("unexpected input asset type")
		}

		inputAssets[inputIndex] = inputAsset
	}

	// Validate total amount of input assets and determine full value spend
	// status.
	var isFullValueSpend bool
	switch expectedAssetType {
	case asset.Normal:
		// Sum the total amount of the input assets.
		var totalInputsAmount uint64
		for _, inputAsset := range inputAssets {
			totalInputsAmount += inputAsset.Amount
		}

		// Ensure that the input assets are sufficient to cover the amount
		// being sent.
		if totalInputsAmount < desc.Amount {
			return false, ErrInsufficientInputAssets
		}

		// Check if the input assets are fully spent.
		isFullValueSpend = totalInputsAmount == desc.Amount

	case asset.Collectible:
		isFullValueSpend = true
	}

	return isFullValueSpend, nil
}

// PrepareOutputAssets prepares the assets of the given outputs depending on
// the amounts set on the transaction. If a split is necessary (non-interactive
// or partial amount send) it computes a split commitment with the given inputs
// and spend information. The inputs MUST be checked as valid beforehand and the
// change output is expected to be declared as such (and be at index 0).
func PrepareOutputAssets(ctx context.Context, vPkt *tappsbt.VPacket) error {
	inputs := vPkt.Inputs
	outputs := vPkt.Outputs

	if len(inputs) == 0 {
		return fmt.Errorf("no inputs specified in virtual packet")
	}

	var (
		totalInputAmount uint64

		// Inspect first asset to determine all input asset IDs.
		//
		// TODO(ffranr): Add support for multiple different input asset
		// IDs.
		assetID = inputs[0].Asset().ID()

		// Inspect first asset to determine all input asset types.
		inputAssetType = inputs[0].Asset().Type

		splitCommitmentInputs = make(
			[]commitment.SplitCommitmentInput, len(inputs),
		)
	)
	for idx := range inputs {
		vIn := inputs[idx]
		inputAsset := vIn.Asset()

		// This should be caught way earlier but just to make sure that
		// we never overflow when converting the input amount to int64
		// we check this again.
		if inputAsset.Amount > math.MaxInt64 {
			return fmt.Errorf("amount int64 overflow")
		}

		// Calculate sum total input amounts with overflow check.
		newTotalInputAmount, carry := bits.Add64(
			totalInputAmount, inputAsset.Amount, 0,
		)
		overflow := carry != 0
		if overflow {
			return fmt.Errorf("total input amount uint64 overflow")
		}
		totalInputAmount = newTotalInputAmount

		// Gather split commitment inputs.
		splitCommitmentInputs[idx] = commitment.SplitCommitmentInput{
			Asset:    inputAsset,
			OutPoint: vIn.PrevID.OutPoint,
		}

		// TODO(ffranr): Right now, we only support a single input or
		// multiple inputs with the same asset ID. We need to support
		// multiple input assets from the same group but do not
		// necessarily share the same asset ID.
		if idx > 0 && inputs[idx].Asset().ID() != assetID {
			return fmt.Errorf("multiple input assets " +
				"must have the same asset ID")
		}
	}

	// Do some general sanity checks on the outputs, these should be
	// independent of the number of outputs.
	for idx := range outputs {
		vOut := outputs[idx]

		// Depending on the output type, an output can be interactive or
		// not.
		if vOut.Interactive && !vOut.Type.CanBeInteractive() {
			return fmt.Errorf("output %d is interactive but "+
				"output type %v cannot be interactive", idx,
				vOut.Type)
		}

		// This method returns an error if the script key's public key
		// isn't set, which should be the case right now.
		isUnSpendable, err := vOut.ScriptKey.IsUnSpendable()
		if err != nil {
			return fmt.Errorf("output %d has invalid script key: "+
				"%w", idx, err)
		}

		switch {
		// Only the split root can be un-spendable.
		case !vOut.Type.IsSplitRoot() && isUnSpendable:
			return commitment.ErrInvalidScriptKey

		// Only the split root can have a zero amount.
		case !vOut.Type.IsSplitRoot() && vOut.Amount == 0:
			return commitment.ErrZeroSplitAmount

		// Interactive outputs can't be un-spendable, since there is no
		// need for a tombstone output and burns work in a different
		// way, unless they are carrying the passive assets.
		case vOut.Interactive && isUnSpendable &&
			!vOut.Type.CanCarryPassive():

			return commitment.ErrInvalidScriptKey

		// Interactive outputs can't have a zero amount, unless they
		// are carrying the passive assets.
		case vOut.Interactive && vOut.Amount == 0 &&
			!vOut.Type.CanCarryPassive():

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

		if vOut.Type.IsSplitRoot() {
			return fmt.Errorf("single output cannot be split root")
		}
		if !vOut.Interactive {
			return fmt.Errorf("single output must be interactive")
		}

		if vOut.Amount != totalInputAmount {
			return ErrInvalidSplitAmounts
		}

	// A two output transaction must have the change at index 0 if it is a
	// non-interactive send.
	case len(outputs) == 2:
		// A collectible cannot be split into individual pieces. So for
		// a two output transaction to be a valid collectible send, it
		// needs to be a non-interactive send where we expect there to
		// be a tombstone output for the split root.
		if inputAssetType == asset.Collectible {
			if !vPkt.HasSplitRootOutput() {
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

			// There should only be a tombstone output in an
			// interactive flow if we need to transport passive
			// assets. Otherwise, for an interactive send we don't
			// need a tombstone output and this wouldn't be a two
			// output collectible send.
			if !rootOut.Type.CanCarryPassive() &&
				recipientOut.Interactive {

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

	var residualAmount = totalInputAmount
	for idx := range outputs {
		residualAmount -= outputs[idx].Amount
	}

	// We should now have exactly zero value left over after splitting.
	if residualAmount != 0 {
		return ErrInvalidSplitAmounts
	}

	// If we have an interactive full value send, we don't need a tomb stone
	// at all.
	recipientIndex, isFullValueInteractiveSend := interactiveFullValueSend(
		totalInputAmount, outputs,
	)

	if isFullValueInteractiveSend {
		if len(inputs) != 1 {
			return fmt.Errorf("full value interactive send " +
				"must have exactly one input")
		}

		// TODO(ffranr): Add support for interactive full value multiple
		// input spend.
		input := inputs[0]
		vOut := outputs[recipientIndex]

		// We'll now create a new copy of the old asset, swapping out
		// the script key. We blank out the tweaked key information as
		// this is now an external asset.
		vOut.Asset = input.Asset().Copy()
		vOut.Asset.ScriptKey = vOut.ScriptKey

		// Record the PrevID of the input asset in a Witness for the new
		// asset. This Witness still needs a valid signature for the new
		// asset to be valid.
		vOut.Asset.PrevWitnesses = []asset.Witness{
			{
				PrevID:          &input.PrevID,
				TxWitness:       nil,
				SplitCommitment: nil,
			},
		}

		// Adjust the version for the requested send type.
		vOut.Asset.Version = vOut.AssetVersion

		// We are done, since we don't need to create a split
		// commitment.
		return nil
	}

	// We need to determine the root locator and the rest of the split
	// locators now.
	var (
		rootLocator   *commitment.SplitLocator
		splitLocators []*commitment.SplitLocator
	)
	for idx := range outputs {
		vOut := outputs[idx]

		locator := outputs[idx].SplitLocator(assetID)
		if vOut.Type.IsSplitRoot() {
			rootLocator = &locator
			continue
		}

		splitLocators = append(splitLocators, &locator)
	}

	splitCommitment, err := commitment.NewSplitCommitment(
		ctx, splitCommitmentInputs, rootLocator, splitLocators...,
	)
	if err != nil {
		return err
	}

	// Assign each of the split assets to their respective outputs.
	for idx := range outputs {
		vOut := outputs[idx]
		locator := outputs[idx].SplitLocator(assetID)

		splitAsset, ok := splitCommitment.SplitAssets[locator]
		if !ok {
			return fmt.Errorf("invalid split, asset for locator "+
				"%v not found", locator)
		}

		// The change output should be marked as the split root, even if
		// it's a zero value (tombstone) split output for the sender.
		if vOut.Type.IsSplitRoot() {
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
// signature over the asset transfer, verifying the transfer with the Taproot
// Asset VM, and attaching that signature to the new Asset.
func SignVirtualTransaction(vPkt *tappsbt.VPacket, signer Signer,
	validator TxValidator) error {

	inputs := vPkt.Inputs
	outputs := vPkt.Outputs

	// If this is a split transfer, it means that the asset to be signed is
	// the root asset, which is located at the change output.
	isSplit, err := vPkt.HasSplitCommitment()
	if err != nil {
		return err
	}

	// Identify new output asset. For splits, the new asset that receives
	// the signature is the one with the split root set to true.
	newAsset := outputs[0].Asset
	if isSplit {
		splitOut, err := vPkt.SplitRootOutput()
		if err != nil {
			return fmt.Errorf("no split root output found for "+
				"split transaction: %w", err)
		}
		newAsset = splitOut.Asset
	}

	// Construct input set from all input assets.
	prevAssets := make(commitment.InputSet, len(inputs))
	for idx := range vPkt.Inputs {
		input := vPkt.Inputs[idx]
		prevAssets[input.PrevID] = input.Asset()
	}

	// Create a Taproot Asset virtual transaction representing the asset
	// transfer.
	virtualTx, _, err := VirtualTx(newAsset, prevAssets)
	if err != nil {
		return err
	}

	for idx := range inputs {
		input := inputs[idx]

		// For each input asset leaf, we need to produce a witness.
		// Update the input of the virtual TX, generate a witness, and
		// attach it to the copy of the new Asset.
		virtualTxCopy := virtualTx.Copy()
		inputSpecificVirtualTx := asset.VirtualTxWithInput(
			virtualTxCopy, input.Asset(), uint32(idx), nil,
		)

		// Sign the virtual transaction based on the input script
		// information (key spend or script spend).
		newWitness, err := CreateTaprootSignature(
			input, inputSpecificVirtualTx, 0, signer,
		)
		if err != nil {
			return fmt.Errorf("error creating taproot "+
				"signature: %w", err)
		}

		newAsset.PrevWitnesses[idx].TxWitness = newWitness
	}

	// Create an instance of the Taproot Asset VM and validate the transfer.
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
		if outputs[idx].Type.IsSplitRoot() {
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
		if outputs[idx].Type.IsSplitRoot() {
			splitAsset = outputs[idx].SplitAsset
		}

		splitCommitment := splitAsset.PrevWitnesses[0].SplitCommitment
		splitCommitment.RootAsset = *newAsset.Copy()
	}

	return nil
}

// CreateOutputCommitments creates the final set of Taproot asset commitments
// representing the asset send.
func CreateOutputCommitments(inputTapCommitments tappsbt.InputCommitments,
	vPkt *tappsbt.VPacket,
	passiveAssets []*tappsbt.VPacket) ([]*commitment.TapCommitment,
	error) {

	inputs := vPkt.Inputs
	outputs := vPkt.Outputs

	// TODO(ffranr): Support multiple inputs with different asset IDs.
	// Currently, every input asset must have the same asset ID. Ensure
	// that's the case.
	assetsTapCommitmentKey := inputs[0].Asset().TapCommitmentKey()
	for idx := range inputs {
		inputAsset := inputs[idx].Asset()
		if inputAsset.TapCommitmentKey() != assetsTapCommitmentKey {
			return nil, fmt.Errorf("inputs must have the same " +
				"asset ID")
		}

		// For multi input, assert asset is not part of a group.
		firstAssetGen := inputs[0].Asset().Genesis
		assetInGroup := firstAssetGen.ID() != assetsTapCommitmentKey
		if len(inputs) > 1 && assetInGroup {
			return nil, fmt.Errorf("multi input spend may not " +
				"include input from asset group")
		}
	}

	// Merge all input Taproot Asset commitments into a single commitment.
	//
	// TODO(ffranr): Use `fn.ForEach` and `inputTapCommitments[1:]`.
	firstCommitment := inputTapCommitments[0]
	for idx := range inputTapCommitments {
		if idx == 0 {
			continue
		}
		err := firstCommitment.Merge(inputTapCommitments[idx])
		if err != nil {
			return nil, fmt.Errorf("failed to merge input Taproot "+
				"Asset commitments: %w", err)
		}
	}

	// We require all outputs that reference the same anchor output to be
	// identical, otherwise some assumptions in the code below don't hold.
	if err := assertAnchorsEqual(vPkt); err != nil {
		return nil, err
	}

	// Remove the spent Asset from the AssetCommitment of the sender. Fail
	// if the input AssetCommitment or Asset were not in the input
	// TapCommitment.
	inputTapCommitment, err := firstCommitment.Copy()
	if err != nil {
		return nil, err
	}

	assetCommitments := inputTapCommitment.Commitments()
	assetCommitment, ok := assetCommitments[assetsTapCommitmentKey]
	if !ok {
		return nil, ErrMissingAssetCommitment
	}

	for idx := range inputs {
		input := inputs[idx]
		inputAsset := input.Asset()

		// Just a sanity check that the asset we're spending really was
		// in the list of input assets.
		_, ok = assetCommitment.Asset(inputAsset.AssetCommitmentKey())
		if !ok {
			return nil, ErrMissingInputAsset
		}

		// Remove all input assets from the asset commitment tree.
		err = assetCommitment.Delete(inputAsset)
		if err != nil {
			return nil, err
		}
	}

	outputCommitments := make([]*commitment.TapCommitment, len(outputs))
	for idx := range outputs {
		vOut := outputs[idx]

		// The output that houses the split root will carry along the
		// existing Taproot Asset commitment of the sender (also known
		// as passive assets). There can be passive assets without a
		// split root, in case it's a full value interactive send or
		// burn.
		if vOut.Type.IsSplitRoot() || vOut.Type.CanCarryPassive() {
			// In the interactive case we might have a full value
			// send without an actual split root output but just the
			// anchor output for the passive assets. We can skip
			// that as we'll create the commitment for the passive
			// assets later.
			switch {
			// The asset is present, just commit it to the input
			// asset commitment.
			case vOut.Asset != nil:
				err = assetCommitment.Upsert(vOut.Asset)
				if err != nil {
					return nil, err
				}

			// There is no asset, but we have an interactive output
			// that has IsSplitRoot set to true, so it means we need
			// to anchor the passive assets to this output, which
			// we'll do below.
			case vOut.Asset == nil && vOut.Interactive:
				// Continue below.

			default:
				return nil, fmt.Errorf("non-interactive "+
					"output %d is missing asset", idx)
			}

			// Update the top-level TapCommitment of the change
			// output (sender). This'll effectively commit to all
			// the new spend details. If there is nothing contained
			// in the input commitment, it is removed from the
			// Taproot Asset tree automatically.
			err = inputTapCommitment.Upsert(assetCommitment)
			if err != nil {
				return nil, err
			}

			log.Tracef("Adding %d passive assets to output with %d "+
				"current assets", len(passiveAssets),
				len(inputTapCommitment.CommittedAssets()))

			// Anchor passive assets to this output, since it's the
			// split root (=change output).
			err = AnchorPassiveAssets(
				passiveAssets, inputTapCommitment,
			)
			if err != nil {
				return nil, fmt.Errorf("unable to anchor "+
					"passive assets: %w", err)
			}

			// Add some trace logging for easier debugging of what
			// goes into the output commitment (we'll do the same
			// for the input commitment).
			LogCommitment(
				"Output", idx, inputTapCommitment,
				vOut.AnchorOutputInternalKey, nil, nil,
			)

			outputCommitments[idx] = inputTapCommitment

			continue
		}

		// Because the receiver of this output might be receiving
		// through an address (non-interactive), we need to blank out
		// the split commitment proof, as the receiver doesn't know of
		// this information yet. The final commitment will be to a leaf
		// without the split commitment proof, that proof will be
		// delivered in the proof file as part of the non-interactive
		// send. We do the same even for interactive sends to not need
		// to distinguish between the two cases in the proof file
		// itself.
		committedAsset := vOut.Asset.Copy()
		committedAsset.PrevWitnesses[0].SplitCommitment = nil

		// This is a new output which only commits to a single asset
		// leaf.
		sendCommitment, err := commitment.NewAssetCommitment(
			committedAsset,
		)
		if err != nil {
			return nil, err
		}
		outputCommitments[idx], err = commitment.NewTapCommitment(
			sendCommitment,
		)
		if err != nil {
			return nil, err
		}

		// Add some trace logging for easier debugging of what goes into
		// the output commitment (we'll do the same for the input
		// commitment).
		LogCommitment(
			"Output", idx, outputCommitments[idx],
			vOut.AnchorOutputInternalKey, nil, nil,
		)
	}

	return outputCommitments, nil
}

// AnchorPassiveAssets anchors the passive assets within the given Taproot Asset
// commitment.
func AnchorPassiveAssets(passiveAssets []*tappsbt.VPacket,
	tapCommitment *commitment.TapCommitment) error {

	for idx := range passiveAssets {
		passiveAsset := passiveAssets[idx].Outputs[0].Asset
		var err error

		// Ensure that a commitment for this asset exists.
		assetCommitment, ok := tapCommitment.Commitment(passiveAsset)
		if ok {
			err = assetCommitment.Upsert(passiveAsset)
			if err != nil {
				return fmt.Errorf("unable to upsert passive "+
					"asset into asset commitment: %w", err)
			}
		} else {
			// If no commitment exists yet, create one and insert
			// the passive asset into it.
			assetCommitment, err = commitment.NewAssetCommitment(
				passiveAsset,
			)
			if err != nil {
				return fmt.Errorf("unable to create "+
					"commitment for passive asset: %w", err)
			}
		}

		err = tapCommitment.Upsert(assetCommitment)
		if err != nil {
			return fmt.Errorf("unable to upsert passive "+
				"asset commitment into Taproot Asset "+
				"commitment: %w", err)
		}
	}

	return nil
}

// AreValidAnchorOutputIndexes checks a set of virtual outputs for the minimum
// number of outputs, and tests if the external indexes could be used for a
// Taproot Asset only spend, i.e. a TX that does not need other outputs added to
// be valid.
func AreValidAnchorOutputIndexes(outputs []*tappsbt.VOutput) (bool, error) {
	// Sanity check the output indexes provided by the sender. There must be
	// at least one output.
	if len(outputs) < 1 {
		return false, ErrInvalidOutputIndexes
	}

	// If the indexes start from 0 and form a continuous range, then the
	// resulting TX would be valid without any changes (Taproot Asset only
	// spend).
	assetOnlySpend := true
	sortedCopy := slices.Clone(outputs)
	sort.Slice(sortedCopy, func(i, j int) bool {
		return sortedCopy[i].AnchorOutputIndex <
			sortedCopy[j].AnchorOutputIndex
	})
	for i := 0; i < len(sortedCopy); i++ {
		if sortedCopy[i].AnchorOutputIndex != uint32(i) {
			assetOnlySpend = false
			break
		}
	}

	return assetOnlySpend, nil
}

// CreateAnchorTx creates a template BTC anchor TX with dummy outputs.
func CreateAnchorTx(outputs []*tappsbt.VOutput) (*psbt.Packet, error) {
	// Check if our outputs are valid, and if we will need to add extra
	// outputs to fill in the gaps between outputs.
	assetOnlySpend, err := AreValidAnchorOutputIndexes(outputs)
	if err != nil {
		return nil, err
	}

	// Calculate the number of outputs we need for our template TX.
	maxOutputIndex := uint32(len(outputs))

	// If there is a gap in our outputs, we need to find the
	// largest output index to properly size our template TX.
	if !assetOnlySpend {
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

	// With the dummy packet created, we'll walk through of vOutputs to set
	// the taproot internal key for each of the outputs.
	for i := range outputs {
		vOut := outputs[i]

		out := &spendPkt.Outputs[vOut.AnchorOutputIndex]
		out.TaprootInternalKey = schnorr.SerializePubKey(
			vOut.AnchorOutputInternalKey,
		)

		for idx := range vOut.AnchorOutputBip32Derivation {
			out.Bip32Derivation = tappsbt.AddBip32Derivation(
				out.Bip32Derivation,
				vOut.AnchorOutputBip32Derivation[idx],
			)
		}
		for idx := range vOut.AnchorOutputTaprootBip32Derivation {
			out.TaprootBip32Derivation = tappsbt.AddTaprootBip32Derivation(
				out.TaprootBip32Derivation,
				vOut.AnchorOutputTaprootBip32Derivation[idx],
			)
		}
	}

	return spendPkt, nil
}

// UpdateTaprootOutputKeys updates a PSBT with outputs embedding TapCommitments
// involved in an asset send. The sender must attach the Bitcoin input holding
// the corresponding Taproot Asset input asset to this PSBT before finalizing
// the TX. Locators MUST be checked beforehand.
func UpdateTaprootOutputKeys(btcPacket *psbt.Packet, vPkt *tappsbt.VPacket,
	outputCommitments []*commitment.TapCommitment) (
	map[uint32]*commitment.TapCommitment, error) {

	// Add the commitment outputs to the BTC level PSBT now.
	anchorCommitments := make(map[uint32]*commitment.TapCommitment)
	for idx := range vPkt.Outputs {
		vOut := vPkt.Outputs[idx]
		vOutCommitment := outputCommitments[idx]

		// The commitment must be defined at this point.
		if vOutCommitment == nil {
			return nil, ErrMissingTapCommitment
		}

		// It could be that we have multiple outputs that are being
		// committed into the same anchor output. We need to merge them
		// into a single commitment.
		anchorIdx := vOut.AnchorOutputIndex
		anchorCommitment, ok := anchorCommitments[anchorIdx]
		if ok {
			err := anchorCommitment.Merge(vOutCommitment)
			if err != nil {
				return nil, fmt.Errorf("cannot merge output "+
					"commitments: %w", err)
			}
		} else {
			anchorCommitment = vOutCommitment
		}
		anchorCommitments[anchorIdx] = anchorCommitment

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

		// Prepare the anchor output's tapscript sibling, if there is
		// one. We assume (and checked in an earlier step) that each
		// virtual output declares the same tapscript sibling if
		// multiple virtual outputs are committed to the same anchor
		// output index.
		var (
			siblingPreimage = vOut.AnchorOutputTapscriptSibling
			siblingHash     *chainhash.Hash
		)
		if siblingPreimage != nil {
			siblingHash, err = siblingPreimage.TapHash()
			if err != nil {
				return nil, fmt.Errorf("unable to get "+
					"sibling hash: %w", err)
			}
		}

		// Create the scripts corresponding to the receiver's
		// TapCommitment.
		script, err := PayToAddrScript(
			*internalKey, siblingHash, *anchorCommitment,
		)
		if err != nil {
			return nil, err
		}

		btcTxOut := btcPacket.UnsignedTx.TxOut[vOut.AnchorOutputIndex]
		btcTxOut.PkScript = script
	}

	return anchorCommitments, nil
}

// interactiveFullValueSend returns true (and the index of the recipient output)
// if there is exactly one output that spends the input fully and interactively
// (when discarding any potential passive asset anchor outputs).
func interactiveFullValueSend(totalInputAmount uint64,
	outputs []*tappsbt.VOutput) (int, bool) {

	var (
		numRecipientOutputs = 0
		recipientIndex      = -1
	)
	for idx := range outputs {
		out := outputs[idx]

		// We identify a "recipient" output as one that is not a split
		// root, as that has to go back to the sender (either to create
		// a zero value tomb stone or to anchor passive assets).
		if !out.Type.IsSplitRoot() {
			numRecipientOutputs++
			recipientIndex = idx
		}
	}

	fullValueInteractiveSend := numRecipientOutputs == 1 &&
		outputs[recipientIndex].Amount == totalInputAmount &&
		outputs[recipientIndex].Interactive

	return recipientIndex, fullValueInteractiveSend
}

// assertAnchorsEqual makes sure that the anchor output information for each
// output of the virtual packet that anchors to the same BTC level output is
// identical.
func assertAnchorsEqual(vPkt *tappsbt.VPacket) error {
	deDupMap := make(map[uint32]*tappsbt.Anchor)
	for idx := range vPkt.Outputs {
		vOut := vPkt.Outputs[idx]

		siblingBytes, _, err := commitment.MaybeEncodeTapscriptPreimage(
			vOut.AnchorOutputTapscriptSibling,
		)
		if err != nil {
			return fmt.Errorf("unable to encode tapscript "+
				"preimage: %w", err)
		}
		outAnchor := &tappsbt.Anchor{
			InternalKey:       vOut.AnchorOutputInternalKey,
			TapscriptSibling:  siblingBytes,
			Bip32Derivation:   vOut.AnchorOutputBip32Derivation,
			TrBip32Derivation: vOut.AnchorOutputTaprootBip32Derivation,
		}

		anchor, ok := deDupMap[vOut.AnchorOutputIndex]
		if !ok {
			deDupMap[vOut.AnchorOutputIndex] = outAnchor
			continue
		}

		if !reflect.DeepEqual(anchor, outAnchor) {
			return fmt.Errorf("%w: anchor output information for "+
				"output %d is not identical to previous "+
				"with same anchor output index",
				ErrInvalidAnchorInfo, idx)
		}
	}

	return nil
}

// LogCommitment logs the given Taproot Asset commitment to the log as a trace
// message. This is a no-op if the log level is not set to trace.
func LogCommitment(prefix string, idx int,
	tapCommitment *commitment.TapCommitment, internalKey *btcec.PublicKey,
	pkScript, trimmedMerkleRoot []byte) {

	if log.Level() > btclog.LevelTrace {
		return
	}

	merkleRoot := tapCommitment.TapscriptRoot(nil)
	log.Tracef("%v commitment #%d v%d, taproot_asset_root=%x, "+
		"internal_key=%x, pk_script=%x, trimmed_merkle_root=%x",
		prefix, idx, tapCommitment.Version, merkleRoot[:],
		internalKey.SerializeCompressed(), pkScript, trimmedMerkleRoot)
	for _, a := range tapCommitment.CommittedAssets() {
		groupKey := "<nil>"
		if a.GroupKey != nil {
			groupKey = hex.EncodeToString(
				a.GroupKey.GroupPubKey.SerializeCompressed(),
			)
		}
		log.Tracef("%v commitment asset_id=%v, script_key=%x, "+
			"group_key=%v, amount=%d, version=%d, "+
			"split_commitment=%v", prefix, a.ID(),
			a.ScriptKey.PubKey.SerializeCompressed(), groupKey,
			a.Amount, a.Version, a.SplitCommitmentRoot != nil)
	}
}
