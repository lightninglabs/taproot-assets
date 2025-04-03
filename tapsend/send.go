package tapsend

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/bits"
	"reflect"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btclog/v2"
	"github.com/davecgh/go-spew/spew"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/tapscript"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lnwallet/btcwallet"
	"golang.org/x/exp/maps"
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

	// ErrInvalidAnchorOutputInfo is an error returned when the anchor output
	// information on a virtual transaction output is invalid.
	ErrInvalidAnchorOutputInfo = errors.New(
		"send: invalid anchor output info",
	)

	// ErrInvalidAnchorInputInfo is an error returned when the anchor input
	// information on a virtual transaction input is invalid.
	ErrInvalidAnchorInputInfo = errors.New(
		"send: invalid anchor input info",
	)

	// ErrAssetMissing is an error returned when an asset is missing from a
	// virtual transaction.
	ErrAssetMissing = errors.New("asset missing")

	// ErrAssetNotSigned is an error returned when an asset is not signed
	// in a virtual transaction that was already committed to an anchor
	// output.
	ErrAssetNotSigned = errors.New("asset not signed")

	// ErrNoRootLocator is an error that is returned when a split commitment
	// is created without a split root output.
	ErrNoRootLocator = errors.New(
		"cannot create split commitment without split root output",
	)

	// ErrDuplicateScriptKeys is an error that is returned when the outputs
	// of a virtual packet contain duplicate script keys.
	ErrDuplicateScriptKeys = errors.New(
		"send: duplicate script keys in outputs - cannot re-use same " +
			"script key in same transaction (e.g. cannot send to " +
			"same address more than once)",
	)
)

var (
	// GenesisDummyScript is a dummy script that we'll use to fund the
	// initial PSBT packet that'll create initial set of assets. It's the
	// same size as an encoded P2TR output and has a valid P2TR prefix.
	GenesisDummyScript = append(
		[]byte{txscript.OP_1, txscript.OP_DATA_32},
		bytes.Repeat([]byte{0x00}, 32)...,
	)
)

// CreateDummyOutput creates a new Bitcoin transaction output that is later
// used to embed a Taproot Asset commitment.
func CreateDummyOutput() *wire.TxOut {
	// The dummy PkScript is the same size as an encoded P2TR output and has
	// a valid P2TR prefix.
	return &wire.TxOut{
		Value:    int64(DummyAmtSats),
		PkScript: bytes.Clone(GenesisDummyScript),
	}
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
	// AssetSpecifier is the asset specifier.
	AssetSpecifier asset.Specifier

	// Amount is the amount of the asset to transfer.
	Amount uint64

	// PrevIDs is the set of inputs that can be used to fund the transfer.
	PrevIDs []asset.PrevID

	// DistinctSpecifier indicates whether we _only_ look at either the
	// group key _or_ the asset ID but not both. That means, if the group
	// key is set, we ignore the asset ID and allow multiple inputs of the
	// same group to be selected.
	DistinctSpecifier bool

	// ScriptKeyType is the type of script key the assets are expected to
	// have. If this is fn.None, then any script key type is allowed.
	ScriptKeyType fn.Option[asset.ScriptKeyType]
}

// TapCommitmentKey is the key that maps to the root commitment for the asset
// group specified by a recipient descriptor.
func (r *FundingDescriptor) TapCommitmentKey() [32]byte {
	return asset.TapCommitmentKey(r.AssetSpecifier)
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
		return nil, fmt.Errorf("unable to query asset group: %w", err)
	}

	assetSpecifier := asset.NewSpecifierOptionalGroupPubKey(
		firstInput.PrevID.ID, groupPubKey,
	)

	desc := &FundingDescriptor{
		AssetSpecifier: assetSpecifier,
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

	assetSpecifier := asset.NewSpecifierOptionalGroupPubKey(
		firstAddr.AssetID, firstAddr.GroupKey,
	)

	desc := &FundingDescriptor{
		AssetSpecifier: assetSpecifier,
	}
	for idx := range addrs {
		desc.Amount += addrs[idx].Amount
	}

	return desc, nil
}

// ValidateCommitmentKeysUnique makes sure the outputs of a set of virtual
// packets don't lead to collisions in and of the trees (e.g. two asset outputs
// with the same asset ID and script key in the same anchor output) or with
// exclusion proofs (e.g. two asset outputs with the same asset ID and script
// key in different anchor outputs).
func ValidateCommitmentKeysUnique(packets []*tappsbt.VPacket) error {
	// We'll keep track of all asset-level commitment keys (per top-level
	// commitment key) that we've seen so far. The lower level commitment
	// keys must be unique per top-level commitment key, otherwise
	// collisions or problems with exclusion proofs can occur. For grouped
	// assets, the asset ID is part of the asset-level commitment key, so
	// it's okay to re-use the same script key (e.g. a zero amount tombstone
	// change output) across different asset IDs.
	commitmentKeys := make(map[[32]byte]map[[32]byte]struct{})

	for _, vPkt := range packets {
		specifier, err := vPkt.AssetSpecifier()
		if err != nil {
			return fmt.Errorf("unable to determine tap commitment "+
				"key: %w", err)
		}

		tapCommitmentKey := asset.TapCommitmentKey(specifier)
		perAssetMap, ok := commitmentKeys[tapCommitmentKey]
		if !ok {
			perAssetMap = make(map[[32]byte]struct{})
			commitmentKeys[tapCommitmentKey] = perAssetMap
		}

		id, err := specifier.UnwrapIdOrErr()
		if err != nil {
			return fmt.Errorf("unable to unwrap asset ID: %w", err)
		}

		hasGroupKey := specifier.HasGroupPubKey()
		for idx := range vPkt.Outputs {
			vOut := vPkt.Outputs[idx]

			// Check if the asset-level commitment key has already
			// been used in this transaction.
			assetCommitmentKey := asset.AssetCommitmentKey(
				id, vOut.ScriptKey.PubKey, !hasGroupKey,
			)
			if _, ok := perAssetMap[assetCommitmentKey]; ok {
				return ErrDuplicateScriptKeys
			}

			perAssetMap[assetCommitmentKey] = struct{}{}
		}
	}

	return nil
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

		// A single virtual packet can only contain assets with the same
		// ID. For different fungible assets, distinct virtual packets
		// need to be created.
		if idx > 0 && inputs[idx].Asset().ID() != assetID {
			return fmt.Errorf("multiple input assets " +
				"must have the same asset ID")
		}
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
		case !vOut.Type.IsSplitRoot() && isUnSpendable:
			return commitment.ErrInvalidScriptKey

		// Only the split root can have a zero amount.
		case !vOut.Type.IsSplitRoot() && vOut.Amount == 0:
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

			// For an interactive transfer of a collectible there
			// should be no split root output.
			if rootOut.Type.IsSplitRoot() &&
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
		// Sum the total amount of the input assets.
		inputsAmountSum := uint64(0)
		for idx := range inputs {
			in := inputs[idx]

			// At the moment, we need to ensure that all inputs have
			// the same asset ID. We've already checked that above,
			// but we will do it again here for clarity.
			if inputs[idx].Asset().ID() != assetID {
				return fmt.Errorf("multiple input assets " +
					"must have the same asset ID")
			}

			inputsAmountSum += in.Asset().Amount
		}

		// At this point we know that each input has the same asset ID
		// we therefore arbitrarily select the first input as our
		// template output asset.
		firstInput := inputs[0]

		// We'll now create a new copy of the old asset, swapping out
		// the script key. We blank out the tweaked key information as
		// this is now an external asset.
		vOut := outputs[recipientIndex]
		vOut.Asset = firstInput.Asset().Copy()
		vOut.Asset.Amount = inputsAmountSum
		vOut.Asset.ScriptKey = vOut.ScriptKey
		vOut.Asset.LockTime = vOut.LockTime
		vOut.Asset.RelativeLockTime = vOut.RelativeLockTime

		// We also need to clear the split commitment root to avoid
		// state from previous splits being carried over.
		vOut.Asset.SplitCommitmentRoot = nil

		// Gather previous witnesses from the input assets.
		prevWitnesses := make([]asset.Witness, len(inputs))
		for idx := range inputs {
			in := inputs[idx]

			// Record the PrevID of the input asset in a Witness for
			// the new asset. This Witness still needs a valid
			// signature for the new asset to be valid.
			prevWitnesses[idx] = asset.Witness{
				PrevID:          &in.PrevID,
				TxWitness:       nil,
				SplitCommitment: nil,
			}
		}
		vOut.Asset.PrevWitnesses = prevWitnesses

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

	// If we're creating a split commitment, there must be a split root.
	// If none of the outputs was designated as the split root, then
	// something was done incorrectly.
	if rootLocator == nil {
		return ErrNoRootLocator
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
			vOut.Asset.LockTime = vOut.LockTime
			vOut.Asset.RelativeLockTime = vOut.RelativeLockTime
			vOut.Asset.ScriptKey = vOut.ScriptKey

			vOut.SplitAsset = &splitAsset.Asset
			vOut.SplitAsset.ScriptKey = vOut.ScriptKey
			continue
		}

		vOut.Asset = &splitAsset.Asset
		vOut.Asset.ScriptKey = vOut.ScriptKey
		vOut.Asset.LockTime = vOut.LockTime
		vOut.Asset.RelativeLockTime = vOut.RelativeLockTime
	}

	return nil
}

// SignVirtualTransaction updates the new asset (the root asset located at the
// change output in case of a non-interactive or partial amount send or the
// full asset in case of an interactive full amount send) by creating a
// signature over the asset transfer, verifying the transfer with the Taproot
// Asset VM, and attaching that signature to the new Asset.
func SignVirtualTransaction(vPkt *tappsbt.VPacket, signer tapscript.Signer,
	validator tapscript.WitnessValidator) error {

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
	var splitAssets []*commitment.SplitAsset
	if isSplit {
		splitOut, err := vPkt.SplitRootOutput()
		if err != nil {
			return fmt.Errorf("no split root output found for "+
				"split transaction: %w", err)
		}
		newAsset = splitOut.Asset

		// If the transfer includes an asset split, we have to validate
		// each split asset to ensure that our new Asset is committing
		// to a valid SplitCommitment.
		splitAssets = make([]*commitment.SplitAsset, len(outputs))
		for idx := range outputs {
			splitAssets[idx] = &commitment.SplitAsset{
				Asset:       *outputs[idx].Asset,
				OutputIndex: outputs[idx].AnchorOutputIndex,
			}

			// The output that houses the root asset in case of a
			// split has a special field for the split asset, which
			// actually contains the split commitment proof. We need
			// to use that one for the validation, as the root asset
			// is already validated as the newAsset.
			if outputs[idx].Type.IsSplitRoot() {
				splitAssets[idx].Asset =
					*outputs[idx].SplitAsset
			}
		}
	}

	// Construct input set from all input assets.
	prevAssets := make(commitment.InputSet, len(inputs))
	for idx := range vPkt.Inputs {
		vIn := vPkt.Inputs[idx]
		prevAssets[vIn.PrevID] = vIn.Asset()
	}

	// Create a Taproot Asset virtual transaction representing the asset
	// transfer.
	virtualTx, _, err := tapscript.VirtualTx(newAsset, prevAssets)
	if err != nil {
		return err
	}

	for idx := range inputs {
		in := inputs[idx]

		// For each input asset leaf, we need to produce a witness.
		// Update the input of the virtual TX, generate a witness, and
		// attach it to the copy of the new Asset.
		virtualTxCopy := virtualTx.Copy()
		inputSpecificVirtualTx := asset.VirtualTxWithInput(
			virtualTxCopy, newAsset.LockTime,
			newAsset.RelativeLockTime, uint32(idx), nil,
		)

		// Sign the virtual transaction based on the input script
		// information (key spend or script spend).
		newWitness, err := CreateTaprootSignature(
			in, inputSpecificVirtualTx, 0, signer,
		)
		if err != nil {
			return fmt.Errorf("error creating taproot "+
				"signature: %w", err)
		}

		newAsset.PrevWitnesses[idx].TxWitness = newWitness
	}

	err = validator.ValidateWitnesses(newAsset, splitAssets, prevAssets)
	if err != nil {
		return err
	}

	if isSplit {
		// Update each split asset to store the root asset with the
		// witness attached, so the receiver can verify inclusion of the
		// root asset.
		for idx := range outputs {
			splitAsset := outputs[idx].Asset

			// The output that houses the root asset in case of a
			// split has a special field for the split asset. That
			// asset is no longer needed (and isn't committed to
			// anywhere), but in order for it to be validated
			// externally, we still want to include it and therefore
			// also want to update it with the signed root asset.
			if outputs[idx].Type.IsSplitRoot() {
				splitAsset = outputs[idx].SplitAsset
			}

			splitCommitment :=
				splitAsset.PrevWitnesses[0].SplitCommitment
			splitCommitment.RootAsset = *newAsset.Copy()
		}
	}

	return nil
}

// CreateTaprootSignature creates a Taproot signature for the given asset input.
// Depending on the fields set in the input, this will either create a key path
// spend or a script path spend.
func CreateTaprootSignature(vIn *tappsbt.VInput, virtualTx *wire.MsgTx,
	idx int, txSigner tapscript.Signer) (wire.TxWitness, error) {

	// Before we even attempt to sign anything, we need to make sure all the
	// input information we require is present.
	if len(vIn.TaprootBip32Derivation) == 0 {
		return nil, fmt.Errorf("missing input Taproot BIP-0032 " +
			"derivation")
	}

	// Currently, we only support creating one signature per input.
	//
	// TODO(guggero): Should we support signing multiple paths at the same
	// time? What are the performance and security implications?
	if len(vIn.TaprootBip32Derivation) > 1 {
		return nil, fmt.Errorf("unsupported multiple taproot " +
			"BIP-0032 derivation info found, can only sign for " +
			"one at a time")
	}
	if len(vIn.TaprootBip32Derivation[0].LeafHashes) > 1 {
		return nil, fmt.Errorf("unsupported number of leaf hashes in " +
			"taproot BIP-0032 derivation info, can only sign for " +
			"one at a time")
	}

	derivation := vIn.Bip32Derivation[0]
	trDerivation := vIn.TaprootBip32Derivation[0]

	keyDesc, err := tappsbt.KeyDescFromBip32Derivation(derivation)
	if err != nil {
		return nil, fmt.Errorf("error identifying input asset key "+
			"descriptor from BIP-0032 derivation: %w", err)
	}

	// Compute a virtual prevOut from the input asset for the signer.
	prevOut, err := tapscript.InputAssetPrevOut(*vIn.Asset())
	if err != nil {
		return nil, err
	}

	// Start with a default sign descriptor and the BIP-0086 sign method
	// then adjust depending on the input parameters.
	spendDesc := lndclient.SignDescriptor{
		KeyDesc:    keyDesc,
		SignMethod: input.TaprootKeySpendBIP0086SignMethod,
		Output:     prevOut,
		HashType:   vIn.SighashType,
		InputIndex: idx,
	}

	// Add any tweak parameters that may be present in the PSBT.
	addKeyTweaks(vIn.Unknowns, &spendDesc)

	// There are three possible signing cases: BIP-0086 key spend path, key
	// spend path with a script root, and script spend path.
	switch {
	// If there is no merkle root, we're doing a BIP-0086 key spend.
	case len(vIn.TaprootMerkleRoot) == 0:
		// This is the default case, so we don't need to do anything.

	// No leaf hash means we're not signing a specific script, so this is
	// the key spend path with a script root.
	case len(vIn.TaprootMerkleRoot) == sha256.Size &&
		len(trDerivation.LeafHashes) == 0:

		spendDesc.SignMethod = input.TaprootKeySpendSignMethod
		spendDesc.TapTweak = vIn.TaprootMerkleRoot

	// One leaf hash and a merkle root means we're signing a specific
	// script. There can be other scripts in the tree, but we only support
	// creating a signature for a single one at a time.
	case len(vIn.TaprootMerkleRoot) == sha256.Size &&
		len(trDerivation.LeafHashes) == 1:

		// If we're supposed to be signing for a leaf hash, we also
		// expect the leaf script that hashes to that hash in the
		// appropriate field.
		if len(vIn.TaprootLeafScript) != 1 {
			return nil, fmt.Errorf("specified leaf hash in " +
				"taproot BIP-0032 derivation but missing " +
				"taproot leaf script")
		}

		leafScript := vIn.TaprootLeafScript[0]
		leaf := txscript.TapLeaf{
			LeafVersion: leafScript.LeafVersion,
			Script:      leafScript.Script,
		}
		leafHash := leaf.TapHash()
		if !bytes.Equal(leafHash[:], trDerivation.LeafHashes[0]) {
			return nil, fmt.Errorf("specified leaf hash in " +
				"taproot BIP-0032 derivation but " +
				"corresponding taproot leaf script was not " +
				"found")
		}

		spendDesc.SignMethod = input.TaprootScriptSpendSignMethod
		spendDesc.WitnessScript = leafScript.Script

	// Some invalid combination of fields was specified, it's not clear what
	// we should do. So rather than fail later, let's return an explicit
	// error here.
	default:
		return nil, fmt.Errorf("unable to determine signing method " +
			"from virtual transaction packet")
	}

	log.Tracef("Signing virtual TX with descriptor %v",
		spew.Sdump(spendDesc))

	sig, err := txSigner.SignVirtualTx(&spendDesc, virtualTx, prevOut)
	if err != nil {
		return nil, err
	}

	witness := wire.TxWitness{sig.Serialize()}
	if vIn.SighashType != txscript.SigHashDefault {
		witness[0] = append(witness[0], byte(vIn.SighashType))
	}

	// If this was a script spend, we also have to add the script itself and
	// the control block to the witness, otherwise the verifier will reject
	// the generated witness.
	if spendDesc.SignMethod == input.TaprootScriptSpendSignMethod {
		witness = append(witness, spendDesc.WitnessScript)
		witness = append(witness, vIn.TaprootLeafScript[0].ControlBlock)
	}

	return witness, nil
}

// addKeyTweaks examines if there are any tweak parameters given in the
// custom/proprietary PSBT fields and may add them to the given sign descriptor.
func addKeyTweaks(unknowns []*psbt.Unknown, desc *lndclient.SignDescriptor) {
	// There can be other custom/unknown keys in a PSBT that we just ignore.
	// Key tweaking is optional and only one tweak (single _or_ double) can
	// ever be applied (at least for any use cases described in the BOLT
	// spec).
	for _, u := range unknowns {
		if bytes.Equal(
			u.Key, btcwallet.PsbtKeyTypeInputSignatureTweakSingle,
		) {

			desc.SingleTweak = u.Value
		}

		if bytes.Equal(
			u.Key, btcwallet.PsbtKeyTypeInputSignatureTweakDouble,
		) {

			doubleTweakKey, _ := btcec.PrivKeyFromBytes(u.Value)
			desc.DoubleTweak = doubleTweakKey
		}
	}
}

// CreateOutputCommitments creates the final set of Taproot asset commitments
// representing the asset sends of the given packets of active and passive
// assets.
func CreateOutputCommitments(
	packets []*tappsbt.VPacket) (tappsbt.OutputCommitments, error) {

	// Inputs must be unique.
	if err := AssertInputsUnique(packets); err != nil {
		return nil, err
	}

	// We require all outputs that reference the same anchor output to be
	// identical, otherwise some assumptions in the code below don't hold.
	if err := AssertInputAnchorsEqual(packets); err != nil {
		return nil, err
	}
	if err := AssertOutputAnchorsEqual(packets); err != nil {
		return nil, err
	}
	if err := AssertOutputAltLeavesValid(packets); err != nil {
		return nil, err
	}

	// We need to make sure this transaction doesn't lead to collisions in
	// any of the trees (e.g. two asset outputs with the same script key in
	// the same anchor output) or with exclusion proofs (e.g. two asset
	// outputs with the same script key in different anchor outputs).
	err := ValidateCommitmentKeysUnique(packets)
	if err != nil {
		return nil, err
	}

	// We create an empty output commitment map, keyed by the anchor output
	// index.
	outputCommitments := make(tappsbt.OutputCommitments)

	// And now we commit each packet to the respective anchor output
	// commitments.
	for _, vPkt := range packets {
		err := commitPacket(vPkt, outputCommitments)
		if err != nil {
			return nil, err
		}
	}

	return outputCommitments, nil
}

// commitPacket creates the output commitments for a virtual packet and merges
// it with the existing commitments for the anchor outputs.
func commitPacket(vPkt *tappsbt.VPacket,
	outputCommitments tappsbt.OutputCommitments) error {

	inputs := vPkt.Inputs
	outputs := vPkt.Outputs

	// One virtual packet is only allowed to contain inputs and outputs of
	// the same asset ID. Fungible assets must be sent in separate packets.
	firstInputID := inputs[0].Asset().ID()
	for idx := range inputs {
		if inputs[idx].Asset().ID() != firstInputID {
			return fmt.Errorf("inputs must have the same asset ID")
		}
	}

	// Set the output commitment version based on the vPkt version.
	outputCommitmentVersion, err := tappsbt.CommitmentVersion(vPkt.Version)
	if err != nil {
		return err
	}

	for idx := range outputs {
		vOut := outputs[idx]
		anchorOutputIdx := vOut.AnchorOutputIndex

		if vOut.Asset == nil {
			return fmt.Errorf("output %d is missing asset", idx)
		}

		sendTapCommitment, err := commitment.FromAssets(
			outputCommitmentVersion, vOut.Asset,
		)
		if err != nil {
			return fmt.Errorf("error committing assets: %w", err)
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
		sendTapCommitment, err = commitment.TrimSplitWitnesses(
			outputCommitmentVersion, sendTapCommitment,
		)
		if err != nil {
			return fmt.Errorf("error trimming split witnesses: %w",
				err)
		}

		// If the vOutput contains any AltLeaves, merge them into the
		// tap commitment.
		err = sendTapCommitment.MergeAltLeaves(vOut.AltLeaves)
		if err != nil {
			return fmt.Errorf("error merging alt leaves: %w", err)
		}

		// Merge the finished TAP level commitment with the existing
		// one (if any) for the anchor output.
		anchorOutputCommitment, ok := outputCommitments[anchorOutputIdx]
		if ok {
			err = sendTapCommitment.Merge(anchorOutputCommitment)
			if err != nil {
				return fmt.Errorf("unable to merge output "+
					"commitment: %w", err)
			}
		}

		outputCommitments[anchorOutputIdx] = sendTapCommitment

		// Add some trace logging for easier debugging of what goes into
		// the output commitment (we'll do the same for the input
		// commitment).
		LogCommitment(
			"Output", idx, outputCommitments[anchorOutputIdx],
			vOut.AnchorOutputInternalKey, nil, nil,
		)
	}

	return nil
}

// CreateAnchorTx creates a template BTC anchor TX with dummy outputs.
func CreateAnchorTx(vPackets []*tappsbt.VPacket) (*psbt.Packet, error) {
	// We locate the highest anchor output index in all virtual packets to
	// create a template TX with the correct number of outputs.
	var maxOutputIndex uint32
	for _, vPkt := range vPackets {
		// Sanity check the output indexes provided by the sender. There
		// must be at least one output.
		if len(vPkt.Outputs) == 0 {
			return nil, ErrInvalidOutputIndexes
		}

		for _, vOut := range vPkt.Outputs {
			if vOut.AnchorOutputIndex > maxOutputIndex {
				maxOutputIndex = vOut.AnchorOutputIndex
			}
		}
	}

	txTemplate := wire.NewMsgTx(2)

	// Zero is a valid anchor output index, so we need to do <= here.
	for i := uint32(0); i <= maxOutputIndex; i++ {
		txTemplate.AddTxOut(CreateDummyOutput())
	}

	spendPkt, err := psbt.NewFromUnsignedTx(txTemplate)
	if err != nil {
		return nil, fmt.Errorf("unable to make psbt packet: %w", err)
	}

	// With the dummy packet created, we'll walk through of vOutputs to set
	// the taproot internal key for each of the outputs.
	for _, vPkt := range vPackets {
		for i := range vPkt.Outputs {
			vOut := vPkt.Outputs[i]

			btcOut := &spendPkt.Outputs[vOut.AnchorOutputIndex]
			btcOut.TaprootInternalKey = schnorr.SerializePubKey(
				vOut.AnchorOutputInternalKey,
			)

			bip32 := vOut.AnchorOutputBip32Derivation
			for idx := range bip32 {
				btcOut.Bip32Derivation =
					tappsbt.AddBip32Derivation(
						btcOut.Bip32Derivation,
						bip32[idx],
					)
			}
			trBip32 := vOut.AnchorOutputTaprootBip32Derivation
			for idx := range trBip32 {
				btcOut.TaprootBip32Derivation =
					tappsbt.AddTaprootBip32Derivation(
						btcOut.TaprootBip32Derivation,
						trBip32[idx],
					)
			}
		}
	}

	return spendPkt, nil
}

// PrepareAnchoringTemplate creates a BTC level PSBT packet that can be used to
// anchor the given virtual packets. The PSBT packet is created with the
// necessary inputs and outputs to anchor the virtual packets, but without any
// signatures. The main difference to CreateAnchorTx is that this function
// populates the inputs with the witness UTXO and derivation path information.
func PrepareAnchoringTemplate(
	vPackets []*tappsbt.VPacket) (*psbt.Packet, error) {

	err := ValidateVPacketVersions(vPackets)
	if err != nil {
		return nil, err
	}

	btcPacket, err := CreateAnchorTx(vPackets)
	if err != nil {
		return nil, err
	}

	// Populate input information now. We add the witness UTXO and
	// derivation path information for each asset input. Since the virtual
	// transactions might refer to the same BTC level input, we need to make
	// sure we don't add any duplicate inputs.
	for pIdx := range vPackets {
		for iIdx := range vPackets[pIdx].Inputs {
			vIn := vPackets[pIdx].Inputs[iIdx]
			anchor := vIn.Anchor

			if HasInput(btcPacket.UnsignedTx, vIn.PrevID.OutPoint) {
				continue
			}

			btcPacket.Inputs = append(btcPacket.Inputs, psbt.PInput{
				WitnessUtxo: &wire.TxOut{
					Value:    int64(anchor.Value),
					PkScript: anchor.PkScript,
				},
				SighashType:            anchor.SigHashType,
				Bip32Derivation:        anchor.Bip32Derivation,
				TaprootBip32Derivation: anchor.TrBip32Derivation,
				TaprootInternalKey: schnorr.SerializePubKey(
					anchor.InternalKey,
				),
				TaprootMerkleRoot: anchor.MerkleRoot,
			})
			btcPacket.UnsignedTx.TxIn = append(
				btcPacket.UnsignedTx.TxIn, &wire.TxIn{
					PreviousOutPoint: vIn.PrevID.OutPoint,
				},
			)
		}
	}

	return btcPacket, nil
}

// HasInput returns true if the given transaction has an input that spends the
// given outpoint.
func HasInput(tx *wire.MsgTx, outpoint wire.OutPoint) bool {
	for _, in := range tx.TxIn {
		if in.PreviousOutPoint == outpoint {
			return true
		}
	}

	return false
}

// AssertAnchorTimeLocks makes sure the anchor transaction and its inputs have
// the correct lock time and sequence set, according to the assets being spent.
func AssertAnchorTimeLocks(btcPkt *psbt.Packet, vPkt *tappsbt.VPacket) {
	maxLockTime := uint64(0)
	for idx := range vPkt.Outputs {
		vOut := vPkt.Outputs[idx]

		// Extract the highest used lock time, as that's per
		// transaction.
		if vOut.LockTime > maxLockTime {
			maxLockTime = vOut.Asset.LockTime
		}

		// For each input, set the relative lock time as the sequence on
		// the BTC input.
		for _, prevWitness := range vOut.Asset.PrevWitnesses {
			outPoint := prevWitness.PrevID.OutPoint

			for btcInIdx := range btcPkt.UnsignedTx.TxIn {
				txIn := btcPkt.UnsignedTx.TxIn[btcInIdx]
				if txIn.PreviousOutPoint == outPoint {
					txIn.Sequence = uint32(
						vOut.RelativeLockTime,
					)
				}
			}
		}
	}

	// Assign the highest lock time to the transaction, if the one present
	// there isn't already higher. We need to check this because this
	// function is called for each vPacket individually.
	if btcPkt.UnsignedTx.LockTime < uint32(maxLockTime) {
		btcPkt.UnsignedTx.LockTime = uint32(maxLockTime)
	}
}

// UpdateTaprootOutputKeys updates a PSBT with outputs embedding TapCommitments
// involved in an asset send. The sender must attach the Bitcoin input holding
// the corresponding Taproot Asset input asset to this PSBT before finalizing
// the TX. Locators MUST be checked beforehand. Since this is called when the
// anchor transaction and all assets are final, we also make sure any time locks
// from the assets are properly bubbled up to the BTC level.
func UpdateTaprootOutputKeys(btcPacket *psbt.Packet, vPkt *tappsbt.VPacket,
	outputCommitments tappsbt.OutputCommitments) error {

	// Make sure the anchor transaction has all lock times correctly bubbled
	// up for this virtual packet.
	AssertAnchorTimeLocks(btcPacket, vPkt)

	// Add the commitment outputs to the BTC level PSBT now.
	for idx := range vPkt.Outputs {
		vOut := vPkt.Outputs[idx]
		anchorCommitment := outputCommitments[vOut.AnchorOutputIndex]

		// The commitment must be defined at this point.
		if anchorCommitment == nil {
			return ErrMissingTapCommitment
		}

		// The external output index cannot be out of bounds of the
		// actual TX outputs. This should be checked earlier and is just
		// a final safeguard here.
		if vOut.AnchorOutputIndex >= uint32(len(btcPacket.Outputs)) {
			return ErrInvalidOutputIndexes
		}

		btcOut := &btcPacket.Outputs[vOut.AnchorOutputIndex]
		internalKey, err := schnorr.ParsePubKey(
			btcOut.TaprootInternalKey,
		)
		if err != nil {
			return err
		}

		// We have all the information now to calculate the actual
		// commitment output script.
		script, merkleRoot, taprootAssetRoot, err := AnchorOutputScript(
			internalKey, vOut.AnchorOutputTapscriptSibling,
			anchorCommitment,
		)
		if err != nil {
			return err
		}

		btcTxOut := btcPacket.UnsignedTx.TxOut[vOut.AnchorOutputIndex]
		btcTxOut.PkScript = script

		// Also set some additional fields in the PSBT output to make
		// it easier to create the transfer database entry later.
		btcOut.Unknowns = tappsbt.AddCustomField(
			btcOut.Unknowns,
			tappsbt.PsbtKeyTypeOutputTaprootMerkleRoot,
			merkleRoot[:],
		)
		btcOut.Unknowns = tappsbt.AddCustomField(
			btcOut.Unknowns,
			tappsbt.PsbtKeyTypeOutputAssetRoot,
			taprootAssetRoot[:],
		)
	}

	return nil
}

// AnchorOutputScript creates the anchor output script given an internal key,
// tapscript sibling and the TapCommitment. It also returns the merkle root and
// taproot asset root for the commitment.
func AnchorOutputScript(internalKey *btcec.PublicKey,
	siblingPreimage *commitment.TapscriptPreimage,
	anchorCommitment *commitment.TapCommitment) ([]byte, chainhash.Hash,
	chainhash.Hash, error) {

	var emptyHash chainhash.Hash

	// If any of the assets were received non-interactively, then the
	// Taproot Asset tree of the input anchor output was built with asset
	// leaves that had empty SplitCommitments. We need to replicate this
	// here as well.
	trimmedCommitment, err := commitment.TrimSplitWitnesses(
		&anchorCommitment.Version, anchorCommitment,
	)
	if err != nil {
		return nil, emptyHash, emptyHash, fmt.Errorf("unable to trim "+
			"split witnesses: %w", err)
	}

	// Decode the Tapscript sibling preimage if there was one, so we can
	// arrive at the correct merkle root hash.
	_, siblingHash, err := commitment.MaybeEncodeTapscriptPreimage(
		siblingPreimage,
	)
	if err != nil {
		return nil, emptyHash, emptyHash, err
	}

	// Create the scripts corresponding to the receiver's TapCommitment.
	script, err := tapscript.PayToAddrScript(
		*internalKey, siblingHash, *trimmedCommitment,
	)
	if err != nil {
		return nil, emptyHash, emptyHash, err
	}

	// Also set some additional fields in the PSBT output to make it easier
	// to create the transfer database entry later.
	merkleRoot := trimmedCommitment.TapscriptRoot(siblingHash)
	taprootAssetRoot := trimmedCommitment.TapscriptRoot(nil)

	return script, merkleRoot, taprootAssetRoot, nil
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

// AssertOutputAnchorsEqual makes sure that the anchor output information for
// each output of the virtual packets that anchors to the same BTC level output
// is identical.
func AssertOutputAnchorsEqual(packets []*tappsbt.VPacket) error {
	// comparableAnchor is a helper function that returns an Anchor struct
	// from a virtual output comparing exactly the fields we require to be
	// equal across all virtual outputs for the same anchor output index.
	comparableAnchor := func(o *tappsbt.VOutput) (*tappsbt.Anchor, error) {
		siblingBytes, _, err := commitment.MaybeEncodeTapscriptPreimage(
			o.AnchorOutputTapscriptSibling,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to encode tapscript "+
				"preimage: %w", err)
		}

		// A virtual output only has certain anchor information set, so
		// we can only construct a partial Anchor struct from it.
		return &tappsbt.Anchor{
			InternalKey:       o.AnchorOutputInternalKey,
			TapscriptSibling:  siblingBytes,
			Bip32Derivation:   o.AnchorOutputBip32Derivation,
			TrBip32Derivation: o.AnchorOutputTaprootBip32Derivation,
		}, nil
	}

	outDeDupMap := make(map[uint32]*tappsbt.Anchor)
	for _, vPkt := range packets {
		for idx := range vPkt.Outputs {
			vOut := vPkt.Outputs[idx]

			outAnchor, err := comparableAnchor(vOut)
			if err != nil {
				return err
			}

			anchor, ok := outDeDupMap[vOut.AnchorOutputIndex]
			if !ok {
				outDeDupMap[vOut.AnchorOutputIndex] = outAnchor

				continue
			}

			if !reflect.DeepEqual(anchor, outAnchor) {
				return fmt.Errorf("%w: anchor output "+
					"information for output %d is not "+
					"identical to previous with same "+
					"anchor output index",
					ErrInvalidAnchorOutputInfo, idx)
			}
		}
	}

	return nil
}

// AssertInputAnchorsEqual makes sure that the anchor input information for
// each input of the virtual packets that anchors to the same BTC level input
// is identical.
func AssertInputAnchorsEqual(packets []*tappsbt.VPacket) error {
	inDeDupMap := make(map[wire.OutPoint]*tappsbt.Anchor)
	for _, vPkt := range packets {
		for idx := range vPkt.Inputs {
			vIn := vPkt.Inputs[idx]

			inAnchor := &vIn.Anchor
			op := vIn.PrevID.OutPoint

			anchor, ok := inDeDupMap[op]
			if !ok {
				inDeDupMap[op] = inAnchor

				continue
			}

			if !reflect.DeepEqual(anchor, inAnchor) {
				return fmt.Errorf("%w: anchor input "+
					"information for input %v is not "+
					"identical to previous with same "+
					"anchor outpoint",
					ErrInvalidAnchorInputInfo, op)
			}
		}
	}

	return nil
}

// AssertInputsUnique makes sure that every input across all virtual packets is
// referencing a unique input asset, which is identified by the input PrevID.
func AssertInputsUnique(packets []*tappsbt.VPacket) error {
	// PrevIDs are comparable enough to serve as a map key without hashing.
	inputs := make(lfn.Set[asset.PrevID])

	for _, vPkt := range packets {
		for _, vIn := range vPkt.Inputs {
			if inputs.Contains(vIn.PrevID) {
				return fmt.Errorf("input %v is duplicated",
					vIn.PrevID)
			}

			inputs.Add(vIn.PrevID)
		}
	}

	return nil
}

// AssertOutputAltLeavesValid checks that, for each anchor output, the AltLeaves
// carried by all packets assigned to that output can be used to construct an
// AltCommitment.
func AssertOutputAltLeavesValid(vPackets []*tappsbt.VPacket) error {
	anchorLeaves := make(map[uint32]fn.Set[[32]byte])

	for _, pkt := range vPackets {
		for _, vOut := range pkt.Outputs {
			if len(vOut.AltLeaves) == 0 {
				continue
			}

			// Build a set of AltLeaf keys for each anchor output.
			outIndex := vOut.AnchorOutputIndex
			if _, ok := anchorLeaves[outIndex]; !ok {
				anchorLeaves[outIndex] = fn.NewSet[[32]byte]()
			}

			err := asset.AddLeafKeysVerifyUnique(
				anchorLeaves[outIndex], vOut.AltLeaves,
			)
			if err != nil {
				return fmt.Errorf("anchor output %d: %w",
					outIndex, err)
			}
		}
	}

	return nil
}

// ExtractUnSpendable extracts all tombstones and burns from the active input
// commitment.
func ExtractUnSpendable(c *commitment.TapCommitment) []*asset.Asset {
	return fn.Filter(c.CommittedAssets(), func(a *asset.Asset) bool {
		return a.IsUnSpendable() || a.IsBurn()
	})
}

// RemoveAssetsFromCommitment removes all assets from the given commitment and
// only returns a tree of the remaining commitments.
func RemoveAssetsFromCommitment(c *commitment.TapCommitment,
	assets []*asset.Asset) (*commitment.TapCommitment, error) {

	// Gather remaining assets ot the commitment. This creates a copy of
	// the commitment map, so we can remove things freely.
	remainingCommitments, err := c.Copy()
	if err != nil {
		return nil, fmt.Errorf("unable to copy commitment: %w", err)
	}

	// Remove input assets (the assets being spent) from list of assets to
	// re-sign.
	for _, a := range assets {
		assetCommitment, ok := remainingCommitments.Commitment(a)
		if !ok {
			continue
		}

		err = assetCommitment.Delete(a)
		if err != nil {
			return nil, fmt.Errorf("unable to delete asset: %w",
				err)
		}
	}

	return remainingCommitments, nil
}

// RemovePacketsFromCommitment removes all assets within the virtual
// transactions from the given commitment.
func RemovePacketsFromCommitment(c *commitment.TapCommitment,
	packets []*tappsbt.VPacket) (*commitment.TapCommitment, error) {

	var activeAssets []*asset.Asset
	fn.ForEach(packets, func(vPkt *tappsbt.VPacket) {
		for _, vIn := range vPkt.Inputs {
			activeAssets = append(activeAssets, vIn.Asset())
		}
	})
	return RemoveAssetsFromCommitment(c, activeAssets)
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
		var buf bytes.Buffer
		_ = a.Encode(&buf)

		groupKey := "<nil>"
		if a.GroupKey != nil {
			groupKey = hex.EncodeToString(
				a.GroupKey.GroupPubKey.SerializeCompressed(),
			)
		}
		log.Tracef("%v commitment asset_id=%v, script_key=%x, "+
			"group_key=%v, amount=%d, version=%d, "+
			"split_commitment=%v, encoded=%x", prefix, a.ID(),
			a.ScriptKey.PubKey.SerializeCompressed(), groupKey,
			a.Amount, a.Version, a.SplitCommitmentRoot != nil,
			buf.Bytes())

	}
}

// ValidateVPacketVersions checks that all virtual packets are the same version.
func ValidateVPacketVersions(vPackets []*tappsbt.VPacket) error {
	if len(vPackets) == 0 {
		return fmt.Errorf("no virtual packets")
	}

	firstPktVersion := vPackets[0].Version
	matchingVersion := fn.All(vPackets, func(vPkt *tappsbt.VPacket) bool {
		return vPkt.Version == firstPktVersion
	})
	if !matchingVersion {
		return fmt.Errorf("mixed virtual packet versions")
	}

	return nil
}

// ValidateAnchorOutputs checks that the anchor outputs of the virtual packets
// are valid and consistent with the provided BTC level PSBT packet. When
// calling this function, everything must be ready to be signed on the BTC
// level, meaning all asset level information must be final (including the
// asset signatures for ASSET_VERSION_V0 assets). If the updateDatabaseHints
// flag is set, the function will also make sure the extra information (merkle
// root and taproot asset root) is set in the PSBT packet's outputs. That info
// is required to create the transfer output database entry.
func ValidateAnchorOutputs(anchorPacket *psbt.Packet,
	packets []*tappsbt.VPacket, updateDatabaseHints bool) error {

	// We first make sure the "static" anchor information in the virtual
	// packets is consistent with the provided BTC level PSBT packet.
	var (
		numAnchorOutputs = uint32(len(anchorPacket.Outputs))
		outputAssets     = make(map[uint32][]*asset.Asset)
		outputSiblings   = make(
			map[uint32]*commitment.TapscriptPreimage,
		)
		outputAltLeaves = make(
			map[uint32][]asset.AltLeaf[asset.Asset],
		)
		outputCommitVersions = make(
			map[uint32]*commitment.TapCommitmentVersion,
		)
	)
	for _, vPkt := range packets {
		pktCommitVersion, err := tappsbt.CommitmentVersion(vPkt.Version)
		if err != nil {
			return err
		}

		for idx := range vPkt.Outputs {
			vOut := vPkt.Outputs[idx]

			// The anchor output index must be within the bounds of
			// the BTC level PSBT packet.
			if vOut.AnchorOutputIndex >= numAnchorOutputs {
				return fmt.Errorf("%w: anchor output index %d "+
					"is invalid", ErrInvalidOutputIndexes,
					vOut.AnchorOutputIndex)
			}

			// The internal key must be set for each output.
			if vOut.AnchorOutputInternalKey == nil {
				return fmt.Errorf("%w: anchor output internal "+
					"key missing",
					ErrInvalidAnchorOutputInfo)
			}

			// The tapscript sibling must be a valid tapscript
			// preimage.
			siblingPreimage := vOut.AnchorOutputTapscriptSibling
			_, _, err := commitment.MaybeEncodeTapscriptPreimage(
				siblingPreimage,
			)
			if err != nil {
				return fmt.Errorf("error parsing anchor "+
					"output tapscript sibling: %w", err)
			}

			btcOut := anchorPacket.Outputs[vOut.AnchorOutputIndex]
			if !bytes.Equal(
				btcOut.TaprootInternalKey,
				schnorr.SerializePubKey(
					vOut.AnchorOutputInternalKey,
				),
			) {

				return fmt.Errorf("%w: internal key mismatch",
					ErrInvalidAnchorOutputInfo)
			}

			if !reflect.DeepEqual(
				btcOut.Bip32Derivation,
				vOut.AnchorOutputBip32Derivation,
			) {

				return fmt.Errorf("%w: bip32 derivation "+
					"mismatch", ErrInvalidAnchorOutputInfo)
			}

			if !reflect.DeepEqual(
				btcOut.TaprootBip32Derivation,
				vOut.AnchorOutputTaprootBip32Derivation,
			) {

				return fmt.Errorf("%w: taproot bip32 "+
					"derivation mismatch",
					ErrInvalidAnchorOutputInfo)
			}

			// We also need to check that the asset is either signed
			// or a segregated witness asset (ASSET_VERSION_V1).
			if vOut.Asset == nil {
				return ErrAssetMissing
			}
			if vOut.Asset.Version != asset.V1 {
				witnesses, err := vOut.PrevWitnesses()
				if err != nil {
					return fmt.Errorf("error getting "+
						"witnesses: %w", err)
				}

				if len(witnesses) == 0 {
					return ErrAssetNotSigned
				}

				if len(witnesses[0].TxWitness) == 0 {
					return ErrAssetNotSigned
				}
			}

			// All tests passed so far, we can add the asset to the
			// list of assets for this anchor output.
			outputAssets[vOut.AnchorOutputIndex] = append(
				outputAssets[vOut.AnchorOutputIndex],
				vOut.Asset,
			)
			outputSiblings[vOut.AnchorOutputIndex] = siblingPreimage
			outputAltLeaves[vOut.AnchorOutputIndex] = append(
				outputAltLeaves[vOut.AnchorOutputIndex],
				asset.CopyAltLeaves(vOut.AltLeaves)...,
			)

			// Fetch the tap commitment version from the proof of
			// inclusion for the vOutput.
			commitVersion, err := vOut.TapCommitmentVersion()
			if err != nil {
				return fmt.Errorf("vOut %d: %w", idx, err)
			}

			storedCommitVersion, ok :=
				outputCommitVersions[vOut.AnchorOutputIndex]

			if !ok {
				// The vOutput commitment version must be
				// similar to the vPacket version.
				if !commitment.IsSimilarTapCommitmentVersion(
					pktCommitVersion, commitVersion,
				) {

					log.Tracef("vOut %d commit version "+
						"%v, vPacket version %v", idx,
						commitVersion, pktCommitVersion)

					return fmt.Errorf("vOut commit " +
						"version and vPacket version " +
						"mismatch")
				}

				outputCommitVersions[vOut.AnchorOutputIndex] =
					commitVersion
				continue
			}

			// Commitment versions must be similar for all vOutputs
			// in the same anchor output.
			if !commitment.IsSimilarTapCommitmentVersion(
				storedCommitVersion, commitVersion,
			) {

				log.Tracef("vOut %d commit version %v, prior "+
					"vOut commit version %v", idx,
					commitVersion, pktCommitVersion)

				return fmt.Errorf("mixed vOut commit versions")
			}
		}
	}

	// All output commitments must also have similar versions at this point.
	firstCommitVersion := maps.Values(outputCommitVersions)[0]
	for idx, commitVersion := range outputCommitVersions {
		if !commitment.IsSimilarTapCommitmentVersion(
			firstCommitVersion, commitVersion,
		) {

			log.Tracef("output %d commit version %v, first output "+
				"commit version %v", idx, commitVersion,
				firstCommitVersion)

			return fmt.Errorf("mixed anchor commitment versions")
		}
	}

	// Each output must have a valid set of AltLeaves at this point.
	for anchorIdx, leaves := range outputAltLeaves {
		err := asset.ValidAltLeaves(leaves)
		if err != nil {
			finalErr := fmt.Errorf("output %d invalid alt "+
				"leaves: %w", anchorIdx, err)
			log.Tracef(finalErr.Error())
			return finalErr
		}
	}

	// We can now go through each anchor output that will carry assets and
	// check that we arrive at the correct script.
	for anchorIdx, assets := range outputAssets {
		anchorCommitment, err := commitment.FromAssets(
			outputCommitVersions[anchorIdx], assets...,
		)
		if err != nil {
			return fmt.Errorf("unable to create commitment from "+
				"output assets: %w", err)
		}

		err = anchorCommitment.MergeAltLeaves(
			outputAltLeaves[anchorIdx],
		)
		if err != nil {
			return fmt.Errorf("unable to merge output alt leaves: "+
				"%w", err)
		}

		anchorOut := &anchorPacket.Outputs[anchorIdx]
		anchorTxOut := anchorPacket.UnsignedTx.TxOut[anchorIdx]
		internalKey, err := schnorr.ParsePubKey(
			anchorOut.TaprootInternalKey,
		)
		if err != nil {
			return fmt.Errorf("error parsing anchor output "+
				"internal key: %w", err)
		}

		LogCommitment(
			"Output", int(anchorIdx), anchorCommitment, internalKey,
			nil, nil,
		)

		script, merkleRoot, taprootAssetRoot, err := AnchorOutputScript(
			internalKey, outputSiblings[anchorIdx],
			anchorCommitment,
		)
		if err != nil {
			return fmt.Errorf("unable to create anchor output "+
				"script: %w", err)
		}

		downgradedCommitment, err := anchorCommitment.Downgrade()
		if err != nil {
			return err
		}

		scriptNonV2, _, _, err := AnchorOutputScript(
			internalKey, outputSiblings[anchorIdx],
			downgradedCommitment,
		)

		if err != nil {
			return fmt.Errorf("unable to create V0 anchor output "+
				"script: %w", err)
		}

		// This is the most important check. This ensures that the
		// assets in the outputs of the virtual transactions match
		// exactly the assets that are committed to in the anchor
		// output script.
		if !bytes.Equal(anchorTxOut.PkScript, script) &&
			!bytes.Equal(anchorTxOut.PkScript, scriptNonV2) {

			return fmt.Errorf("%w: anchor output script mismatch "+
				"for anchor output index %d",
				ErrInvalidAnchorOutputInfo, anchorIdx)
		}

		// If we don't need to update the database hints, we can stop
		// here.
		if !updateDatabaseHints {
			continue
		}

		// The caller requested to update the merkle root and Taproot
		// Asset root in the PSBT packet, so we do that now.
		anchorOut.Unknowns = tappsbt.AddCustomField(
			anchorOut.Unknowns,
			tappsbt.PsbtKeyTypeOutputTaprootMerkleRoot,
			merkleRoot[:],
		)
		anchorOut.Unknowns = tappsbt.AddCustomField(
			anchorOut.Unknowns,
			tappsbt.PsbtKeyTypeOutputAssetRoot,
			taprootAssetRoot[:],
		)
	}

	return nil
}

// ValidateAnchorInputs checks that the anchor inputs of the virtual packets
// are valid and consistent with the provided BTC level PSBT packet.
func ValidateAnchorInputs(anchorPacket *psbt.Packet, packets []*tappsbt.VPacket,
	prunedAssets map[wire.OutPoint][]*asset.Asset) error {

	// We first make sure the "static" anchor information in the virtual
	// packets is consistent with the provided BTC level PSBT packet.
	var (
		inputAssets   = make(map[wire.OutPoint][]*asset.Asset)
		inputScripts  = make(map[wire.OutPoint][]byte)
		inputAnchors  = make(map[wire.OutPoint]tappsbt.Anchor)
		inputSiblings = make(
			map[wire.OutPoint]*commitment.TapscriptPreimage,
		)
		inputAltLeaves = make(
			map[wire.OutPoint][]asset.AltLeaf[asset.Asset],
		)
		inputAnchorIndex = make(map[wire.OutPoint]uint32)
	)
	for _, vPkt := range packets {
		for idx := range vPkt.Inputs {
			vIn := vPkt.Inputs[idx]

			outpoint := vIn.PrevID.OutPoint
			if !HasInput(anchorPacket.UnsignedTx, outpoint) {
				return fmt.Errorf("%w: prev ID outpoint %v "+
					"not found in anchor TX",
					ErrInvalidAnchorInputInfo, outpoint)
			}

			// The internal key must be set for each input.
			if vIn.Anchor.InternalKey == nil {
				return fmt.Errorf("%w: internal key missing",
					ErrInvalidAnchorInputInfo)
			}

			var anchorIn *psbt.PInput
			for i, txIn := range anchorPacket.UnsignedTx.TxIn {
				if txIn.PreviousOutPoint == outpoint {
					anchorIn = &anchorPacket.Inputs[i]
					inputAnchorIndex[outpoint] = uint32(i)

					break
				}
			}

			// Shouldn't happen as we validated above, but just in
			// case.
			if anchorIn == nil {
				return fmt.Errorf("%w: input %v not found in "+
					"anchor TX", ErrInvalidAnchorInputInfo,
					outpoint)
			}

			// We can only check if the two internal keys are equal
			// if the transaction isn't signed yet. If it is, then
			// the PSBT library no longer serializes some fields.
			if len(anchorIn.FinalScriptWitness) == 0 {
				// Make sure we can parse the internal key.
				_, err := schnorr.ParsePubKey(
					anchorIn.TaprootInternalKey,
				)
				if err != nil {
					return fmt.Errorf("%w, error parsing "+
						"internal key: %s",
						ErrInvalidAnchorInputInfo,
						err.Error())
				}

				// But only compare the x-coordinate of the
				// actual key.
				if !bytes.Equal(
					anchorIn.TaprootInternalKey,
					schnorr.SerializePubKey(
						vIn.Anchor.InternalKey,
					),
				) {

					return fmt.Errorf("%w: internal key "+
						"mismatch",
						ErrInvalidAnchorInputInfo)
				}
			}

			sibling, _, err := commitment.MaybeDecodeTapscriptPreimage(
				vIn.Anchor.TapscriptSibling,
			)
			if err != nil {
				return fmt.Errorf("%w: error parsing anchor "+
					"input tapscript sibling: %s",
					ErrInvalidAnchorInputInfo, err.Error())
			}

			// The witness UTXO information is also required to get
			// the correct script for the input.
			if anchorIn.WitnessUtxo == nil {
				return fmt.Errorf("%w: witness UTXO missing",
					ErrInvalidAnchorInputInfo)
			}

			// All tests passed so far, we can add the asset to the
			// list of assets for this anchor input.
			inputAssets[outpoint] = append(
				inputAssets[outpoint], vIn.Asset(),
			)
			inputSiblings[outpoint] = sibling
			inputAltLeaves[outpoint] = append(
				inputAltLeaves[outpoint],
				asset.CopyAltLeaves(vIn.AltLeaves)...,
			)
			inputScripts[outpoint] = anchorIn.WitnessUtxo.PkScript
			inputAnchors[outpoint] = vIn.Anchor
		}
	}

	// Add the pruned assets to the input assets, as we know they were
	// originally present in the input commitment.
	for outpoint := range prunedAssets {
		inputAssets[outpoint] = append(
			inputAssets[outpoint], prunedAssets[outpoint]...,
		)
	}

	// Each input must have a valid set of AltLeaves at this point.
	for outpoint, leaves := range inputAltLeaves {
		err := asset.ValidAltLeaves(leaves)
		if err != nil {
			return fmt.Errorf("input %v invalid alt leaves: %w",
				outpoint.String(), err)
		}
	}

	// We can now go through each anchor input that contains assets being
	// spent and check that we arrive at the correct script.
	for anchorOutpoint, assets := range inputAssets {
		anchorCommitment, err := commitment.FromAssets(
			fn.Ptr(commitment.TapCommitmentV2), assets...,
		)
		if err != nil {
			return fmt.Errorf("unable to create commitment from "+
				"output assets: %w", err)
		}

		err = anchorCommitment.MergeAltLeaves(
			inputAltLeaves[anchorOutpoint],
		)
		if err != nil {
			return fmt.Errorf("unable to merge input alt leaves: "+
				"%w", err)
		}

		anchorIdx := inputAnchorIndex[anchorOutpoint]
		anchorIn := inputAnchors[anchorOutpoint]
		internalKey := anchorIn.InternalKey

		LogCommitment(
			"Input", int(anchorIdx), anchorCommitment, internalKey,
			nil, nil,
		)

		script, merkleRoot, _, err := AnchorOutputScript(
			internalKey, inputSiblings[anchorOutpoint],
			anchorCommitment,
		)
		if err != nil {
			return fmt.Errorf("unable to create anchor output "+
				"script: %w", err)
		}

		// This is the most important check. This ensures that the
		// assets in the inputs of the virtual transactions match
		// exactly the assets committed to in the anchor output script
		// that is being spent.
		anchorScript := inputScripts[anchorOutpoint]
		if !bytes.Equal(anchorScript, script) {
			// The commitment may not be V2; let's check against
			// a non-V2 commitment.
			anchorCommitment, err = anchorCommitment.Downgrade()
			if err != nil {
				return err
			}

			script, merkleRoot, _, err = AnchorOutputScript(
				internalKey, inputSiblings[anchorOutpoint],
				anchorCommitment,
			)
			if err != nil {
				return fmt.Errorf("unable to create MarkerV0 "+
					"anchor output script: %w", err)
			}
			if !bytes.Equal(anchorScript, script) {
				// This matches neither version.
				return fmt.Errorf("%w: anchor input script "+
					"mismatch for anchor outpoint %v",
					ErrInvalidAnchorInputInfo,
					anchorOutpoint)
			}
		}

		// The merkle root should also match.
		if !bytes.Equal(anchorIn.MerkleRoot, merkleRoot[:]) {
			return fmt.Errorf("%w: merkle root mismatch for "+
				"anchor outpoint %v", ErrInvalidAnchorInputInfo,
				anchorOutpoint)
		}
	}

	return nil
}
