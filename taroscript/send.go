package taroscript

import (
	"errors"
	"sort"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taro/address"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/commitment"
	"golang.org/x/exp/maps"
)

var (
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

)

// SpendDelta stores the information needed to prepare new asset leaves or a
// split commitment, and validated a spend with the Taro VM. SpendDelta is also
// used to create the final TaroCommitments for each receiver.
type SpendDelta struct {
	// NewAsset is the Asset that will be validated by the Taro VM.
	// In the case of an asset split, it is the root locator that also
	// contains the split commitment. Otherwise, it is the asset that will
	// be sent to the receiver.
	NewAsset asset.Asset

	// InputAssets maps asset PrevIDs to Assets being spent by the sender.
	InputAssets commitment.InputSet

	// Locators maps AssetCommitmentKeys for all receivers to splitLocators.
	// The locators are used to create split commitments, and store indexes
	// for each receiver's corresponding Bitcoin output.
	Locators SpendLocators

	// SplitCommitment contains all data needed to validate and commit to an
	// asset split.

	// NOTE: This is nil unless the InputAsset is being split.
	SplitCommitment *commitment.SplitCommitment
}

// SpendLocators stores a split locators for each receiver, keyed by their
// AssetCommitmentKey. These locators are used to create split commitments and
// the final PSBT for the transfer. AssetCommitmentKeys are unique to each asset
// and each receiver due to the inclusion of the receiver's ScriptKey.
type SpendLocators = map[[32]byte]commitment.SplitLocator

// Copy returns a deep copy of a SpendDelta.
func (s *SpendDelta) Copy() SpendDelta {
	// Copy the fields that are not maps directly; the other fields must
	// maintain their nil-ness, and therefore require an extra check.
	newDelta := SpendDelta{
		NewAsset:        *s.NewAsset.Copy(),
		SplitCommitment: s.SplitCommitment,
	}

	if s.InputAssets != nil {
		inputAssets := make(commitment.InputSet)
		maps.Copy(inputAssets, s.InputAssets)
		newDelta.InputAssets = inputAssets
	}

	if s.Locators != nil {
		locators := make(SpendLocators)
		maps.Copy(locators, s.Locators)
		newDelta.Locators = locators
	}

	return newDelta
}

// createDummyLocators creates a set of split locators with continuous output
// indexes, starting for 0. These mock locators are used for initial split
// commitment validation, and are the default for the final PSBT.
func createDummyLocators(stateKeys [][32]byte) SpendLocators {
	locators := make(SpendLocators)
	for i := uint32(0); i < uint32(len(stateKeys)); i++ {
		index := i
		locators[stateKeys[i]] = commitment.SplitLocator{
			OutputIndex: index,
		}
	}
	return locators
}

// areValidIndexes checks a set of split locators to check for the minimum
// number of locators, and tests if the locators could be used for a Taro-only
// spend, i.e. a TX that does not need other outputs added to be valid.
func areValidIndexes(locators SpendLocators) (bool, error) {
	// Sanity check the output indexes provided by the sender. There must be
	// at least two indexes; one for the receiver, and one for the change
	// commitment for the sender.
	idxCount := len(locators)
	if idxCount < 2 {
		return false, ErrInvalidOutputIndexes
	}

	// If the indexes start from 0 and form a continuous range, then the
	// resulting TX would be valid without any changes (Taro-only spend).
	taroOnlySpend := true
	txoLocators := maps.Values(locators)
	sort.Slice(txoLocators, func(i, j int) bool {
		return txoLocators[i].OutputIndex < txoLocators[j].OutputIndex
	})
	for i := uint32(0); i < uint32(idxCount); i++ {
		if txoLocators[i].OutputIndex != i {
			taroOnlySpend = false
			break
		}
	}

	return taroOnlySpend, nil
}

// isValidInput verifies that the Taro commitment of the input contains an
// asset that could be spent to the given Taro address.
func isValidInput(input commitment.TaroCommitment,
	addr address.Taro, inputScriptKey btcec.PublicKey,
	net address.ChainParams) (*asset.Asset, bool, error) {

	needsSplit := false

	// The input and address networks must match.
	if !address.IsForNet(addr.ChainParams.TaroHRP, &net) {
		return nil, needsSplit, address.ErrMismatchedHRP
	}

	// The top-level Taro tree must have a non-empty asset tree at the leaf
	// specified in the address.
	inputCommitments := input.Commitments()
	assetCommitment, ok := inputCommitments[addr.TaroCommitmentKey()]
	if !ok {
		return nil, needsSplit, ErrMissingInputAsset
	}

	// The asset tree must have a non-empty Asset at the location
	// specified by the sender's script key.
	assetCommitmentKey := asset.AssetCommitmentKey(
		addr.ID, &inputScriptKey, addr.FamilyKey == nil,
	)
	inputAsset, _, err := assetCommitment.AssetProof(assetCommitmentKey)
	if err != nil {
		return nil, needsSplit, err
	}

	if inputAsset == nil {
		return nil, needsSplit, ErrMissingInputAsset
	}

	// For Normal assets, we also check that the input asset amount is
	// at least as large as the amount specified in the address.
	// If the input amount exceeds the amount specified in the address,
	// the spend will require an asset split.
	if inputAsset.Type == asset.Normal {
		if inputAsset.Amount < addr.Amount {
			return nil, needsSplit, ErrInsufficientInputAsset
		}
		if inputAsset.Amount > addr.Amount {
			needsSplit = true
		}
	}

	return inputAsset, needsSplit, nil
}

// TODO(jhb): This assumes only 2 split outputs / 1 receiver; needs update
// to support multiple receivers.
// prepareAssetSplitSpend computes a split commitment with the given input and
// spend information. Input MUST be checked as valid beforehand, and locators
// MUST be checked for validity beforehand if provided.
func prepareAssetSplitSpend(addr address.Taro, prevInput asset.PrevID,
	scriptKey btcec.PublicKey, delta SpendDelta) (*SpendDelta, error) {

	updatedDelta := delta.Copy()

	// Generate the keys used to look up split locators for each receiver.
	senderStateKey := asset.AssetCommitmentKey(
		addr.ID, &scriptKey, addr.FamilyKey == nil,
	)
	receiverStateKey := addr.AssetCommitmentKey()

	// TODO(jhb): Handle change of 0 amount / splits with no change.
	// If no locators are provided, we create a split with mock locators
	// to verify that the desired split is possible. We can later regenerate
	// a split with the final output indexes.
	if updatedDelta.Locators == nil {
		updatedDelta.Locators = createDummyLocators(
			[][32]byte{senderStateKey, receiverStateKey},
		)
	}

	senderLocator := updatedDelta.Locators[senderStateKey]
	receiverLocator := updatedDelta.Locators[receiverStateKey]

	inputAsset := updatedDelta.InputAssets[prevInput]

	// Populate the remaining fields in the splitLocators before generating
	// the splitCommitment.
	senderLocator.AssetID = addr.ID
	senderLocator.ScriptKey = scriptKey
	senderLocator.Amount = inputAsset.Amount - addr.Amount
	updatedDelta.Locators[senderStateKey] = senderLocator

	receiverLocator.AssetID = addr.ID
	receiverLocator.ScriptKey = addr.ScriptKey
	receiverLocator.Amount = addr.Amount
	updatedDelta.Locators[receiverStateKey] = receiverLocator

	splitCommitment, err := commitment.NewSplitCommitment(
		inputAsset, prevInput.OutPoint,
		&senderLocator, &receiverLocator,
	)
	if err != nil {
		return nil, err
	}

	updatedDelta.NewAsset = *splitCommitment.RootAsset
	updatedDelta.InputAssets = splitCommitment.PrevAssets
	updatedDelta.SplitCommitment = splitCommitment

	return &updatedDelta, nil
}

// prepareAssetCompleteSpend computes a new asset leaf for spends that
// fully consume the input, i.e. collectibles or an equal-valued send. Input
// MUST be checked as valid beforehand.
func prepareAssetCompleteSpend(addr address.Taro, prevInput asset.PrevID,
	delta SpendDelta) *SpendDelta {

	updatedDelta := delta.Copy()

	newAsset := updatedDelta.InputAssets[prevInput].Copy()
	newAsset.ScriptKey.PubKey = &addr.ScriptKey

	// Record the PrevID of the input asset in a Witness for the new asset.
	// This Witness still needs a valid signature for the new asset
	// to be valid.
	newAsset.PrevWitnesses = []asset.Witness{
		{
			PrevID:          &prevInput,
			TxWitness:       nil,
			SplitCommitment: nil,
		},
	}

	updatedDelta.NewAsset = *newAsset

	return &updatedDelta
}

