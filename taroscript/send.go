package taroscript

import (
	"errors"
	"sort"

	"github.com/btcsuite/btcd/btcec/v2"
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

// SpendLocators stores a split locators for each receiver, keyed by their
// AssetCommitmentKey. These locators are used to create split commitments and
// the final PSBT for the transfer. AssetCommitmentKeys are unique to each asset
// and each receiver due to the inclusion of the receiver's ScriptKey.
type SpendLocators = map[[32]byte]commitment.SplitLocator

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

