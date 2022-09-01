package taroscript

import (
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/taro/address"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/commitment"
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

)


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

