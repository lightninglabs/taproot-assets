package commitment

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/mssmt"
)

var (
	// ErrDuplicateSplitOutputIndex is an error returned when duplicate
	// split output indices are detected.
	ErrDuplicateSplitOutputIndex = errors.New(
		"found locator with duplicate output index",
	)

	// ErrInvalidSplitAmount is an error returned when a split amount is
	// invalid (e.g. splits do not fully consume input amount).
	ErrInvalidSplitAmount = errors.New("invalid split amounts")

	// ErrInvalidSplitLocator is returned if a new split is attempted to be
	// created w/o a valid external split locator.
	ErrInvalidSplitLocator = errors.New(
		"at least one locator should be specified",
	)

	// ErrInvalidSplitLocatorCount is returned if a collectible split is
	// attempted with a count of external split locators not equal to one.
	ErrInvalidSplitLocatorCount = errors.New(
		"exactly one locator should be specified",
	)

	// ErrInvalidScriptKey is an error returned when a root locator has zero
	// value but does not use the correct un-spendable script key.
	ErrInvalidScriptKey = errors.New(
		"invalid script key for zero-amount locator",
	)

	// ErrZeroSplitAmount is an error returned when a non-root split locator
	// has zero amount.
	ErrZeroSplitAmount = errors.New(
		"split locator has zero amount",
	)

	// ErrNonZeroSplitAmount is an error returned when a root locator uses
	// an un-spendable script key but has a non-zero amount.
	ErrNonZeroSplitAmount = errors.New(
		"un-spendable root locator has non-zero amount",
	)
)

// SplitLocator encodes the data that uniquely identifies an asset split within
// a split commitment tree.
type SplitLocator struct {
	// OutputIndex is the output index of the on-chain transaction which
	// the asset split was sent to.
	OutputIndex uint32

	// AssetID is the unique ID of the asset.
	AssetID asset.ID

	// ScriptKey is the Taproot tweaked key encoding the different spend
	// conditions possible for the asset split.
	ScriptKey asset.SerializedKey

	// Amount is the amount of units for the asset split.
	Amount uint64

	// AssetVersion is the version that the asset split should use.
	AssetVersion asset.Version
}

// Hash computes the hash of a SplitLocator, encumbering its `OutputIndex`,
// `AssetID` and `ScriptKey`. This hash is used as the key for the asset split
// within a split commitment tree.
func (l SplitLocator) Hash() [sha256.Size]byte {
	h := sha256.New()
	_ = binary.Write(h, binary.BigEndian, l.OutputIndex)
	_, _ = h.Write(l.AssetID[:])
	_, _ = h.Write(l.ScriptKey.SchnorrSerialized())
	return *(*[sha256.Size]byte)(h.Sum(nil))
}

// SplitAsset is an asset resulting from a split. This is the same as the
// underlying asset, except it also encodes its `OutputIndex`.
type SplitAsset struct {
	asset.Asset

	// OutputIndex is the index of the on-chain transaction that held the
	// split asset at the time of its creation.
	OutputIndex uint32
}

// InputSet represents the set of inputs for a given asset indexed by their
// `PrevID`.
type InputSet map[asset.PrevID]*asset.Asset

// SplitSet is a type to represent a set of asset splits.
type SplitSet map[SplitLocator]*SplitAsset

// SplitCommitment encodes all of the data necessary to generate and validate a
// set of asset splits from its root.
type SplitCommitment struct {
	// PrevAssets is the set of asset inputs being split.
	PrevAssets InputSet

	// RootAsset is the root asset resulting after the creation of split
	// assets containing the SplitCommitmentRoot.
	RootAsset *asset.Asset

	// SplitAssets is the set of asset splits within the on-chain
	// transaction committed to within the split commitment MS-SMT.
	SplitAssets SplitSet

	// tree is the MS-SMT committing to all of the asset splits above.
	tree mssmt.Tree
}

// SplitCommitmentInput holds input asset specific data used in constructing a
// new split commitment.
type SplitCommitmentInput struct {
	// Asset is the input asset.
	Asset *asset.Asset

	// OutPoint is the input asset's on-chain outpoint.
	OutPoint wire.OutPoint
}

// NewSplitCommitment computes a new SplitCommitment based on the given input
// assets. It creates a set of asset splits uniquely identified by their
// `locators`. The resulting asset splits are committed to a MS-SMT and its root
// is placed within the root asset, which should have a signature over the split
// state transition to authenticate the transfer. This signature on the root
// asset needs to be provided after the fact. The rootLocator field is
// considered to be the "change" output in the transfer: this is the location
// where all the other splits (elsewhere in the transaction are committed to).
func NewSplitCommitment(ctx context.Context, inputs []SplitCommitmentInput,
	rootLocator *SplitLocator,
	externalLocators ...*SplitLocator) (*SplitCommitment, error) {

	// Calculate sum total input amounts.
	totalInputAmount := uint64(0)
	for idx := range inputs {
		input := inputs[idx]
		totalInputAmount += input.Asset.Amount
	}

	assetType := inputs[0].Asset.Type

	// The assets need to go somewhere, they can be fully spent, but we
	// still require this external locator to denote where the new value
	// lives.
	if len(externalLocators) == 0 {
		return nil, ErrInvalidSplitLocator
	}

	// To transfer a collectible with a split, the split root must be
	// un-spendable, and there can only be one external locator.
	if assetType == asset.Collectible {
		if rootLocator.Amount != 0 {
			return nil, ErrNonZeroSplitAmount
		}

		if len(externalLocators) != 1 {
			return nil, ErrInvalidSplitLocatorCount
		}
	}

	// The only valid un-spendable root locator uses the correct
	// un-spendable script key and has zero value.
	if rootLocator.Amount == 0 &&
		rootLocator.ScriptKey != asset.NUMSCompressedKey {

		return nil, ErrInvalidScriptKey
	}

	if rootLocator.Amount != 0 &&
		rootLocator.ScriptKey == asset.NUMSCompressedKey {

		return nil, ErrNonZeroSplitAmount
	}

	// Map each SplitLocator to an asset split, making sure to decrement
	// each split's amount from the asset input to ensure we fully consume
	// the total input amount.
	locators := append(externalLocators, rootLocator)
	splitAssets := make(SplitSet, len(locators))
	splitTree := mssmt.NewCompactedTree(mssmt.NewDefaultStore())
	remainingAmount := totalInputAmount
	rootIdx := len(locators) - 1
	addAssetSplit := func(locator *SplitLocator) error {
		assetSplit := inputs[0].Asset.Copy()
		assetSplit.Amount = locator.Amount
		assetSplit.Version = locator.AssetVersion

		scriptKey, err := btcec.ParsePubKey(locator.ScriptKey[:])
		if err != nil {
			return err
		}
		assetSplit.ScriptKey = asset.NewScriptKey(scriptKey)
		assetSplit.PrevWitnesses = []asset.Witness{{
			PrevID:          &asset.ZeroPrevID,
			TxWitness:       nil,
			SplitCommitment: nil,
		}}
		assetSplit.SplitCommitmentRoot = nil

		splitAssets[*locator] = &SplitAsset{
			Asset:       *assetSplit,
			OutputIndex: locator.OutputIndex,
		}

		splitKey := locator.Hash()
		splitLeaf, err := assetSplit.Leaf()
		if err != nil {
			return err
		}

		_, err = splitTree.Insert(ctx, splitKey, splitLeaf)
		if err != nil {
			return err
		}

		// Ensure that we won't underflow the remaining amount. None of
		// the split amounts should be greater than the input amount.
		if remainingAmount < locator.Amount {
			return ErrInvalidSplitAmount
		}
		remainingAmount -= locator.Amount

		return nil
	}
	for idx := range locators {
		locator := locators[idx]
		if idx != rootIdx && locator.Amount == 0 {
			return nil, ErrZeroSplitAmount
		}

		if err := addAssetSplit(locator); err != nil {
			return nil, err
		}
	}
	if remainingAmount != 0 {
		return nil, ErrInvalidSplitAmount
	}

	// With all the split assets created and inserted into the split
	// commitment tree, we'll create the root asset. This root asset
	// commits to the root of the split commitment tree and should have a
	// valid witness generated over the virtual transaction enabling the
	// state transition.
	var err error
	rootAsset := splitAssets[*rootLocator].Copy()

	// Construct input set and set root asset previous witnesses.
	inputSet := make(InputSet)
	rootAsset.PrevWitnesses = make([]asset.Witness, len(inputs))

	for idx := range inputs {
		input := inputs[idx]
		inAsset := input.Asset
		prevID := &asset.PrevID{
			OutPoint:  input.OutPoint,
			ID:        inAsset.Genesis.ID(),
			ScriptKey: asset.ToSerialized(inAsset.ScriptKey.PubKey),
		}
		inputSet[*prevID] = inAsset

		rootAsset.PrevWitnesses[idx].PrevID = prevID
	}

	rootAsset.SplitCommitmentRoot, err = splitTree.Root(context.TODO())
	if err != nil {
		return nil, err
	}

	// We'll also update each asset split with it's split commitment proof.
	for idx := range locators {
		locator := locators[idx]

		proof, err := splitTree.MerkleProof(ctx, locator.Hash())
		if err != nil {
			return nil, err
		}

		prevWitnesses := splitAssets[*locator].PrevWitnesses
		prevWitnesses[0].SplitCommitment = &asset.SplitCommitment{
			Proof:     *proof,
			RootAsset: *rootAsset,
		}
	}

	return &SplitCommitment{
		PrevAssets:  inputSet,
		RootAsset:   rootAsset,
		SplitAssets: splitAssets,
		tree:        splitTree,
	}, nil
}
