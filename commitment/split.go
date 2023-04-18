package commitment

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/mssmt"
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

// NewSplitCommitment computes a new SplitCommitment based on the given asset
// input creating a set of asset splits uniquely identified by their `locators`.
// The resulting asset splits are committed to within a MS-SMT and its root is
// placed within the root asset, which should have a signature over the split
// state transition to authenticate the transfer. This signature on the root
// asset needs to be provided after the fact. The rootLocator field is
// considered to be the "change" output in the transfer: this is the location
// where all the other splits (elsewhere in the transaction are committed to).
//
// TODO: Is it allowed to merge several assets to create a split within a single
// state transition? Imagine 3 separate UTXOs containing 5 USD each and merged
// to create a split payment of 7 USD in one UTXO for the recipient and a change
// UTXO of 8 USD.
func NewSplitCommitment(input *asset.Asset, outPoint wire.OutPoint,
	rootLocator *SplitLocator, externalLocators ...*SplitLocator) (
	*SplitCommitment, error) {

	prevID := &asset.PrevID{
		OutPoint:  outPoint,
		ID:        input.Genesis.ID(),
		ScriptKey: asset.ToSerialized(input.ScriptKey.PubKey),
	}

	// The assets need to go somewhere, they can be fully spent, but we
	// still require this external locator to denote where the new value
	// lives.
	if len(externalLocators) == 0 {
		return nil, ErrInvalidSplitLocator
	}

	// To transfer a collectible with a split, the split root must be
	// un-spendable, and there can only be one external locator.
	if input.Type == asset.Collectible {
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
	locatorOutputs := make(map[uint32]struct{}, len(locators))
	splitAssets := make(SplitSet, len(locators))
	splitTree := mssmt.NewCompactedTree(mssmt.NewDefaultStore())
	remainingAmount := input.Amount
	rootIdx := len(locators) - 1
	addAssetSplit := func(locator *SplitLocator) error {
		// Return an error if we've already seen a locator with this
		// output index.
		//
		// TODO(roasbeef): is there any reason to allow the external
		// split to map to a series of internal splits? so you split
		// into more UTXOs within the tree
		if _, ok := locatorOutputs[locator.OutputIndex]; ok {
			return ErrDuplicateSplitOutputIndex
		}

		assetSplit := input.Copy()
		assetSplit.Amount = locator.Amount

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

		locatorOutputs[locator.OutputIndex] = struct{}{}

		splitAssets[*locator] = &SplitAsset{
			Asset:       *assetSplit,
			OutputIndex: locator.OutputIndex,
		}

		splitKey := locator.Hash()
		splitLeaf, err := assetSplit.Leaf()
		if err != nil {
			return err
		}

		// TODO(bhandras): thread the context through.
		_, err = splitTree.Insert(context.TODO(), splitKey, splitLeaf)
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
	for idx, locator := range locators {
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
	rootAsset.PrevWitnesses[0].PrevID = prevID
	rootAsset.SplitCommitmentRoot, err = splitTree.Root(context.TODO())
	if err != nil {
		return nil, err
	}

	// We'll also update each asset split with it's split commitment proof.
	for _, locator := range locators {
		// TODO(bhandras): thread the context through.
		proof, err := splitTree.MerkleProof(
			context.TODO(), locator.Hash(),
		)
		if err != nil {
			return nil, err
		}

		splitAssets[*locator].PrevWitnesses[0].SplitCommitment =
			&asset.SplitCommitment{
				Proof:     *proof,
				RootAsset: *rootAsset,
			}
	}

	return &SplitCommitment{
		PrevAssets:  InputSet{*prevID: input},
		RootAsset:   rootAsset,
		SplitAssets: splitAssets,
		tree:        splitTree,
	}, nil
}
