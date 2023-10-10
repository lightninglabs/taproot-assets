package commitment

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"golang.org/x/exp/maps"
)

var (
	// ErrNoAssets is an error returned when we attempt to instantiate a new
	// AssetCommitment without any assets.
	ErrNoAssets = errors.New("asset commitment: no assets provided")

	// ErrAssetGenesisMismatch is an error returned when we attempt to
	// create a new asset commitment and two assets disagree on their
	// genesis.
	ErrAssetGenesisMismatch = errors.New(
		"asset commitment: genesis mismatch",
	)

	// ErrAssetTypeMismatch is an error returned when we attempt to insert
	// an asset into an asset commitment and the asset type does not match
	// the assets stored in the commitment.
	ErrAssetTypeMismatch = errors.New(
		"asset commitment: asset type mismatch",
	)

	// ErrAssetGroupKeyMismatch is an error returned when we attempt to
	// create a new asset commitment and two assets disagree on their
	// group key.
	ErrAssetGroupKeyMismatch = errors.New(
		"asset commitment: group key mismatch",
	)

	// ErrAssetDuplicateScriptKey is an error returned when we attempt to
	// create a new asset commitment that would include two assets with the
	// same script key.
	ErrAssetDuplicateScriptKey = errors.New(
		"asset commitment: duplicate script key",
	)
)

// CommittedAssets is the set of Assets backing an AssetCommitment.
// The map is keyed by the Asset's AssetCommitmentKey.
type CommittedAssets map[[32]byte]*asset.Asset

// AssetCommitment represents the inner MS-SMT within the Taproot Asset protocol
// committing to a set of assets under the same ID/group. Assets within this
// tree, which are leaves represented as the serialized asset TLV payload, are
// keyed by their `asset_script_key`.
type AssetCommitment struct {
	// Version is the max version of the assets committed.
	Version asset.Version

	// TapKey is the common identifier for all assets found within the
	// AssetCommitment. This can either be an asset.ID, which every
	// committed asset must match, or the hash of an asset.GroupKey which
	// every committed asset must match if their asset.ID differs.
	TapKey [32]byte

	// AssetType is the type of asset(s) committed to within the tree.
	AssetType asset.Type

	// TreeRoot is the root node of the MS-SMT containing all of the
	// committed assets.
	TreeRoot *mssmt.BranchNode

	// tree is the underlying MS-SMT containing all of the committed assets.
	//
	// NOTE: This is nil unless AssetCommitment is constructed with
	// NewAssetCommitment.
	tree mssmt.Tree

	// assets is the set of assets committed to within the tree above.
	//
	// NOTE: This is nil unless AssetCommitment is constructed with
	// NewAssetCommitment.
	assets CommittedAssets
}

// parseCommon extracts the common fixed parameters of a set of assets to
// include in the returned commitment.
func parseCommon(assets ...*asset.Asset) (*AssetCommitment, error) {
	if len(assets) == 0 {
		return nil, ErrNoAssets
	}

	var (
		assetType        asset.Type
		tapCommitmentKey [32]byte
		maxVersion       = asset.Version(0)
		firstAssetID     = assets[0].Genesis.ID()
		assetGroupKey    = assets[0].GroupKey
		assetsMap        = make(CommittedAssets, len(assets))
	)
	for idx, newAsset := range assets {
		// Inspect the first asset to note properties which should be
		// consistent across all assets.
		if idx == 0 {
			// Set the asset type from the first asset.
			assetType = newAsset.Type

			// Set the expected tapCommitmentKey from the first
			// asset.
			tapCommitmentKey = newAsset.TapCommitmentKey()
		}

		// Return error if the asset type doesn't match the previously
		// encountered asset types.
		if assetType != newAsset.Type {
			return nil, ErrAssetTypeMismatch
		}

		switch {
		case !assetGroupKey.IsEqualGroup(newAsset.GroupKey):
			return nil, ErrAssetGroupKeyMismatch

		case assetGroupKey == nil:
			if firstAssetID != newAsset.Genesis.ID() {
				return nil, ErrAssetGenesisMismatch
			}
		}

		// Return error if the asset's tap commitment key doesn't match
		// the previously encountered key.
		//
		// NOTE: This sanity check executes after the group key check
		// because it is a less specific check.
		if tapCommitmentKey != newAsset.TapCommitmentKey() {
			return nil, fmt.Errorf("inconsistent asset " +
				"TapCommitmentKey")
		}

		key := newAsset.AssetCommitmentKey()
		if _, ok := assetsMap[key]; ok {
			return nil, fmt.Errorf("%w: %x",
				ErrAssetDuplicateScriptKey, key[:])
		}
		if newAsset.Version > maxVersion {
			maxVersion = newAsset.Version
		}
		assetsMap[key] = newAsset
	}

	var groupPubKey *btcec.PublicKey
	if assetGroupKey != nil {
		groupPubKey = &assetGroupKey.GroupPubKey
	}

	// The tapKey here is what will be used to place this asset commitment
	// into the top-level Taproot Asset commitment. For assets without a
	// group key, then this will be the normal asset ID. Otherwise, this'll
	// be the sha256 of the group key.
	tapKey := asset.TapCommitmentKey(firstAssetID, groupPubKey)

	return &AssetCommitment{
		Version:   maxVersion,
		TapKey:    tapKey,
		AssetType: assetType,
		assets:    assetsMap,
	}, nil
}

// NewAssetCommitment constructs a new commitment for the given assets capable
// of computing merkle proofs. All assets provided should be related, i.e.,
// their `ID` or `GroupKey` should match.
func NewAssetCommitment(assets ...*asset.Asset) (*AssetCommitment, error) {
	commitment, err := parseCommon(assets...)
	if err != nil {
		return nil, err
	}

	tree := mssmt.NewCompactedTree(mssmt.NewDefaultStore())
	for _, newAsset := range assets {
		key := newAsset.AssetCommitmentKey()
		leaf, err := newAsset.Leaf()
		if err != nil {
			return nil, err
		}

		// TODO(bhandras): thread the context through.
		_, err = tree.Insert(context.TODO(), key, leaf)
		if err != nil {
			return nil, err
		}
	}

	commitment.TreeRoot, err = tree.Root(context.TODO())
	if err != nil {
		return nil, err
	}

	commitment.tree = tree
	return commitment, nil
}

// Upsert modifies one entry in the AssetCommitment by inserting (or updating)
// it in the inner MS-SMT and adding (or updating) it in the internal asset map.
func (c *AssetCommitment) Upsert(newAsset *asset.Asset) error {
	if newAsset == nil {
		return ErrNoAssets
	}

	// Sanity check the asset type of the given asset. This check ensures
	// that all assets committed to within the tree are of the same type.
	if c.AssetType != newAsset.Type {
		return ErrAssetTypeMismatch
	}

	// The given Asset must have an ID that matches the AssetCommitment ID.
	// The AssetCommitment ID is either a hash of the groupKey, or the ID
	// of all the assets in the AssetCommitment.
	if newAsset.TapCommitmentKey() != c.TapKey {
		if newAsset.GroupKey != nil {
			return ErrAssetGroupKeyMismatch
		}
		return ErrAssetGenesisMismatch
	}

	key := newAsset.AssetCommitmentKey()

	// TODO(bhandras): thread the context through.
	ctx := context.TODO()

	leaf, err := newAsset.Leaf()
	if err != nil {
		return err
	}

	_, err = c.tree.Insert(ctx, key, leaf)
	if err != nil {
		return err
	}

	c.TreeRoot, err = c.tree.Root(ctx)
	if err != nil {
		return err
	}

	c.assets[key] = newAsset

	// As a final step, we'll update the version of this commitment based
	// on the new asset.
	if newAsset.Version > c.Version {
		c.Version = newAsset.Version
	}

	return nil
}

// Delete modifies one entry in the AssetCommitment by deleting it in the inner
// MS-SMT and deleting it in the internal asset map.
func (c *AssetCommitment) Delete(oldAsset *asset.Asset) error {
	if oldAsset == nil {
		return ErrNoAssets
	}

	// The given Asset must have an ID that matches the AssetCommitment ID.
	// The AssetCommitment ID is either a hash of the groupKey, or the ID
	// of all the assets in the AssetCommitment.
	if oldAsset.TapCommitmentKey() != c.TapKey {
		if oldAsset.GroupKey != nil {
			return ErrAssetGroupKeyMismatch
		}
		return ErrAssetGenesisMismatch
	}

	// Ensure the given asset is of the expected type.
	if c.AssetType != oldAsset.Type {
		return ErrAssetTypeMismatch
	}

	key := oldAsset.AssetCommitmentKey()

	// TODO(bhandras): thread the context through.
	ctx := context.TODO()

	_, err := c.tree.Delete(ctx, key)
	if err != nil {
		return err
	}

	c.TreeRoot, err = c.tree.Root(ctx)
	if err != nil {
		return err
	}

	delete(c.assets, key)

	// Now that we've deleted the asset, we need to update the version of
	// this commitment.
	assets := maps.Values(c.assets)
	versions := fn.Map(assets, func(a *asset.Asset) asset.Version {
		return a.Version
	})
	c.Version = fn.Reduce(versions, func(a, b asset.Version) asset.Version {
		if a > b {
			return a
		}
		return b
	})

	return nil
}

// Root computes the root identifier required to commit to this specific asset
// commitment within the outer commitment, also known as the Taproot Asset
// commitment.
func (c *AssetCommitment) Root() [sha256.Size]byte {
	left := c.TreeRoot.Left.NodeHash()
	right := c.TreeRoot.Right.NodeHash()

	h := sha256.New()
	_, _ = h.Write(c.TapKey[:])
	_, _ = h.Write(left[:])
	_, _ = h.Write(right[:])
	_ = binary.Write(h, binary.BigEndian, c.TreeRoot.NodeSum())
	return *(*[sha256.Size]byte)(h.Sum(nil))
}

// TapCommitmentKey computes the insertion key for this specific asset
// commitment to include in the Taproot Asset commitment MS-SMT.
func (c *AssetCommitment) TapCommitmentKey() [32]byte {
	return c.TapKey
}

// TapCommitmentLeaf computes the leaf node for this specific asset commitment
// to include in the Taproot Asset commitment MS-SMT.
func (c *AssetCommitment) TapCommitmentLeaf() *mssmt.LeafNode {
	root := c.Root()
	sum := c.TreeRoot.NodeSum()

	var leaf bytes.Buffer
	_, _ = leaf.Write([]byte{byte(c.Version)})
	_, _ = leaf.Write(root[:])
	_ = binary.Write(&leaf, binary.BigEndian, sum)
	return mssmt.NewLeafNode(leaf.Bytes(), sum)
}

// AssetProof computes the AssetCommitment merkle proof for the asset leaf
// located at `key`. A `nil` asset is returned if the asset is not committed to.
func (c *AssetCommitment) AssetProof(key [32]byte) (
	*asset.Asset, *mssmt.Proof, error) {

	if c.tree == nil {
		return nil, nil, fmt.Errorf("missing tree to compute proofs")
	}

	// TODO(bhandras): thread the context through.
	proof, err := c.tree.MerkleProof(context.TODO(), key)
	if err != nil {
		return nil, nil, err
	}

	return c.assets[key], proof, nil
}

// Assets returns the set of assets committed to in the asset commitment.
func (c *AssetCommitment) Assets() CommittedAssets {
	assets := make(CommittedAssets, len(c.assets))
	maps.Copy(assets, c.assets)

	return assets
}

// Asset returns the committed asset specified by the given asset commitment
// key. If the asset is not present, the second result OK parameter is false.
func (c *AssetCommitment) Asset(key [32]byte) (*asset.Asset, bool) {
	a := c.assets[key]
	ok := a != nil
	return a, ok
}

// Copy returns a deep copy of tha target AssetCommitment.
func (c *AssetCommitment) Copy() (*AssetCommitment, error) {
	// If there're no assets in this commitment, then we can simply return
	// a blank asset commitment.
	if len(c.assets) == 0 {
		treeRoot := c.TreeRoot.Copy().(*mssmt.BranchNode)
		return &AssetCommitment{
			Version:  c.Version,
			TapKey:   c.TapKey,
			TreeRoot: treeRoot,
		}, nil
	}

	// First, we'll perform a deep copy of all the assets that this existing
	// commitment is committing to.
	newAssets := fn.CopyAll(maps.Values(c.Assets()))

	// Now that we have a deep copy of all the assets, we can just create a
	// brand-new commitment from the set of assets.
	return NewAssetCommitment(newAssets...)
}

// Merge merges the other commitment into this commitment. If the other
// commitment is empty, then this is a no-op. If the other commitment was
// not constructed with NewAssetCommitment, then an error is returned.
func (c *AssetCommitment) Merge(other *AssetCommitment) error {
	// Ensure that the given asset commitment commits assets of the expected
	// type.
	if c.AssetType != other.AssetType {
		return ErrAssetTypeMismatch
	}

	// If this was not constructed with NewAssetCommitment then we can't
	// merge as we don't have the assets available.
	if other.assets == nil {
		return fmt.Errorf("cannot merge commitments without assets")
	}

	// If the other commitment is empty, then we can just exit early.
	if len(other.assets) == 0 {
		return nil
	}

	// Otherwise, we'll need to merge the other asset commitments into
	// this commitment.
	for _, otherCommitment := range other.assets {
		if err := c.Upsert(otherCommitment.Copy()); err != nil {
			return fmt.Errorf("error upserting other commitment: "+
				"%w", err)
		}
	}

	return nil
}
