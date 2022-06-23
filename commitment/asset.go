package commitment

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/mssmt"
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

	// ErrAssetFamilyKeyMismatch is an error returned when we attempt to
	// create a new asset commitment and two assets disagree on their
	// family key.
	ErrAssetFamilyKeyMismatch = errors.New(
		"asset commitment: family key mismatch",
	)

	// ErrAssetDuplicateScriptKey is an error returned when we attempt to
	// create a new asset commitment that would include two assets with the
	// same script key.
	ErrAssetDuplicateScriptKey = errors.New(
		"asset commitment: duplicate script key",
	)
)

// AssetCommitment represents the inner MS-SMT within the Taro protocol
// committing to a set of assets under the same ID/family. Assets within this
// tree, which are leaves represented as the serialized asset TLV payload, are
// keyed by their `asset_script_key`.
type AssetCommitment struct {
	// Version is the max version of the assets committed.
	Version asset.Version

	// AssetID is the common identifier for all assets found within the
	// AssetCommitment. This can either be an asset.ID, which every
	// committed asset must match, or the hash of an asset.FamilyKey which
	// every committed asset must match if their asset.ID differs.
	AssetID [32]byte

	// TreeRoot is the root node of the MS-SMT containing all of the
	// committed assets.
	TreeRoot *mssmt.BranchNode

	// tree is the underlying MS-SMT containing all of the committed assets.
	//
	// NOTE: This is nil unless AssetCommitment is constructed with
	// NewAssetCommitment.
	tree *mssmt.Tree

	// assets is the set of assets committed to within the tree above.
	//
	// NOTE: This is nil unless AssetCommitment is constructed with
	// NewAssetCommitment.
	assets map[[32]byte]*asset.Asset
}

// parseCommon extracts the common fixed parameters of a set of assets to
// include in the returned commitment.
func parseCommon(assets ...*asset.Asset) (*AssetCommitment, error) {
	if len(assets) == 0 {
		return nil, ErrNoAssets
	}

	maxVersion := asset.Version(0)
	assetGenesis := assets[0].Genesis.ID()
	assetFamilyKey := assets[0].FamilyKey
	assetsMap := make(map[[32]byte]*asset.Asset, len(assets))
	for _, asset := range assets {
		if assetFamilyKey != asset.FamilyKey {
			return nil, ErrAssetFamilyKeyMismatch
		}
		if assetFamilyKey == nil && assetGenesis != asset.Genesis.ID() {
			return nil, ErrAssetGenesisMismatch
		}
		key := asset.AssetCommitmentKey()
		if _, ok := assetsMap[key]; ok {
			return nil, ErrAssetDuplicateScriptKey
		}
		if asset.Version > maxVersion {
			maxVersion = asset.Version
		}
		assetsMap[key] = asset
	}

	// The assetID here is what will be used to place this asset commitment
	// into the top-level Taro commitment. For assets without a family key,
	// then this will be the normal asset ID. Otherwise, this'll be the
	// sha256 of the family key.
	var assetID [32]byte
	if assetFamilyKey == nil {
		assetID = assetGenesis
	} else {
		assetID = sha256.Sum256(
			schnorr.SerializePubKey(&assetFamilyKey.Key),
		)
	}

	return &AssetCommitment{
		Version: maxVersion,
		AssetID: assetID,
		assets:  assetsMap,
	}, nil
}

// NewAssetCommitment constructs a new commitment for the given assets capable
// of computing merkle proofs. All assets provided should be related, i.e.,
// their `ID` or `FamilyKey` should match.
func NewAssetCommitment(assets ...*asset.Asset) (*AssetCommitment, error) {
	commitment, err := parseCommon(assets...)
	if err != nil {
		return nil, err
	}

	tree := mssmt.NewTree(mssmt.NewDefaultStore())
	for _, asset := range assets {
		key := asset.AssetCommitmentKey()
		leaf, err := asset.Leaf()
		if err != nil {
			return nil, err
		}
		tree.Insert(key, leaf)
	}

	commitment.TreeRoot = tree.Root()
	commitment.tree = tree
	return commitment, nil
}

// Root computes the root identifier required to commit to this specific asset
// commitment within the outer commitment, also known as the Taro commitment.
func (c AssetCommitment) Root() [sha256.Size]byte {
	left := c.TreeRoot.Left.NodeKey()
	right := c.TreeRoot.Right.NodeKey()

	h := sha256.New()
	_, _ = h.Write(c.AssetID[:])
	_, _ = h.Write(left[:])
	_, _ = h.Write(right[:])
	_ = binary.Write(h, binary.BigEndian, c.TreeRoot.NodeSum())
	return *(*[sha256.Size]byte)(h.Sum(nil))
}

// TaroCommitmentKey computes the insertion key for this specific asset
// commitment to include in the Taro commitment MS-SMT.
func (c AssetCommitment) TaroCommitmentKey() [32]byte {
	return c.AssetID
}

// TaroCommitmentLeaf computes the leaf node for this specific asset commitment
// to include in the Taro commitment MS-SMT.
func (c AssetCommitment) TaroCommitmentLeaf() *mssmt.LeafNode {
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
func (c AssetCommitment) AssetProof(key [32]byte) (*asset.Asset, *mssmt.Proof) {
	if c.tree == nil {
		panic("missing tree to compute proofs")
	}
	return c.assets[key], c.tree.MerkleProof(key)
}
