package commitment

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/chanutils"
	"github.com/lightninglabs/taro/mssmt"
	"golang.org/x/exp/maps"
)

const (
	// taroMarkerTag is the preimage to the TaroMarker included in tapscript
	// leaves for Taro commitments.
	taroMarkerTag = "taro"
)

var (
	// TaroMarker is a static identifier included in the leaf script of a
	// Taro commitment to uniquely identify from any other leaves in the
	// tapscript tree.
	TaroMarker = sha256.Sum256([]byte(taroMarkerTag))
)

// AssetCommitments is the set of assetCommitments backing a TaroCommitment.
// The map is keyed by the AssetCommitment's TaroCommitmentKey.
type AssetCommitments map[[32]byte]*AssetCommitment

// TaroCommitment represents the outer MS-SMT within the Taro protocol
// committing to a set of asset commitments. Asset commitments, which are
// leaves represented as `asset_version || asset_tree_root || asset_sum`, are
// keyed by their `asset_group_key` or `asset_id` otherwise.
type TaroCommitment struct {
	// Version is the maximum Taro asset version found within all of the
	// assets committed.
	Version asset.Version

	// TreeRoot is the root node of the MS-SMT containing all of the asset
	// commitments.
	TreeRoot *mssmt.BranchNode

	// tree is the outer MS-SMT containing all of the asset commitments.
	//
	// NOTE: This is nil when TaroCommitment is constructed with
	// NewTaroCommitmentWithRoot.
	tree mssmt.Tree

	// assetCommitments is the set of asset commitments found within the
	// tree above.
	//
	// NOTE: This is nil when TaroCommitment is constructed with
	// NewTaroCommitmentWithRoot.
	assetCommitments AssetCommitments
}

// NewTaroCommitment creates a new Taro commitment for the given asset
// commitments capable of computing merkle proofs.
func NewTaroCommitment(assets ...*AssetCommitment) (*TaroCommitment, error) {
	maxVersion := asset.V0
	tree := mssmt.NewCompactedTree(mssmt.NewDefaultStore())
	assetCommitments := make(AssetCommitments, len(assets))
	for _, asset := range assets {
		asset := asset

		if asset.Version > maxVersion {
			maxVersion = asset.Version
		}
		key := asset.TaroCommitmentKey()
		leaf := asset.TaroCommitmentLeaf()

		// TODO(bhandras): thread the context through.
		_, err := tree.Insert(context.TODO(), key, leaf)
		if err != nil {
			return nil, err
		}

		assetCommitments[key] = asset
	}

	root, err := tree.Root(context.Background())
	if err != nil {
		return nil, err
	}

	return &TaroCommitment{
		Version:          maxVersion,
		TreeRoot:         root,
		assetCommitments: assetCommitments,
		tree:             tree,
	}, nil
}

// Delete modifies one entry in the TaroCommitment by deleting it in the inner
// MS-SMT and in the internal AssetCommitment map.
func (c *TaroCommitment) Delete(asset *AssetCommitment) error {
	if asset == nil {
		// TODO(jhb): Concrete error types
		panic("taro commitment update is missing asset commitment")
	}

	key := asset.TaroCommitmentKey()

	// TODO(bhandras): thread the context through.
	_, err := c.tree.Delete(context.TODO(), key)
	if err != nil {
		return err
	}

	c.TreeRoot, err = c.tree.Root(context.TODO())
	if err != nil {
		return err
	}

	delete(c.assetCommitments, key)

	return nil
}

// Upsert modifies one entry in the TaroCommitment by inserting (or updating)
// it in the inner MS-SMT and in the internal AssetCommitment map.
func (c *TaroCommitment) Upsert(asset *AssetCommitment) error {
	if asset == nil {
		// TODO(jhb): Concrete error types
		panic("taro commitment update is missing asset commitment")
	}

	key := asset.TaroCommitmentKey()

	// TODO(bhandras): thread the context through.
	leaf := asset.TaroCommitmentLeaf()
	_, err := c.tree.Insert(context.TODO(), key, leaf)
	if err != nil {
		return err
	}

	c.TreeRoot, err = c.tree.Root(context.TODO())
	if err != nil {
		return err
	}

	c.assetCommitments[key] = asset

	return nil
}

// Commitment returns the asset commitment for the given asset. If the asset
// commitment is not found, the second returned value is false.
func (c *TaroCommitment) Commitment(a *asset.Asset) (*AssetCommitment, bool) {
	key := a.TaroCommitmentKey()
	commitment, ok := c.assetCommitments[key]
	return commitment, ok
}

// NewTaroCommitmentWithRoot creates a new Taro commitment backed by the root
// node. The resulting commitment will not be able to compute merkle proofs as
// it only knows of the tree's root node, and not the tree itself.
func NewTaroCommitmentWithRoot(version asset.Version,
	root *mssmt.BranchNode) *TaroCommitment {

	return &TaroCommitment{
		Version:          version,
		TreeRoot:         root,
		assetCommitments: nil,
		tree:             nil,
	}
}

// TapLeaf constructs a new `TapLeaf` for this `TaroCommitment`.
func (c *TaroCommitment) TapLeaf() txscript.TapLeaf {
	rootHash := c.TreeRoot.NodeHash()
	var rootSum [8]byte
	binary.BigEndian.PutUint64(rootSum[:], c.TreeRoot.NodeSum())
	leafParts := [][]byte{
		{byte(c.Version)}, TaroMarker[:], rootHash[:], rootSum[:],
	}
	leafScript := bytes.Join(leafParts, nil)
	return txscript.NewBaseTapLeaf(leafScript)
}

// tapBranchHash takes the tap hashes of the left and right nodes and hashes
// them into a branch.
func tapBranchHash(l, r chainhash.Hash) chainhash.Hash {
	if bytes.Compare(l[:], r[:]) > 0 {
		l, r = r, l
	}
	return *chainhash.TaggedHash(chainhash.TagTapBranch, l[:], r[:])
}

// TapscriptRoot returns the tapscript root for this TaroCommitment. If
// `sibling` is not nil, we assume it is a valid sibling (e.g., not a duplicate
// Taro commitment), and hash it with the Taro commitment leaf to arrive at the
// tapscript root, otherwise the Taro commitment leaf itself becomes the
// tapscript root.
func (c *TaroCommitment) TapscriptRoot(sibling *chainhash.Hash) chainhash.Hash {
	commitmentLeaf := c.TapLeaf()
	if sibling == nil {
		return txscript.AssembleTaprootScriptTree(commitmentLeaf).
			RootNode.TapHash()
	}

	// The ordering of `commitmentLeaf` and `sibling` doesn't matter here as
	// TapBranch will sort them before hashing.
	return tapBranchHash(commitmentLeaf.TapHash(), *sibling)
}

// Proof computes the full TaroCommitment merkle proof for the asset leaf
// located at `assetCommitmentKey` within the AssetCommitment located at
// `taroCommitmentKey`.
func (c *TaroCommitment) Proof(taroCommitmentKey,
	assetCommitmentKey [32]byte) (*asset.Asset, *Proof, error) {

	if c.assetCommitments == nil || c.tree == nil {
		panic("missing asset commitments to compute proofs")
	}

	// TODO(bhandras): thread the context through.
	merkleProof, err := c.tree.MerkleProof(
		context.TODO(), taroCommitmentKey,
	)
	if err != nil {
		return nil, nil, err
	}

	proof := &Proof{
		TaroProof: TaroProof{
			Proof:   *merkleProof,
			Version: c.Version,
		},
	}

	// If the corresponding AssetCommitment does not exist, return the Proof
	// as is.
	assetCommitment, ok := c.assetCommitments[taroCommitmentKey]
	if !ok {
		return nil, proof, nil
	}

	// Otherwise, compute the AssetProof and include it in the result. It's
	// possible for the asset to not be found, leading to a non-inclusion
	// proof.
	asset, assetProof, err := assetCommitment.AssetProof(assetCommitmentKey)
	if err != nil {
		return nil, nil, err
	}

	proof.AssetProof = &AssetProof{
		Proof:   *assetProof,
		Version: assetCommitment.Version,
		AssetID: assetCommitment.AssetID,
	}

	return asset, proof, nil
}

// CommittedAssets returns the set of assets committed to in the taro
// commitment.
func (c *TaroCommitment) CommittedAssets() []*asset.Asset {
	var assets []*asset.Asset
	for _, commitment := range c.assetCommitments {
		commitment := commitment

		committedAssets := maps.Values(commitment.Assets())
		assets = append(assets, committedAssets...)
	}

	return assets
}

// Commitments returns the set of assetCommitments committed to in the taro
// commitment.
func (c *TaroCommitment) Commitments() AssetCommitments {
	assetCommitments := make(AssetCommitments, len(c.assetCommitments))
	maps.Copy(assetCommitments, c.assetCommitments)

	return assetCommitments
}

// Copy performs a deep copy of the passed Taro commitment.
func (c *TaroCommitment) Copy() (*TaroCommitment, error) {
	// If no commitments are present, then this is a commitment with just
	// the root, so we just need to copy that over.
	if len(c.assetCommitments) == 0 {
		rootCopy := c.TreeRoot.Copy().(*mssmt.BranchNode)
		return &TaroCommitment{
			Version:  c.Version,
			TreeRoot: rootCopy,
		}, nil
	}

	// Otherwise, we'll copy all the internal asset commitments.
	newAssetCommitments, err := chanutils.CopyAllErr(
		maps.Values(c.assetCommitments),
	)
	if err != nil {
		return nil, err
	}

	// With the internal assets commitments copied, we can just re-create
	// the taro commitment as a whole.
	return NewTaroCommitment(newAssetCommitments...)
}
