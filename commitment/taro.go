package commitment

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/mssmt"
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

// TaroCommitment represents the outer MS-SMT within the Taro protocol
// committing to a set of asset commitments. Asset commitments, which are
// leaves represented as `asset_version || asset_tree_root || asset_sum`, are
// keyed by their `asset_family_key` or `asset_id` otherwise.
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
	tree *mssmt.Tree

	// assetCommitments is the set of asset commitments found within the
	// tree above.
	//
	// NOTE: This is nil when TaroCommitment is constructed with
	// NewTaroCommitmentWithRoot.
	assetCommitments map[[32]byte]*AssetCommitment
}

// NewTaroCommitment creates a new Taro commitment for the given asset
// commitments capable of computing merkle proofs.
func NewTaroCommitment(assets ...*AssetCommitment) *TaroCommitment {
	maxVersion := asset.V0
	tree := mssmt.NewTree(mssmt.NewDefaultStore())
	assetCommitments := make(map[[32]byte]*AssetCommitment, len(assets))
	for _, asset := range assets {
		if asset.Version > maxVersion {
			maxVersion = asset.Version
		}
		key := asset.TaroCommitmentKey()
		leaf := asset.TaroCommitmentLeaf()
		tree.Insert(key, leaf)
		assetCommitments[key] = asset
	}
	return &TaroCommitment{
		Version:          maxVersion,
		TreeRoot:         tree.Root(),
		assetCommitments: assetCommitments,
		tree:             tree,
	}
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
func (c TaroCommitment) TapLeaf() txscript.TapLeaf {
	rootHash := c.TreeRoot.NodeKey()
	var rootSum [8]byte
	binary.BigEndian.PutUint64(rootSum[:], c.TreeRoot.NodeSum())
	leafParts := [][]byte{
		{byte(c.Version)}, TaroMarker[:], rootHash[:], rootSum[:],
	}
	leafScript := bytes.Join(leafParts, nil)
	return txscript.NewBaseTapLeaf(leafScript)
}

// TapscriptRoot returns the tapscript root for this TaroCommitment. If
// `sibling` is not nil, we assume it is a valid sibling (e.g., not a duplicate
// Taro commitment), and hash it with the Taro commitment leaf to arrive at the
// tapscript root, otherwise the Taro commitment leaf itself becomes the
// tapscript root.
func (c TaroCommitment) TapscriptRoot(sibling *chainhash.Hash) chainhash.Hash {
	commitmentLeaf := c.TapLeaf()
	if sibling == nil {
		return txscript.AssembleTaprootScriptTree(commitmentLeaf).
			RootNode.TapHash()
	}
	// TODO: Expose an easy way to construct merkle proofs for this
	// type of tree. If `sibling` is the root of a tapscript tree,
	// then it's as simple as computing the control block for said
	// tree and appending the taro commitment leaf hash at the end.
	//
	// NOTE: The ordering of `commitmentLeaf` and `sibling`
	// doesn't matter here as TapBranch will sort them before
	// hashing.
	return tapBranchHash(commitmentLeaf.TapHash(), *sibling)
}

// Proof computes the full TaroCommitment merkle proof for the asset leaf
// located at `assetCommitmentKey` within the AssetCommitment located at
// `taroCommitmentKey`.
func (c TaroCommitment) Proof(taroCommitmentKey,
	assetCommitmentKey [32]byte) *Proof {

	if c.assetCommitments == nil || c.tree == nil {
		panic("missing asset commitments to compute proofs")
	}

	proof := &Proof{
		AssetCommitmentKey: assetCommitmentKey,
		TaroCommitmentKey:  taroCommitmentKey,
		TaroProof: &TaroProof{
			Proof:   *c.tree.MerkleProof(taroCommitmentKey),
			Version: c.Version,
		},
	}

	// If the corresponding AssetCommitment does not exist, return the Proof
	// as is.
	assetCommitment, ok := c.assetCommitments[taroCommitmentKey]
	if !ok {
		return proof
	}

	// Otherwise, compute the AssetProof and include it in the result. It's
	// possible for the asset to not be found, leading to a non-inclusion
	// proof.
	asset, assetProof := assetCommitment.AssetProof(assetCommitmentKey)
	proof.Asset = asset
	proof.AssetProof = &AssetProof{
		Proof:   *assetProof,
		Version: assetCommitment.Version,
		AssetID: assetCommitment.AssetID,
	}
	return proof
}

// Asset returns the AssetCommitment located at 'taroCommitmentKey'.
// This function is safe to use even if the TaroCommitment tree is empty,
// such as when constructed with NewTaroCommitmentWIthRoot.
func (c TaroCommitment) Asset(taroCommitmentKey [32]byte) (*AssetCommitment, bool) {
	assetCommitment, ok := c.assetCommitments[taroCommitmentKey]
	return assetCommitment, ok
}

// tapBranchHash takes the tap hashes of the left and right nodes and hashes
// them into a branch.
func tapBranchHash(l, r chainhash.Hash) chainhash.Hash {
	if bytes.Compare(l[:], r[:]) > 0 {
		l, r = r, l
	}
	return *chainhash.TaggedHash(chainhash.TagTapBranch, l[:], r[:])
}
