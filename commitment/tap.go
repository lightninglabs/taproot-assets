package commitment

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"golang.org/x/exp/maps"
)

// TapCommitmentVersion denotes the structure of the Taproot Asset commitment
// MS-SMT and the procedure for building a TapLeaf from a Taproot Asset
// commitment.
type TapCommitmentVersion uint8

const (
	// TapCommitmentV0 is the initial Taproot Asset Commitment version. A
	// V0 commitment uses the legacy TapLeaf format, and ONLY commits to V0
	// assets.
	TapCommitmentV0 TapCommitmentVersion = 0

	// TapCommitmentV1 is used by Taproot Asset Commitments that commit to
	// V0 or V1 assets. A V1 commitment uses the legacy TapLeaf format.
	TapCommitmentV1 TapCommitmentVersion = 1

	// TapCommitmentV2 is used by Taproot Asset Commitments that commit to
	// V0 or V1 assets. A V2 commitment uses the V1 TapLeaf format.
	TapCommitmentV2 TapCommitmentVersion = 2
)

const (
	// taprootAssetsMarkerTag is the preimage to the TaprootAssetsMarker
	// included in tapscript leaves for Taproot Asset commitments.
	taprootAssetsMarkerTag = "taproot-assets"
)

var (
	// TaprootAssetsMarker is a static identifier included in the leaf
	// script of a Taproot Asset commitment to uniquely identify from any
	// other leaves in the tapscript tree.
	TaprootAssetsMarker = sha256.Sum256([]byte(taprootAssetsMarkerTag))

	// ErrMissingAssetCommitment is an error returned when we attempt to
	// update or delete a Taproot Asset commitment without an asset
	// commitment.
	ErrMissingAssetCommitment = errors.New(
		"tap commitment: missing asset commitment",
	)

	// ErrInvalidTapCommitmentVersion is an error returned when we attempt
	// to create a TapCommitment with an invalid TapCommitmentVersion.
	ErrInvalidTapCommitmentVersion = errors.New(
		"tap commitment: invalid version",
	)

	// TaprootAssetCommitmentScriptSize is the size of the Taproot Asset
	// commitment script:
	//
	//	- 1 byte for the version
	//	- 32 bytes for the TaprootAssetsMarker
	//	- 32 bytes for the root hash
	//	- 8 bytes for the root sum
	TaprootAssetCommitmentScriptSize = 1 + 32 + 32 + 8
)

// AssetCommitments is the set of assetCommitments backing a TapCommitment.
// The map is keyed by the AssetCommitment's TapCommitmentKey.
type AssetCommitments map[[32]byte]*AssetCommitment

// TapCommitment represents the outer MS-SMT within the Taproot Asset protocol
// committing to a set of asset commitments. Asset commitments, which are
// leaves represented as `asset_version || asset_tree_root || asset_sum`, are
// keyed by their `asset_group_key` or `asset_id` otherwise.
type TapCommitment struct {
	// Version is the version of the Taproot Asset commitment.
	Version TapCommitmentVersion

	// TreeRoot is the root node of the MS-SMT containing all of the asset
	// commitments.
	TreeRoot *mssmt.BranchNode

	// tree is the outer MS-SMT containing all of the asset commitments.
	//
	// NOTE: This is nil when TapCommitment is constructed with
	// NewTapCommitmentWithRoot.
	tree mssmt.Tree

	// assetCommitments is the set of asset commitments found within the
	// tree above.
	//
	// NOTE: This is nil when TapCommitment is constructed with
	// NewTapCommitmentWithRoot.
	assetCommitments AssetCommitments
}

// NewTapCommitment creates a new Taproot Asset commitment for the given asset
// commitments capable of computing merkle proofs.
func NewTapCommitment(version *TapCommitmentVersion,
	newCommitments ...*AssetCommitment) (*TapCommitment, error) {

	maxVersion := asset.V0
	tree := mssmt.NewCompactedTree(mssmt.NewDefaultStore())
	assetCommitments := make(AssetCommitments, len(newCommitments))
	for idx := range newCommitments {
		assetCommitment := newCommitments[idx]

		if assetCommitment.Version > maxVersion {
			maxVersion = assetCommitment.Version
		}
		key := assetCommitment.TapCommitmentKey()

		// Do we already have an asset commitment for this key? If so,
		// we need to merge them together.
		existingCommitment, ok := assetCommitments[key]
		if ok {
			err := existingCommitment.Merge(assetCommitment)
			if err != nil {
				return nil, err
			}

			assetCommitment = existingCommitment
		}

		leaf := assetCommitment.TapCommitmentLeaf()

		// TODO(bhandras): thread the context through.
		_, err := tree.Insert(context.TODO(), key, leaf)
		if err != nil {
			return nil, err
		}

		assetCommitments[key] = assetCommitment
	}

	root, err := tree.Root(context.Background())
	if err != nil {
		return nil, err
	}

	switch {
	// If no version was specified, we'll use the max version of the asset
	// commitments.
	case version == nil:
		return &TapCommitment{
			TreeRoot:         root,
			assetCommitments: assetCommitments,
			tree:             tree,
			Version:          TapCommitmentVersion(maxVersion),
		}, nil

	case *version == TapCommitmentV0 || *version == TapCommitmentV1:
		return &TapCommitment{
			TreeRoot:         root,
			assetCommitments: assetCommitments,
			tree:             tree,
			Version:          *version,
		}, nil

	case *version == TapCommitmentV2:
		return &TapCommitment{
			TreeRoot:         root,
			assetCommitments: assetCommitments,
			tree:             tree,
			Version:          TapCommitmentV2,
		}, nil

	default:
		return nil, fmt.Errorf("%w: %v", ErrInvalidTapCommitmentVersion,
			*version)
	}
}

// FromAssets creates a new Taproot Asset commitment for the given assets,
// creating the appropriate asset commitments internally.
func FromAssets(version *TapCommitmentVersion,
	assets ...*asset.Asset) (*TapCommitment, error) {

	lowerCommitments := make(map[[32]byte]*AssetCommitment, len(assets))

	// Create the necessary asset commitments. Assets are upserted into
	// commitments based on their Taproot Asset commitment keys.
	for _, a := range assets {
		key := a.TapCommitmentKey()
		commitment, ok := lowerCommitments[key]
		if ok {
			err := commitment.Upsert(a)
			if err != nil {
				return nil, err
			}

			continue
		}

		commitment, err := NewAssetCommitment(a)
		if err != nil {
			return nil, err
		}

		lowerCommitments[key] = commitment
	}

	// Finally, we'll construct the Taproot Asset commitment for this group
	// of assets.
	topCommitment, err := NewTapCommitment(
		version, maps.Values(lowerCommitments)...,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to make new Taproot Asset "+
			"commitment from assets: %w", err)
	}

	return topCommitment, nil
}

// maxAssetCommitmentVersion returns the maximum commitment version from a list
// of AssetCommitments.
func maxAssetCommitmentVersion(
	commits []*AssetCommitment) TapCommitmentVersion {

	versions := fn.Map(commits, func(a *AssetCommitment) asset.Version {
		return a.Version
	})
	maxVersion := fn.Reduce(
		versions, func(a, b asset.Version) asset.Version {
			if a > b {
				return a
			}

			return b
		})

	return TapCommitmentVersion(maxVersion)
}

// Delete modifies one entry in the TapCommitment by deleting it in the inner
// MS-SMT and in the internal AssetCommitment map.
func (c *TapCommitment) Delete(assetCommitment *AssetCommitment) error {
	if assetCommitment == nil {
		return ErrMissingAssetCommitment
	}

	key := assetCommitment.TapCommitmentKey()

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

	switch {
	case c.Version == TapCommitmentV2:

	// With the commitment above deleted, we'll need to update the max
	// version amongst the remaining commitments.
	default:
		commits := maps.Values(c.assetCommitments)
		c.Version = maxAssetCommitmentVersion(commits)
	}

	return nil
}

// IsSimilarTapCommitmentVersion returns true if both TapCommitmentVersions
// are nil, equal, or would map to the same TapCommitmentVersion.
func IsSimilarTapCommitmentVersion(a, b *TapCommitmentVersion) bool {
	switch {
	case a == nil && b == nil:
		return true

	// If one of the versions is nil, the constructed commitment could be V0
	// or V1, depending on the included assets.
	case a == nil:
		return *b == TapCommitmentV0 || *b == TapCommitmentV1

	case b == nil:
		return *a == TapCommitmentV0 || *a == TapCommitmentV1

	default:
		// If one of the commitments is V2, both must be V2.
		if *a == TapCommitmentV2 {
			return *b == TapCommitmentV2
		}

		// Mixing V0 and V1 commitments is valid.
		return (*a == TapCommitmentV0 || *a == TapCommitmentV1) &&
			(*b == TapCommitmentV0 || *b == TapCommitmentV1)
	}
}

// Upsert modifies one entry in the TapCommitment by inserting (or updating)
// it in the inner MS-SMT and in the internal AssetCommitment map. If the asset
// commitment passed in is empty, it is instead pruned from the Taproot Asset
// tree.
func (c *TapCommitment) Upsert(assetCommitment *AssetCommitment) error {
	if assetCommitment == nil {
		return ErrMissingAssetCommitment
	}

	key := assetCommitment.TapCommitmentKey()
	leaf := assetCommitment.TapCommitmentLeaf()

	// Because the Taproot Asset tree has a different root whether we
	// insert an empty asset tree vs. there being an empty leaf, we need to
	// remove the whole asset tree if the given asset commitment is empty.
	if assetCommitment.TreeRoot.NodeHash() == mssmt.EmptyTreeRootHash {
		_, err := c.tree.Delete(context.TODO(), key)
		if err != nil {
			return err
		}

		delete(c.assetCommitments, key)
	} else {
		// TODO(bhandras): thread the context through.
		_, err := c.tree.Insert(context.TODO(), key, leaf)
		if err != nil {
			return err
		}

		c.assetCommitments[key] = assetCommitment
	}

	var err error
	c.TreeRoot, err = c.tree.Root(context.TODO())
	if err != nil {
		return err
	}

	switch {
	case c.Version == TapCommitmentV2:

	// With the commitment above deleted, we'll need to update the max
	// version amongst the remaining commitments.
	default:
		commits := maps.Values(c.assetCommitments)
		c.Version = maxAssetCommitmentVersion(commits)
	}

	return nil
}

// Commitment returns the asset commitment for the given asset. If the asset
// commitment is not found, the second returned value is false.
func (c *TapCommitment) Commitment(a *asset.Asset) (*AssetCommitment, bool) {
	key := a.TapCommitmentKey()
	commitment, ok := c.assetCommitments[key]
	return commitment, ok
}

// NewTapCommitmentWithRoot creates a new Taproot Asset commitment backed by
// the root node. The resulting commitment will not be able to compute merkle
// proofs as it only knows of the tree's root node, and not the tree itself.
func NewTapCommitmentWithRoot(version TapCommitmentVersion,
	root *mssmt.BranchNode) *TapCommitment {

	return &TapCommitment{
		Version:          version,
		TreeRoot:         root,
		assetCommitments: nil,
		tree:             nil,
	}
}

// TapLeaf constructs a new `TapLeaf` for this `TapCommitment`.
func (c *TapCommitment) TapLeaf() txscript.TapLeaf {
	rootHash := c.TreeRoot.NodeHash()
	tapVersion := byte(c.Version)
	var rootSum [8]byte
	binary.BigEndian.PutUint64(rootSum[:], c.TreeRoot.NodeSum())

	var leafParts [][]byte

	// Assemble the leafParts based on the commitment version.
	switch {
	case c.Version == TapCommitmentV0 || c.Version == TapCommitmentV1:
		leafParts = [][]byte{
			{tapVersion}, TaprootAssetsMarker[:], rootHash[:],
			rootSum[:],
		}

	case c.Version == TapCommitmentV2:
		tag := sha256.Sum256([]byte(taprootAssetsMarkerTag + ":194243"))
		leafParts = [][]byte{
			tag[:], {tapVersion}, rootHash[:], rootSum[:],
		}
	}

	leafScript := bytes.Join(leafParts, nil)
	return txscript.NewBaseTapLeaf(leafScript)
}

// Downgrade returns a taproot asset commitment with the same root, but with
// the asset commitment version downgraded to V0. This is useful for unit tests.
func (c *TapCommitment) Downgrade() (*TapCommitment, error) {
	// If no commitments are present, then this is a commitment with just
	// the root, so we just need to copy that over.
	if len(c.assetCommitments) == 0 {
		rootCopy := c.TreeRoot.Copy().(*mssmt.BranchNode)
		return &TapCommitment{
			Version:  TapCommitmentV0,
			TreeRoot: rootCopy,
		}, nil
	}

	// Otherwise, we'll copy all the internal asset commitments.
	newAssetCommitments, err := fn.CopyAllErr(
		maps.Values(c.assetCommitments),
	)
	if err != nil {
		return nil, err
	}

	return NewTapCommitment(nil, newAssetCommitments...)
}

// IsTaprootAssetCommitmentScript returns true if the passed script is a valid
// Taproot Asset commitment script.
func IsTaprootAssetCommitmentScript(script []byte) bool {
	if len(script) != TaprootAssetCommitmentScriptSize {
		return false
	}

	switch {
	// V0 and V1 commitment scripts use the legacy TapLeaf format.
	case script[0] == byte(TapCommitmentV0) ||
		script[0] == byte(TapCommitmentV1):

		return bytes.Equal(
			script[1:1+sha256.Size], TaprootAssetsMarker[:],
		)

	default:
		tag := sha256.Sum256([]byte(taprootAssetsMarkerTag + ":194243"))
		return bytes.Equal(script[:sha256.Size], tag[:])
	}
}

// TapscriptRoot returns the tapscript root for this TapCommitment. If `sibling`
// is not nil, we assume it is a valid sibling (e.g., not a duplicate Taproot
// Asset commitment), and hash it with the Taproot Asset commitment leaf to
// arrive at the tapscript root, otherwise the Taproot Asset commitment leaf
// itself becomes the tapscript root.
func (c *TapCommitment) TapscriptRoot(sibling *chainhash.Hash) chainhash.Hash {
	commitmentLeaf := c.TapLeaf()
	if sibling == nil {
		return txscript.AssembleTaprootScriptTree(commitmentLeaf).
			RootNode.TapHash()
	}

	// The ordering of `commitmentLeaf` and `sibling` doesn't matter here as
	// TapBranch will sort them before hashing.
	return asset.TapBranchHash(commitmentLeaf.TapHash(), *sibling)
}

// Proof computes the full TapCommitment merkle proof for the asset leaf
// located at `assetCommitmentKey` within the AssetCommitment located at
// `tapCommitmentKey`.
func (c *TapCommitment) Proof(tapCommitmentKey,
	assetCommitmentKey [32]byte) (*asset.Asset, *Proof, error) {

	if c.assetCommitments == nil || c.tree == nil {
		panic("missing asset commitments to compute proofs")
	}

	// TODO(bhandras): thread the context through.
	merkleProof, err := c.tree.MerkleProof(context.TODO(), tapCommitmentKey)
	if err != nil {
		return nil, nil, err
	}

	proof := &Proof{
		TaprootAssetProof: TaprootAssetProof{
			Proof:   *merkleProof,
			Version: c.Version,
		},
	}

	// If the corresponding AssetCommitment does not exist, return the Proof
	// as is.
	assetCommitment, ok := c.assetCommitments[tapCommitmentKey]
	if !ok {
		return nil, proof, nil
	}

	// Otherwise, compute the AssetProof and include it in the result. It's
	// possible for the asset to not be found, leading to a non-inclusion
	// proof.
	a, assetProof, err := assetCommitment.AssetProof(assetCommitmentKey)
	if err != nil {
		return nil, nil, err
	}

	proof.AssetProof = &AssetProof{
		Proof:   *assetProof,
		Version: assetCommitment.Version,
		TapKey:  assetCommitment.TapKey,
	}

	return a, proof, nil
}

// CommittedAssets returns the set of assets committed to in the Taproot Asset
// commitment.
func (c *TapCommitment) CommittedAssets() []*asset.Asset {
	var assets []*asset.Asset
	for _, commitment := range c.assetCommitments {
		commitment := commitment

		committedAssets := maps.Values(commitment.Assets())
		assets = append(assets, committedAssets...)
	}

	return assets
}

// Commitments returns the set of assetCommitments committed to in the Taproot
// Asset commitment.
func (c *TapCommitment) Commitments() AssetCommitments {
	assetCommitments := make(AssetCommitments, len(c.assetCommitments))
	maps.Copy(assetCommitments, c.assetCommitments)

	return assetCommitments
}

// Copy performs a deep copy of the passed Taproot Asset commitment.
func (c *TapCommitment) Copy() (*TapCommitment, error) {
	// If no commitments are present, then this is a commitment with just
	// the root, so we just need to copy that over.
	if len(c.assetCommitments) == 0 {
		rootCopy := c.TreeRoot.Copy().(*mssmt.BranchNode)
		return &TapCommitment{
			Version:  c.Version,
			TreeRoot: rootCopy,
		}, nil
	}

	// Otherwise, we'll copy all the internal asset commitments.
	newAssetCommitments, err := fn.CopyAllErr(
		maps.Values(c.assetCommitments),
	)
	if err != nil {
		return nil, err
	}

	// With the internal assets commitments copied, we can just re-create
	// the Taproot Asset commitment as a whole.
	switch {
	case c.Version == TapCommitmentV2:
		return NewTapCommitment(
			fn.Ptr(TapCommitmentV2), newAssetCommitments...,
		)

	default:
		return NewTapCommitment(nil, newAssetCommitments...)
	}
}

// Merge merges the other commitment into this commitment. If the other
// commitment is empty, then this is a no-op. If the other commitment was
// constructed with NewTapCommitmentWithRoot, then an error is returned.
func (c *TapCommitment) Merge(other *TapCommitment) error {
	// If this was constructed with NewTapCommitmentWithRoot then we can't
	// merge as we don't have the asset commitments.
	if other.assetCommitments == nil {
		return fmt.Errorf("cannot merge commitments without asset " +
			"commitments")
	}

	// If the other commitment is empty, then we can just exit early.
	if len(other.assetCommitments) == 0 {
		return nil
	}

	// Only commitments with similar versions can be merged.
	if !IsSimilarTapCommitmentVersion(&c.Version, &other.Version) {
		return fmt.Errorf("commitment version mismatch: %v, %v",
			c.Version, other.Version)
	}

	// Otherwise, we'll need to merge the other asset commitments into
	// this commitment.
	for key := range other.assetCommitments {
		otherCommitment := other.assetCommitments[key]

		// If we already have an asset commitment for this key, then we
		// merge the two asset trees together.
		existingCommitment, ok := c.assetCommitments[key]
		if ok {
			err := existingCommitment.Merge(otherCommitment)
			if err != nil {
				return fmt.Errorf("error merging asset "+
					"commitment: %w", err)
			}
		} else {
			existingCommitment = otherCommitment
		}

		// With either the new or merged asset commitment obtained, we
		// can now (re-)insert it into the Taproot Asset commitment.
		if err := c.Upsert(existingCommitment); err != nil {
			return fmt.Errorf("error upserting other commitment: "+
				"%w", err)
		}
	}

	return nil
}

// TrimSplitWitnesses returns a copy of the commitment in which all assets with
// a split commitment witness have their SplitCommitment field set to nil.
func TrimSplitWitnesses(version *TapCommitmentVersion,
	c *TapCommitment) (*TapCommitment, error) {

	// If the input asset was received non-interactively, then the Taproot
	// Asset tree of the input anchor output was built with asset leaves
	// that had empty SplitCommitments. However, the SplitCommitment field
	// was populated when the transfer of the input asset was verified.
	// To recompute the correct output script, we need to build a Taproot
	// Asset tree from the input asset without any SplitCommitment.
	originalAssets := c.CommittedAssets()
	assetCopies := make([]*asset.Asset, len(originalAssets))
	for idx, originalAsset := range originalAssets {
		assetCopy := originalAsset.Copy()

		// Assets received via non-interactive split should have one
		// witness, with an empty PrevID and a SplitCommitment present.
		if assetCopy.HasSplitCommitmentWitness() &&
			*assetCopy.PrevWitnesses[0].PrevID == asset.ZeroPrevID {

			assetCopy.PrevWitnesses[0].SplitCommitment = nil
		}

		assetCopies[idx] = assetCopy
	}
	tapCommitment, err := FromAssets(version, assetCopies...)
	if err != nil {
		return nil, err
	}

	return tapCommitment, nil
}

// TrimAltLeaves creates a new TapCommitment with any AltLeaves removed, if
// present. The removed AltLeaves are returned separately.
func TrimAltLeaves(c *TapCommitment) (*TapCommitment, []*asset.Asset, error) {
	altAssets, err := c.FetchAltLeaves()
	if err != nil {
		return nil, nil, fmt.Errorf("cannot trim: %w", err)
	}

	// Remove the AltCommitment and reconstruct the Tap commitment.
	allCommitments := c.Commitments()
	delete(allCommitments, asset.EmptyGenesisID)

	tapCommitment, err := NewTapCommitment(
		&c.Version, maps.Values(allCommitments)...,
	)
	if err != nil {
		return nil, nil, err
	}

	return tapCommitment, altAssets, nil
}

// FetchAltLeaves returns a copy of any AltLeaves present in the TapCommitment.
func (c *TapCommitment) FetchAltLeaves() ([]*asset.Asset, error) {
	if c.assetCommitments == nil {
		return nil, errors.New("tap commitment has no leaves")
	}

	altCommit := c.assetCommitments[asset.EmptyGenesisID]
	if altCommit == nil {
		return nil, nil
	}

	return maps.Values(altCommit.Assets()), nil
}

// MergeAltLeaves adds a set of AltLeaves to an existing TapCommitment. Merging
// fails if the new AltLeaves collide with any existing AltLeaves.
func (c *TapCommitment) MergeAltLeaves(
	altLeaves []asset.AltLeaf[asset.Asset]) error {

	if len(altLeaves) == 0 {
		return nil
	}

	// First, check that the given alt leaves have unique
	// AssetCommitmentKeys.
	newLeafKeys := asset.NewLeafKeySet()
	err := asset.AddLeafKeysVerifyUnique(newLeafKeys, altLeaves)
	if err != nil {
		return err
	}

	// Check if any alt leaves are already present.
	var currentAltCommit *AssetCommitment
	if c.assetCommitments != nil {
		currentAltCommit = c.assetCommitments[asset.EmptyGenesisID]
		if currentAltCommit != nil {
			currentLeaves := currentAltCommit.Assets()

			// If any alt leaves are already committed, new alt
			// leaves must not collide with existing alt leaves.
			for leafKey := range currentLeaves {
				if newLeafKeys.Contains(leafKey) {
					return fmt.Errorf("%w: existing alt "+
						"leaf: %x",
						asset.ErrDuplicateAltLeafKey,
						leafKey)
				}
			}
		}
	}

	// None of the new or existing alt leaves collide; we can now update
	// the AltCommitment and Tap commitment.
	if currentAltCommit == nil {
		currentAltCommit, err = NewAssetCommitment(
			altLeaves[0].(*asset.Asset),
		)
		if err != nil {
			return err
		}
	}

	for _, newLeaf := range altLeaves {
		err := currentAltCommit.Upsert(newLeaf.(*asset.Asset))
		if err != nil {
			return err
		}
	}

	err = c.Upsert(currentAltCommit)
	if err != nil {
		return err
	}

	return nil
}
