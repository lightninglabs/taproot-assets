package commitment

import (
	"errors"

	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/mssmt"
)

var (
	// ErrMissingAssetProof is an error returned when attempting to derive a
	// TaroCommitment and an AssetProof is required but missing.
	ErrMissingAssetProof = errors.New("missing asset proof")
)

// AssetProof is the proof used along with an asset leaf to arrive at the root
// of the AssetCommitment MS-SMT.
type AssetProof struct {
	mssmt.Proof

	// Version is the max version of the assets committed.
	Version asset.Version

	// AssetID is the common identifier for all assets found within the
	// AssetCommitment. This can either be an asset.ID, which every
	// committed asset must match, otherwise an asset.FamilyKey which every
	// committed asset must match.
	AssetID [32]byte
}

// TaroProof is the proof used along with an asset commitment leaf to arrive at
// the root of the TaroCommitment MS-SMT.
type TaroProof struct {
	mssmt.Proof

	// Version is the max version committed of the AssetCommitment's
	// included in the TaroCommitment.
	Version asset.Version
}

// Proof represents a full commitment proof for a particular `Asset`. It proves
// that an asset does or does not exist within a Taro commitment.
type Proof struct {
	// AssetProof is the proof used along with the asset to arrive at the
	// root of the AssetCommitment MS-SMT.
	//
	// NOTE: This proof must be nil if the asset commitment for this
	// particular asset is not found within the Taro commitment. In this
	// case, the TaroProof below would be a non-inclusion proof of the asset
	// commitment.
	AssetProof *AssetProof

	// TaroProof is the proof used along with the asset commitment to arrive
	// at the root of the TaroCommitment MS-SMT.
	TaroProof TaroProof
}

// DeriveByAssetInclusion derives the Taro commitment containing the provided
// asset. This consists of proving that an asset exists within the inner MS-SMT
// with the AssetProof, also known as the AssetCommitment. With the
// AssetCommitment obtained, the TaroProof is used to prove that it exists or
// within the outer MS-SMT, also known as the TaroCommitment.
func (p Proof) DeriveByAssetInclusion(asset *asset.Asset) (*TaroCommitment,
	error) {

	if p.AssetProof == nil {
		return nil, ErrMissingAssetProof
	}

	// Use the asset proof to arrive at the asset commitment included within
	// the Taro commitment.
	assetCommitmentLeaf, err := asset.Leaf()
	if err != nil {
		return nil, err
	}
	assetProofRoot := p.AssetProof.Root(
		asset.AssetCommitmentKey(), assetCommitmentLeaf,
	)
	assetCommitment := &AssetCommitment{
		Version:  p.AssetProof.Version,
		AssetID:  p.AssetProof.AssetID,
		TreeRoot: assetProofRoot,
	}

	// Use the Taro commitment proof to arrive at the Taro commitment.
	taroProofRoot := p.TaroProof.Root(
		assetCommitment.TaroCommitmentKey(),
		assetCommitment.TaroCommitmentLeaf(),
	)

	return NewTaroCommitmentWithRoot(p.TaroProof.Version, taroProofRoot), nil
}

// DeriveByAssetExclusion derives the Taro commitment excluding the given asset
// identified by its key within an AssetCommitment. This consists of proving
// with the AssetProof that an asset does not exist within the inner MS-SMT,
// also known as the AssetCommitment. With the AssetCommitment obtained, the
// TaroProof is used to prove that the AssetCommitment exists within the outer
// MS-SMT, also known as the TaroCommitment.
func (p Proof) DeriveByAssetExclusion(assetCommitmentKey [32]byte) (
	*TaroCommitment, error) {

	if p.AssetProof == nil {
		return nil, ErrMissingAssetProof
	}

	// Use the asset proof to arrive at the asset commitment included within
	// the Taro commitment.
	assetCommitmentLeaf := mssmt.EmptyLeafNode
	assetProofRoot := p.AssetProof.Root(
		assetCommitmentKey, assetCommitmentLeaf,
	)
	assetCommitment := &AssetCommitment{
		Version:  p.AssetProof.Version,
		AssetID:  p.AssetProof.AssetID,
		TreeRoot: assetProofRoot,
	}

	// Use the Taro commitment proof to arrive at the Taro commitment.
	taroProofRoot := p.TaroProof.Root(
		assetCommitment.TaroCommitmentKey(),
		assetCommitment.TaroCommitmentLeaf(),
	)
	return NewTaroCommitmentWithRoot(p.TaroProof.Version, taroProofRoot), nil
}

// DeriveByAssetCommitmentExclusion derives the Taro commitment excluding the
// given asset commitment identified by its key within a TaroCommitment. This
// consists of proving with the TaroProof that an AssetCommitment does not exist
// within the outer MS-SMT, also known as the TaroCommitment.
func (p Proof) DeriveByAssetCommitmentExclusion(taroCommitmentKey [32]byte) (
	*TaroCommitment, error) {

	if p.AssetProof != nil {
		return nil, errors.New("attempting to prove an invalid asset " +
			"commitment exclusion")
	}

	// Use the Taro commitment proof to arrive at the Taro commitment.
	taroProofRoot := p.TaroProof.Root(taroCommitmentKey, mssmt.EmptyLeafNode)
	return NewTaroCommitmentWithRoot(p.TaroProof.Version, taroProofRoot), nil
}
