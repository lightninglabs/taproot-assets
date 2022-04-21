package commitment

import (
	"errors"

	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/mssmt"
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
	// Asset is the asset in question to prove existence for.
	//
	// NOTE: This must be nil if the asset itself or its respective
	// AssetCommitment do not exist within the Taro commitment.
	Asset *asset.Asset

	// AssetCommitmentKey is the key of the Asset for which the AssetProof
	// below is generated for.
	AssetCommitmentKey [32]byte

	// AssetProof is the proof used along with the asset to arrive at the
	// root of the AssetCommitment MS-SMT.
	//
	// NOTE: This proof must be nil if the asset commitment for this
	// particular asset is not found within the Taro commitment. In this
	// case, the TaroProof below would be a non-inclusion proof of the asset
	// commitment.
	AssetProof *AssetProof

	// TaroCommitmentKey is the key of the AssetCommitment for which the
	// TaroProof below is generated for.
	TaroCommitmentKey [32]byte

	// TaroProof is the proof used along with the asset commitment to arrive
	// at the root of the TaroCommitment MS-SMT.
	TaroProof *TaroProof
}

// DeriveTaroCommitment derives the Taro commitment using an asset's commitment
// proof. This consists of proving that an asset does or does not exist within
// the inner MS-SMT, also known as the AssetCommitment. With the AssetCommitment
// obtained, the commitment proof is used to prove that it exists or not within
// the outer MS-SMT, also known as the TaroCommitment.
func (p Proof) DeriveTaroCommitment() (*TaroCommitment, error) {
	// Use the asset proof to arrive at the asset commitment included within
	// the Taro commitment.
	taroCommitmentKey := p.TaroCommitmentKey
	taroCommitmentLeaf := mssmt.EmptyLeafNode
	if p.AssetProof != nil {
		assetCommitmentKey := p.AssetCommitmentKey
		assetCommitmentLeaf := mssmt.EmptyLeafNode
		if p.Asset != nil {
			if p.Asset.AssetCommitmentKey() != assetCommitmentKey {
				return nil, errors.New("asset commitment key mismatch")
			}
			var err error
			assetCommitmentLeaf, err = p.Asset.Leaf()
			if err != nil {
				return nil, err
			}
		}

		assetProofRoot := p.AssetProof.Root(
			assetCommitmentKey, assetCommitmentLeaf,
		)
		assetCommitment := &AssetCommitment{
			Version:  p.AssetProof.Version,
			AssetID:  p.AssetProof.AssetID,
			TreeRoot: assetProofRoot,
		}
		if assetCommitment.TaroCommitmentKey() != taroCommitmentKey {
			return nil, errors.New("taro commitment key mismatch")
		}
		taroCommitmentLeaf = assetCommitment.TaroCommitmentLeaf()
	}

	// Use the Taro commitment proof to arrive at the Taro commitment.
	taroProofRoot := p.TaroProof.Root(taroCommitmentKey, taroCommitmentLeaf)
	return NewTaroCommitmentWithRoot(p.TaroProof.Version, taroProofRoot), nil
}

// ProvesAssetInclusion determines whether Proof proves that its Asset is
// included within the derived TaroCommimtment.
func (p Proof) ProvesAssetInclusion() bool {
	return p.Asset != nil
}
