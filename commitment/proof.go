package commitment

import (
	"errors"
	"io"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightningnetwork/lnd/tlv"
)

var (
	// ErrMissingAssetProof is an error returned when attempting to derive a
	// TapCommitment and an AssetProof is required but missing.
	ErrMissingAssetProof = errors.New("missing asset proof")
)

// AssetProof is the proof used along with an asset leaf to arrive at the root
// of the AssetCommitment MS-SMT.
type AssetProof struct {
	mssmt.Proof

	// Version is the max version of the assets committed.
	Version asset.Version

	// TapKey is the common identifier for all assets found within the
	// AssetCommitment. This can either be an asset.ID, which every
	// committed asset must match, otherwise an asset.GroupKey which every
	// committed asset must match.
	TapKey [32]byte
}

// TaprootAssetProof is the proof used along with an asset commitment leaf to
// arrive at the root of the TapCommitment MS-SMT.
type TaprootAssetProof struct {
	mssmt.Proof

	// Version is the max version committed of the AssetCommitment's
	// included in the TapCommitment.
	Version asset.Version
}

// Proof represents a full commitment proof for a particular `Asset`. It proves
// that an asset does or does not exist within a Taproot Asset commitment.
type Proof struct {
	// AssetProof is the proof used along with the asset to arrive at the
	// root of the AssetCommitment MS-SMT.
	//
	// NOTE: This proof must be nil if the asset commitment for this
	// particular asset is not found within the Taproot Asset commitment. In
	// this case, the TaprootAssetProof below would be a non-inclusion proof
	// of the asset commitment.
	AssetProof *AssetProof

	// TaprootAssetProof is the proof used along with the asset commitment
	// to arrive at the root of the TapCommitment MS-SMT.
	TaprootAssetProof TaprootAssetProof
}

// EncodeRecords returns the encoding records for the Proof.
func (p Proof) EncodeRecords() []tlv.Record {
	records := make([]tlv.Record, 0, 3)
	if p.AssetProof != nil {
		records = append(records, ProofAssetProofRecord(&p.AssetProof))
	}
	records = append(records, ProofTaprootAssetProofRecord(&p.TaprootAssetProof))
	return records
}

// DecodeRecords returns the decoding records for the CommitmentProof.
func (p *Proof) DecodeRecords() []tlv.Record {
	return []tlv.Record{
		ProofAssetProofRecord(&p.AssetProof),
		ProofTaprootAssetProofRecord(&p.TaprootAssetProof),
	}
}

// Encode attempts to encode the CommitmentProof into the passed io.Writer.
func (p Proof) Encode(w io.Writer) error {
	stream, err := tlv.NewStream(p.EncodeRecords()...)
	if err != nil {
		return err
	}
	return stream.Encode(w)
}

// Decode attempts to decode the CommitmentProof from the passed io.Reader.
func (p *Proof) Decode(r io.Reader) error {
	stream, err := tlv.NewStream(p.DecodeRecords()...)
	if err != nil {
		return err
	}
	return stream.DecodeP2P(r)
}

// DeriveByAssetInclusion derives the Taproot Asset commitment containing the
// provided asset. This consists of proving that an asset exists within the
// inner MS-SMT with the AssetProof, also known as the AssetCommitment. With the
// AssetCommitment obtained, the TaprootAssetProof is used to prove that it
// exists or within the outer MS-SMT, also known as the TapCommitment.
func (p Proof) DeriveByAssetInclusion(asset *asset.Asset) (*TapCommitment,
	error) {

	if p.AssetProof == nil {
		return nil, ErrMissingAssetProof
	}

	// Use the asset proof to arrive at the asset commitment included within
	// the Taproot Asset commitment.
	assetCommitmentLeaf, err := asset.Leaf()
	if err != nil {
		return nil, err
	}
	assetProofRoot := p.AssetProof.Root(
		asset.AssetCommitmentKey(), assetCommitmentLeaf,
	)
	assetCommitment := &AssetCommitment{
		Version:  p.AssetProof.Version,
		TapKey:   p.AssetProof.TapKey,
		TreeRoot: assetProofRoot,
	}

	// Use the Taproot Asset commitment proof to arrive at the Taproot Asset
	// commitment.
	tapProofRoot := p.TaprootAssetProof.Root(
		assetCommitment.TapCommitmentKey(),
		assetCommitment.TapCommitmentLeaf(),
	)
	log.Tracef("Derived asset inclusion proof for asset_id=%v, "+
		"asset_commitment_key=%x, asset_commitment_leaf=%s",
		asset.ID(), fn.ByteSlice(asset.AssetCommitmentKey()),
		assetCommitmentLeaf.NodeHash())

	return NewTapCommitmentWithRoot(
		p.TaprootAssetProof.Version, tapProofRoot,
	), nil
}

// DeriveByAssetExclusion derives the Taproot Asset commitment excluding the
// given asset identified by its key within an AssetCommitment. This consists of
// proving with the AssetProof that an asset does not exist within the inner
// MS-SMT, also known as the AssetCommitment. With the AssetCommitment obtained,
// the TaprootAssetProof is used to prove that the AssetCommitment exists within
// the outer MS-SMT, also known as the TapCommitment.
func (p Proof) DeriveByAssetExclusion(assetCommitmentKey [32]byte) (
	*TapCommitment, error) {

	if p.AssetProof == nil {
		return nil, ErrMissingAssetProof
	}

	// Use the asset proof to arrive at the asset commitment included within
	// the Taproot Asset commitment.
	assetCommitmentLeaf := mssmt.EmptyLeafNode
	assetProofRoot := p.AssetProof.Root(
		assetCommitmentKey, assetCommitmentLeaf,
	)
	assetCommitment := &AssetCommitment{
		Version:  p.AssetProof.Version,
		TapKey:   p.AssetProof.TapKey,
		TreeRoot: assetProofRoot,
	}

	// Use the Taproot Asset commitment proof to arrive at the Taproot Asset
	// commitment.
	tapProofRoot := p.TaprootAssetProof.Root(
		assetCommitment.TapCommitmentKey(),
		assetCommitment.TapCommitmentLeaf(),
	)
	return NewTapCommitmentWithRoot(
		p.TaprootAssetProof.Version, tapProofRoot,
	), nil
}

// DeriveByAssetCommitmentExclusion derives the Taproot Asset commitment
// excluding the given asset commitment identified by its key within a
// TapCommitment. This consists of proving with the TaprootAssetProof that an
// AssetCommitment does not exist within the outer MS-SMT, also known as the
// TapCommitment.
func (p Proof) DeriveByAssetCommitmentExclusion(tapCommitmentKey [32]byte) (
	*TapCommitment, error) {

	if p.AssetProof != nil {
		return nil, errors.New("attempting to prove an invalid asset " +
			"commitment exclusion")
	}

	// Use the Taproot Asset commitment proof to arrive at the Taproot Asset
	// commitment.
	tapProofRoot := p.TaprootAssetProof.Root(
		tapCommitmentKey, mssmt.EmptyLeafNode,
	)
	return NewTapCommitmentWithRoot(
		p.TaprootAssetProof.Version, tapProofRoot,
	), nil
}
