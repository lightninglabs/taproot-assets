package proof

import (
	"errors"
	"io"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightningnetwork/lnd/tlv"
)

var (
	// ErrInvalidTxMerkleProof is an error returned upon verifying an
	// invalid on-chain transaction merkle proof.
	ErrInvalidTxMerkleProof = errors.New("invalid transaction merkle proof")

	// ErrMissingExclusionProofs is an error returned upon noticing an
	// exclusion proof for a P2TR output is missing.
	ErrMissingExclusionProofs = errors.New("missing exclusion proof(s)")

	// ErrMissingSplitRootProof is an error returned upon noticing an
	// inclusion proof for a split root asset is missing.
	ErrMissingSplitRootProof = errors.New("missing split root proof")

	// ErrNonGenesisAssetWithMetaReveal is an error returned if an asset
	// proof has a meta reveal but isn't itself a genesis asset.
	ErrNonGenesisAssetWithMetaReveal = errors.New("non genesis asset has " +
		"meta reveal")

	// ErrMetaRevealMismatch is an error returned if the hash of the meta
	// reveal doesn't match the actual asset meta hash.
	ErrMetaRevealMismatch = errors.New("meta reveal doesn't match meta " +
		"hash")

	// ErrMetaRevealRequired is an error returned if an asset proof for a
	// genesis asset has a non-zero metahash, but doesn't have a meta
	// reveal.
	ErrMetaRevealRequired = errors.New("meta reveal required")
)

// Proof encodes all of the data necessary to prove a valid state transition for
// an asset has occurred within an on-chain transaction.
type Proof struct {
	// PrevOut is the previous on-chain outpoint of the asset.
	PrevOut wire.OutPoint

	// BlockHeader is the current block header committing to the on-chain
	// transaction attempting an asset state transition.
	BlockHeader wire.BlockHeader

	// BlockHeight is the height of the current block committing to the
	// on-chain transaction attempting an asset state transition.
	BlockHeight uint32

	// AnchorTx is the on-chain transaction attempting the asset state
	// transition.
	AnchorTx wire.MsgTx

	// TxMerkleProof is the merkle proof for AnchorTx used to prove its
	// inclusion within BlockHeader.
	//
	// TODO(roasbeef): also store height+index information?
	TxMerkleProof TxMerkleProof

	// Asset is the resulting asset after its state transition.
	Asset asset.Asset

	// InclusionProof is the TaprootProof proving the new inclusion of the
	// resulting asset within AnchorTx.
	InclusionProof TaprootProof

	// ExclusionProofs is the set of TaprootProofs proving the exclusion of
	// the resulting asset from all other Taproot outputs within AnchorTx.
	ExclusionProofs []TaprootProof

	// SplitRootProof is an optional TaprootProof needed if this asset is
	// the result of a split. SplitRootProof proves inclusion of the root
	// asset of the split.
	SplitRootProof *TaprootProof

	// MetaReveal is the set of bytes that were revealed to prove the
	// derivation of the meta data hash contained in the genesis asset.
	//
	// TODO(roasbeef): use even/odd framing here?
	//
	// NOTE: This field is optional, and can only be specified if the asset
	// above is a genesis asset. If specified, then verifiers _should_ also
	// verify the hashes match up.
	MetaReveal *MetaReveal

	// AdditionalInputs is a nested full proof for any additional inputs
	// found within the resulting asset.
	AdditionalInputs []File

	// ChallengeWitness is an optional virtual transaction witness that
	// serves as an ownership proof for the asset. If this is non-nil, then
	// it is a valid transfer witness for a 1-input, 1-output virtual
	// transaction that spends the asset in this proof and sends it to the
	// NUMS key, to prove that the creator of the proof is able to produce
	// a valid signature to spend the asset.
	ChallengeWitness wire.TxWitness
}

// EncodeRecords returns the set of known TLV records to encode a Proof.
func (p *Proof) EncodeRecords() []tlv.Record {
	records := make([]tlv.Record, 0, 9)
	records = append(records, PrevOutRecord(&p.PrevOut))
	records = append(records, BlockHeaderRecord(&p.BlockHeader))
	records = append(records, AnchorTxRecord(&p.AnchorTx))
	records = append(records, TxMerkleProofRecord(&p.TxMerkleProof))
	records = append(records, AssetLeafRecord(&p.Asset))
	records = append(records, InclusionProofRecord(&p.InclusionProof))
	if len(p.ExclusionProofs) > 0 {
		records = append(records, ExclusionProofsRecord(
			&p.ExclusionProofs,
		))
	}
	if p.SplitRootProof != nil {
		records = append(records, SplitRootProofRecord(
			&p.SplitRootProof,
		))
	}
	if p.MetaReveal != nil {
		records = append(records, MetaRevealRecord(&p.MetaReveal))
	}
	if len(p.AdditionalInputs) > 0 {
		records = append(records, AdditionalInputsRecord(
			&p.AdditionalInputs,
		))
	}
	if p.ChallengeWitness != nil {
		records = append(records, ChallengeWitnessRecord(
			&p.ChallengeWitness,
		))
	}
	records = append(records, BlockHeightRecord(&p.BlockHeight))
	return records
}

// DecodeRecords returns the set of known TLV records to decode a Proof.
func (p *Proof) DecodeRecords() []tlv.Record {
	return []tlv.Record{
		PrevOutRecord(&p.PrevOut),
		BlockHeaderRecord(&p.BlockHeader),
		AnchorTxRecord(&p.AnchorTx),
		TxMerkleProofRecord(&p.TxMerkleProof),
		AssetLeafRecord(&p.Asset),
		InclusionProofRecord(&p.InclusionProof),
		ExclusionProofsRecord(&p.ExclusionProofs),
		SplitRootProofRecord(&p.SplitRootProof),
		MetaRevealRecord(&p.MetaReveal),
		AdditionalInputsRecord(&p.AdditionalInputs),
		ChallengeWitnessRecord(&p.ChallengeWitness),
		BlockHeightRecord(&p.BlockHeight),
	}
}

// Encode encodes a Proof into `w`.
func (p *Proof) Encode(w io.Writer) error {
	stream, err := tlv.NewStream(p.EncodeRecords()...)
	if err != nil {
		return err
	}
	return stream.Encode(w)
}

// Decode decodes a Proof from `r`.
func (p *Proof) Decode(r io.Reader) error {
	stream, err := tlv.NewStream(p.DecodeRecords()...)
	if err != nil {
		return err
	}
	return stream.Decode(r)
}
