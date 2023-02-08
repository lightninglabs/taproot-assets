package proof

import (
	"errors"
	"io"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightningnetwork/lnd/tlv"
)

var (
	// ErrInvalidTaprootProof is an error returned upon verifying an invalid
	// Taproot proof.
	ErrInvalidTaprootProof = errors.New("invalid taproot proof")

	// ErrInvalidTxMerkleProof is an error returned upon verifying an
	// invalid on-chain transaction merkle proof.
	ErrInvalidTxMerkleProof = errors.New("invalid transaction merkle proof")

	// ErrMissingExclusionProofs is an error returned upon noticing an
	// exclusion proof for a P2TR output is missing.
	ErrMissingExclusionProofs = errors.New("missing exclusion proof(s)")

	// ErrMissingSplitRootProof is an error returned upon noticing an
	// inclusion proof for a split root asset is missing.
	ErrMissingSplitRootProof = errors.New("missing split root proof")
)

// Proof encodes all of the data necessary to prove a valid state transition for
// an asset has occurred within an on-chain transaction.
type Proof struct {
	// PrevOut is the previous on-chain outpoint of the asset.
	PrevOut wire.OutPoint

	// BlockHeader is the current block header committing to the on-chain
	// transaction attempting an asset state transition.
	BlockHeader wire.BlockHeader

	// AnchorTx is the on-chain transaction attempting the asset state
	// transition.
	AnchorTx wire.MsgTx

	// TxMerkleProof is the merkle proof for AnchorTx used to prove its
	// inclusion within BlockHeader.
	//
	// TODO(roasbeef): also store height+index information?
	TxMerkleProof TxMerkleProof

	// Asset is the resulting asset after its state transition.
	Asset *asset.Asset

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

	// AdditionalInputs is a nested full proof for any additional inputs
	// found within the resulting asset.
	AdditionalInputs []File
}

// EncodeRecords returns the set of known TLV records to encode a Proof.
func (p *Proof) EncodeRecords() []tlv.Record {
	records := make([]tlv.Record, 0, 9)
	records = append(records, PrevOutRecord(&p.PrevOut))
	records = append(records, BlockHeaderRecord(&p.BlockHeader))
	records = append(records, AnchorTxRecord(&p.AnchorTx))
	records = append(records, TxMerkleProofRecord(&p.TxMerkleProof))
	if p.Asset != nil {
		records = append(records, AssetLeafRecord(&p.Asset))
	}
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
	if len(p.AdditionalInputs) > 0 {
		records = append(records, AdditionalInputsRecord(
			&p.AdditionalInputs,
		))
	}
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
		AdditionalInputsRecord(&p.AdditionalInputs),
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
