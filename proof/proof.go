package proof

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightningnetwork/lnd/input"
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

	// ErrNonGenesisAssetWithGenesisReveal is an error returned if an asset
	// proof for a non-genesis asset contains a genesis reveal.
	ErrNonGenesisAssetWithGenesisReveal = errors.New("non genesis asset " +
		"has genesis reveal")

	// ErrGenesisRevealRequired is an error returned if an asset proof for a
	// genesis asset is missing a genesis reveal.
	ErrGenesisRevealRequired = errors.New("genesis reveal required")

	// ErrGenesisRevealAssetIDMismatch is an error returned if an asset
	// proof for a genesis asset has a genesis reveal that is inconsistent
	// with the asset ID.
	ErrGenesisRevealAssetIDMismatch = errors.New("genesis reveal asset " +
		"ID mismatch")

	// ErrGenesisRevealPrevOutMismatch is an error returned if an asset
	// proof for a genesis asset has a genesis reveal where the prev out
	// doesn't match the proof TLV field.
	ErrGenesisRevealPrevOutMismatch = errors.New("genesis reveal prev " +
		"out mismatch")

	// ErrGenesisRevealMetaRevealRequired is an error returned if an asset
	// proof for a genesis asset has a non-zero meta hash, but doesn't have
	// a meta reveal.
	ErrGenesisRevealMetaRevealRequired = errors.New("genesis meta reveal " +
		"required")

	// ErrGenesisRevealMetaHashMismatch is an error returned if an asset
	// proof for a genesis asset has a genesis reveal where the meta hash
	// doesn't match the proof TLV field.
	ErrGenesisRevealMetaHashMismatch = errors.New("genesis reveal meta " +
		"hash mismatch")

	// ErrGenesisRevealOutputIndexMismatch is an error returned if an asset
	// proof for a genesis asset has a genesis reveal where the output index
	// doesn't match the proof TLV field.
	ErrGenesisRevealOutputIndexMismatch = errors.New("genesis reveal " +
		"output index mismatch")

	// ErrNonGenesisAssetWithGroupKeyReveal is an error returned if an asset
	// proof for a non-genesis asset contains a group key reveal.
	ErrNonGenesisAssetWithGroupKeyReveal = errors.New("non genesis asset " +
		"has group key reveal")

	// ErrGroupKeyRevealMismatch is an error returned if an asset proof for
	// a genesis asset has a group key reveal that doesn't match the group
	// key.
	ErrGroupKeyRevealMismatch = errors.New("group key reveal doesn't " +
		"match group key")

	// ErrGroupKeyRevealRequired is an error returned if an asset proof for
	// a genesis asset with a group key is missing a group key reveal.
	ErrGroupKeyRevealRequired = errors.New("group key reveal required")

	// ErrGroupKeyRequired is an error returned if an asset proof for a
	// genesis asset is missing a group key when it should have one.
	ErrGroupKeyRequired = errors.New("group key required")

	// ErrGroupKeyUnknown is an error returned if an asset proof for a
	// group asset references an asset group that has not been previously
	// verified. This can apply to genesis proofs for reissaunces into a
	// group, and any further transfer of a grouped asset.
	ErrGroupKeyUnknown = errors.New("group key not known")

	// ErrProofInvalid is the error that's returned when a proof file is
	// invalid.
	ErrProofInvalid = errors.New("proof is invalid")

	// RegtestTestVectorName is the name of the test vector file that is
	// generated/updated by an actual integration test run on regtest. It is
	// exported here, so we can use it in the integration tests.
	RegtestTestVectorName = "proof_tlv_encoding_regtest.json"

	// RegtestProofFileName is the name of the file that is generated/
	// updated by an actual integration test run on regtest. It is exported
	// here, so we can use it in the integration tests.
	RegtestProofFileName = "proof-file.hex"

	// RegtestProofName is the name of the file that is generated/updated by
	// an actual integration test run on regtest. It is exported here, so we
	// can use it in the integration tests.
	RegtestProofName = "proof.hex"

	// RegtestOwnershipProofName is the name of the ownership proof that is
	// generated/updated by an actual integration test run on regtest. It is
	// exported here, so we can use it in the integration tests.
	RegtestOwnershipProofName = "ownership-proof.hex"
)

const (
	// PrefixMagicBytesLength is the length of the magic bytes that are
	// prefixed to individual proofs or proof files.
	PrefixMagicBytesLength = 4

	// MaxNumTaprootProofs is the maximum number of Taproot proofs there can
	// be in a proof. This limit represents the maximum block size in vBytes
	// divided by the size of a single P2TR output and is therefore only a
	// theoretical limit that can never be reached in practice.
	MaxNumTaprootProofs uint64 = blockchain.MaxBlockBaseSize /
		input.P2TRSize

	// MaxTaprootProofSizeBytes is the maximum size of a single Taproot
	// proof. A Taproot proof can contain a commitment proof which at
	// maximum can contain two MS-SMT proofs that max out at around 10k
	// bytes each (in the worst case).
	MaxTaprootProofSizeBytes = tlv.MaxRecordSize

	// MerkleProofMaxNodes is the maximum number of nodes a merkle proof can
	// contain. This is log2(max_num_txs_in_block) + 1, where max number of
	// transactions in a block is limited to be 17k (theoretical smallest
	// transaction that can be serialized, which is 1 input + 1 output +
	// transaction overhead = 59 bytes, then 1MB block size divided by that
	// and rounded up).
	MerkleProofMaxNodes = 15
)

var (
	// PrefixMagicBytes are the magic bytes that are prefixed to an
	// individual transition or mint proof when encoding it. This is the
	// ASCII encoding of the string "TAPP" (Taproot Assets Protocol Proof)
	// in hex.
	PrefixMagicBytes = [PrefixMagicBytesLength]byte{0x54, 0x41, 0x50, 0x50}

	// FilePrefixMagicBytes are the magic bytes that are prefixed to a proof
	// file when encoding it. This is the ASCII encoding of the string
	// "TAPF" (Taproot Assets Protocol File) in hex.
	FilePrefixMagicBytes = [PrefixMagicBytesLength]byte{
		0x54, 0x41, 0x50, 0x46,
	}
)

// IsSingleProof returns true if the given blob is an encoded individual
// mint/transition proof.
func IsSingleProof(blob Blob) bool {
	if len(blob) < PrefixMagicBytesLength {
		return false
	}

	return bytes.Equal(blob[:PrefixMagicBytesLength], PrefixMagicBytes[:])
}

// IsProofFile returns true if the given blob is an encoded proof file.
func IsProofFile(blob Blob) bool {
	if len(blob) < PrefixMagicBytesLength {
		return false
	}

	return bytes.Equal(
		blob[:PrefixMagicBytesLength], FilePrefixMagicBytes[:],
	)
}

// CheckMaxFileSize checks that the given blob is not larger than the maximum
// file size.
func CheckMaxFileSize(blob Blob) error {
	if len(blob) > FileMaxProofSizeBytes {
		return fmt.Errorf("file exceeds maximum size of %d bytes",
			FileMaxProofSizeBytes)
	}

	return nil
}

// UpdateCallback is a callback that is called when proofs are updated because
// of a re-org.
type UpdateCallback func([]*Proof) error

// Watcher is used to watch new proofs for their anchor transaction to be
// confirmed safely with a minimum number of confirmations.
type Watcher interface {
	// WatchProofs adds new proofs to the re-org watcher for their anchor
	// transaction to be watched until it reaches a safe confirmation depth.
	WatchProofs(newProofs []*Proof, onProofUpdate UpdateCallback) error

	// MaybeWatch inspects the given proof file for any proofs that are not
	// yet buried sufficiently deep and adds them to the re-org watcher.
	MaybeWatch(file *File, onProofUpdate UpdateCallback) error

	// ShouldWatch returns true if the proof is for a block that is not yet
	// sufficiently deep to be considered safe.
	ShouldWatch(proof *Proof) bool

	// DefaultUpdateCallback returns the default implementation for the
	// update callback that is called when a proof is updated. This
	// implementation will replace the old proof in the proof archiver
	// (multi-archive) with the new one.
	DefaultUpdateCallback() UpdateCallback
}

// TransitionVersion denotes the versioning scheme for an individual state
// transition proof.
type TransitionVersion uint32

const (
	// TransitionV0 is the first version of the state transition proof.
	TransitionV0 TransitionVersion = 0
)

// Proof encodes all of the data necessary to prove a valid state transition for
// an asset has occurred within an on-chain transaction.
type Proof struct {
	// Version is the version of the state transition proof.
	Version TransitionVersion

	// PrevOut is the previous on-chain outpoint of the asset. This outpoint
	// is that of the first on-chain input. Outpoints which correspond to
	// the other inputs can be found in AdditionalInputs.
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

	// GenesisReveal is the Genesis information for an asset, that must be
	// provided for minting proofs, and must be empty for non-minting
	// proofs. This allows for derivation of the asset ID. If the asset is
	// part of an asset group, the Genesis information is also used for
	// rederivation of the asset group key.
	GenesisReveal *asset.Genesis

	// GroupKeyReveal is an optional set of bytes that represent the public
	// key and Tapscript root used to derive the final tweaked group key for
	// the asset group. This field must be provided for issuance proofs of
	// grouped assets.
	GroupKeyReveal *asset.GroupKeyReveal
}

// OutPoint returns the outpoint that commits to the asset associated with this
// proof.
func (p *Proof) OutPoint() wire.OutPoint {
	return wire.OutPoint{
		Hash:  p.AnchorTx.TxHash(),
		Index: p.InclusionProof.OutputIndex,
	}
}

// EncodeRecords returns the set of known TLV records to encode a Proof.
func (p *Proof) EncodeRecords() []tlv.Record {
	records := make([]tlv.Record, 0, 15)
	records = append(records, VersionRecord(&p.Version))
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
	if p.GenesisReveal != nil {
		records = append(records, GenesisRevealRecord(&p.GenesisReveal))
	}
	if p.GroupKeyReveal != nil {
		records = append(records, GroupKeyRevealRecord(
			&p.GroupKeyReveal,
		))
	}
	return records
}

// DecodeRecords returns the set of known TLV records to decode a Proof.
func (p *Proof) DecodeRecords() []tlv.Record {
	return []tlv.Record{
		VersionRecord(&p.Version),
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
		GenesisRevealRecord(&p.GenesisReveal),
		GroupKeyRevealRecord(&p.GroupKeyReveal),
	}
}

// Encode encodes a Proof into `w`.
func (p *Proof) Encode(w io.Writer) error {
	num, err := w.Write(PrefixMagicBytes[:])
	if err != nil {
		return err
	}
	if num != PrefixMagicBytesLength {
		return errors.New("failed to write prefix magic bytes")
	}

	stream, err := tlv.NewStream(p.EncodeRecords()...)
	if err != nil {
		return err
	}
	return stream.Encode(w)
}

// Decode decodes a Proof from `r`.
func (p *Proof) Decode(r io.Reader) error {
	var prefixMagicBytes [PrefixMagicBytesLength]byte
	num, err := r.Read(prefixMagicBytes[:])
	if err != nil {
		return err
	}
	if num != PrefixMagicBytesLength {
		return errors.New("failed to read prefix magic bytes")
	}

	if prefixMagicBytes != PrefixMagicBytes {
		return fmt.Errorf("invalid prefix magic bytes, expected %s, "+
			"got %s", string(PrefixMagicBytes[:]),
			string(prefixMagicBytes[:]))
	}

	stream, err := tlv.NewStream(p.DecodeRecords()...)
	if err != nil {
		return err
	}

	// Note, we can't use the DecodeP2P method here, because the additional
	// inputs records might be larger than 64k each. Instead, we add
	// individual limits to each record.
	return stream.Decode(r)
}

// IsUnknownVersion returns true if a proof has a version that is not recognized
// by this implementation of tap.
func (p *Proof) IsUnknownVersion() bool {
	switch p.Version {
	case TransitionV0:
		return false
	default:
		return true
	}
}

// SparseDecode can be used to decode a proof from a reader without decoding
// and parsing the entire thing. This handles ignoring the magic bytes, and
// will decode directly into the target records.
func SparseDecode(r io.Reader, records ...tlv.Record) error {
	// The very first byte of the serialized proof is a magic byte, so
	// we'll read one byte to skip it.
	var magicBytes [PrefixMagicBytesLength]byte
	_, err := r.Read(magicBytes[:])
	if err != nil {
		return err
	}

	if magicBytes != PrefixMagicBytes {
		return fmt.Errorf("invalid prefix magic bytes, expected %s, "+
			"got %s", string(PrefixMagicBytes[:]),
			string(magicBytes[:]))
	}

	proofStream, err := tlv.NewStream(records...)
	if err != nil {
		return err
	}

	return proofStream.Decode(r)
}
