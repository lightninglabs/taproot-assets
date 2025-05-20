package proof

import (
	"bytes"
	"net/url"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightningnetwork/lnd/tlv"
)

const (
	VersionType          tlv.Type = 0
	PrevOutType          tlv.Type = 2
	BlockHeaderType      tlv.Type = 4
	AnchorTxType         tlv.Type = 6
	TxMerkleProofType    tlv.Type = 8
	AssetLeafType        tlv.Type = 10
	InclusionProofType   tlv.Type = 12
	ExclusionProofsType  tlv.Type = 13
	SplitRootProofType   tlv.Type = 15
	MetaRevealType       tlv.Type = 17
	AdditionalInputsType tlv.Type = 19
	ChallengeWitnessType tlv.Type = 21
	BlockHeightType      tlv.Type = 22
	GenesisRevealType    tlv.Type = 23
	GroupKeyRevealType   tlv.Type = 25
	AltLeavesType        tlv.Type = 27

	TaprootProofOutputIndexType     tlv.Type = 0
	TaprootProofInternalKeyType     tlv.Type = 2
	TaprootProofCommitmentProofType tlv.Type = 3
	TaprootProofTapscriptProofType  tlv.Type = 5

	// CommitmentProofTapSiblingPreimageType is the type of the TLV record
	// for the CommitmentProof's SiblingPreimage field. It continues the
	// count from where commitment.ProofTaprootAssetProofType left off.
	CommitmentProofTapSiblingPreimageType tlv.Type = 5

	// CommitmentProofSTXOProofsType is the type of the TLV record for the
	// Exclusion proof CommitmentProof's STXOProofs field.
	CommitmentProofSTXOProofsType tlv.Type = 7

	TapscriptProofTapPreimage1 tlv.Type = 1
	TapscriptProofTapPreimage2 tlv.Type = 3
	TapscriptProofBip86        tlv.Type = 4

	MetaRevealEncodingType           tlv.Type = 0
	MetaRevealDataType               tlv.Type = 2
	MetaRevealDecimalDisplay         tlv.Type = 5
	MetaRevealUniverseCommitments    tlv.Type = 7
	MetaRevealCanonicalUniversesType tlv.Type = 9
	MetaRevealDelegationKeyType      tlv.Type = 11
)

// KnownProofTypes is a set of all known proof TLV types. This set is asserted
// to be complete by a check in the BIP test vector unit tests.
var KnownProofTypes = fn.NewSet(
	VersionType, PrevOutType, BlockHeaderType, AnchorTxType,
	TxMerkleProofType, AssetLeafType, InclusionProofType,
	ExclusionProofsType, SplitRootProofType, MetaRevealType,
	AdditionalInputsType, ChallengeWitnessType, BlockHeightType,
	GenesisRevealType, GroupKeyRevealType, AltLeavesType,
)

// KnownTaprootProofTypes is a set of all known Taproot proof TLV types. This
// set is asserted to be complete by a check in the BIP test vector unit tests.
var KnownTaprootProofTypes = fn.NewSet(
	TaprootProofOutputIndexType, TaprootProofInternalKeyType,
	TaprootProofCommitmentProofType, TaprootProofTapscriptProofType,
)

// KnownCommitmentProofTypes is a set of all known commitment proof TLV types.
// This set is asserted to be complete by a check in the BIP test vector unit
// tests.
var KnownCommitmentProofTypes = fn.NewSet(
	commitment.ProofAssetProofType, commitment.ProofTaprootAssetProofType,
	CommitmentProofTapSiblingPreimageType, CommitmentProofSTXOProofsType,
)

// KnownTapscriptProofTypes is a set of all known Tapscript proof TLV types.
// This set is asserted to be complete by a check in the BIP test vector unit
// tests.
var KnownTapscriptProofTypes = fn.NewSet(
	TapscriptProofTapPreimage1, TapscriptProofTapPreimage2,
	TapscriptProofBip86,
)

// KnownMetaRevealTypes is a set of all known meta reveal TLV types. This set is
// asserted to be complete by a check in the BIP test vector unit tests.
var KnownMetaRevealTypes = fn.NewSet(
	MetaRevealEncodingType, MetaRevealDataType, MetaRevealDecimalDisplay,
	MetaRevealUniverseCommitments, MetaRevealCanonicalUniversesType,
	MetaRevealDelegationKeyType,
)

func VersionRecord(version *TransitionVersion) tlv.Record {
	return tlv.MakeStaticRecord(
		VersionType, version, 4, VersionEncoder, VersionDecoder,
	)
}

func PrevOutRecord(prevOut *wire.OutPoint) tlv.Record {
	return tlv.MakeStaticRecord(
		PrevOutType, prevOut, 32+4, asset.OutPointEncoder,
		asset.OutPointDecoder,
	)
}

func BlockHeaderRecord(header *wire.BlockHeader) tlv.Record {
	return tlv.MakeStaticRecord(
		BlockHeaderType, header, wire.MaxBlockHeaderPayload,
		BlockHeaderEncoder, BlockHeaderDecoder,
	)
}

func BlockHeightRecord(height *uint32) tlv.Record {
	return tlv.MakeStaticRecord(
		BlockHeightType, height, 4, tlv.EUint32, tlv.DUint32,
	)
}

func AnchorTxRecord(tx *wire.MsgTx) tlv.Record {
	sizeFunc := func() uint64 {
		return uint64(tx.SerializeSize())
	}
	return tlv.MakeDynamicRecord(
		AnchorTxType, tx, sizeFunc, TxEncoder, TxDecoder,
	)
}

func TxMerkleProofRecord(proof *TxMerkleProof) tlv.Record {
	sizeFunc := func() uint64 {
		var buf bytes.Buffer
		if err := proof.Encode(&buf); err != nil {
			panic(err)
		}
		return uint64(len(buf.Bytes()))
	}
	return tlv.MakeDynamicRecord(
		TxMerkleProofType, proof, sizeFunc, TxMerkleProofEncoder,
		TxMerkleProofDecoder,
	)
}

func AssetLeafRecord(a *asset.Asset) tlv.Record {
	sizeFunc := func() uint64 {
		var buf bytes.Buffer
		if err := a.Encode(&buf); err != nil {
			panic(err)
		}
		return uint64(len(buf.Bytes()))
	}
	return tlv.MakeDynamicRecord(
		AssetLeafType, a, sizeFunc, asset.LeafEncoder,
		asset.LeafDecoder,
	)
}

func InclusionProofRecord(proof *TaprootProof) tlv.Record {
	sizeFunc := func() uint64 {
		var buf bytes.Buffer
		err := TaprootProofEncoder(&buf, proof, &[8]byte{})
		if err != nil {
			panic(err)
		}
		return uint64(len(buf.Bytes()))
	}
	return tlv.MakeDynamicRecord(
		InclusionProofType, proof, sizeFunc, TaprootProofEncoder,
		TaprootProofDecoder,
	)
}

func ExclusionProofsRecord(proofs *[]TaprootProof) tlv.Record {
	sizeFunc := func() uint64 {
		var buf bytes.Buffer
		err := TaprootProofsEncoder(&buf, proofs, &[8]byte{})
		if err != nil {
			panic(err)
		}
		return uint64(len(buf.Bytes()))
	}
	return tlv.MakeDynamicRecord(
		ExclusionProofsType, proofs, sizeFunc, TaprootProofsEncoder,
		TaprootProofsDecoder,
	)
}

func SplitRootProofRecord(proof **TaprootProof) tlv.Record {
	sizeFunc := func() uint64 {
		var buf bytes.Buffer
		err := SplitRootProofEncoder(&buf, proof, &[8]byte{})
		if err != nil {
			panic(err)
		}
		return uint64(len(buf.Bytes()))
	}
	return tlv.MakeDynamicRecord(
		SplitRootProofType, proof, sizeFunc, SplitRootProofEncoder,
		SplitRootProofDecoder,
	)
}

func AdditionalInputsRecord(inputs *[]File) tlv.Record {
	sizeFunc := func() uint64 {
		var buf bytes.Buffer
		err := AdditionalInputsEncoder(&buf, inputs, &[8]byte{})
		if err != nil {
			panic(err)
		}
		return uint64(len(buf.Bytes()))
	}
	return tlv.MakeDynamicRecord(
		AdditionalInputsType, inputs, sizeFunc, AdditionalInputsEncoder,
		AdditionalInputsDecoder,
	)
}

func ChallengeWitnessRecord(challengeWitness *wire.TxWitness) tlv.Record {
	sizeFunc := func() uint64 {
		return uint64((*challengeWitness).SerializeSize())
	}
	return tlv.MakeDynamicRecord(
		ChallengeWitnessType, challengeWitness, sizeFunc,
		asset.TxWitnessEncoder, asset.TxWitnessDecoder,
	)
}

func TaprootProofOutputIndexRecord(idx *uint32) tlv.Record {
	return tlv.MakePrimitiveRecord(TaprootProofOutputIndexType, idx)
}

func TaprootProofInternalKeyRecord(internalKey **btcec.PublicKey) tlv.Record {
	return tlv.MakeStaticRecord(
		TaprootProofInternalKeyType, internalKey,
		btcec.PubKeyBytesLenCompressed,
		asset.CompressedPubKeyEncoder, asset.CompressedPubKeyDecoder,
	)
}

func TaprootProofCommitmentProofRecord(proof **CommitmentProof) tlv.Record {
	sizeFunc := func() uint64 {
		var buf bytes.Buffer
		err := CommitmentProofEncoder(&buf, proof, &[8]byte{})
		if err != nil {
			panic(err)
		}
		return uint64(len(buf.Bytes()))
	}
	return tlv.MakeDynamicRecord(
		TaprootProofCommitmentProofType, proof, sizeFunc,
		CommitmentProofEncoder, CommitmentProofDecoder,
	)
}

func TaprootProofTapscriptProofRecord(proof **TapscriptProof) tlv.Record {
	sizeFunc := func() uint64 {
		var buf bytes.Buffer
		err := TapscriptProofEncoder(&buf, proof, &[8]byte{})
		if err != nil {
			panic(err)
		}
		return uint64(len(buf.Bytes()))
	}
	return tlv.MakeDynamicRecord(
		TaprootProofTapscriptProofType, proof, sizeFunc,
		TapscriptProofEncoder, TapscriptProofDecoder,
	)
}

func CommitmentProofTapSiblingPreimageRecord(
	preimage **commitment.TapscriptPreimage) tlv.Record {

	sizeFunc := func() uint64 {
		var buf bytes.Buffer
		err := commitment.TapscriptPreimageEncoder(
			&buf, preimage, &[8]byte{},
		)
		if err != nil {
			panic(err)
		}
		return uint64(len(buf.Bytes()))
	}
	return tlv.MakeDynamicRecord(
		CommitmentProofTapSiblingPreimageType, preimage, sizeFunc,
		commitment.TapscriptPreimageEncoder,
		commitment.TapscriptPreimageDecoder,
	)
}

func CommitmentProofSTXOProofsRecord(
	stxoProofs *map[asset.SerializedKey]commitment.Proof) tlv.Record {

	sizeFunc := func() uint64 {
		var buf bytes.Buffer
		err := CommitmentProofsEncoder(
			&buf, stxoProofs, &[8]byte{},
		)
		if err != nil {
			panic(err)
		}
		return uint64(len(buf.Bytes()))
	}
	return tlv.MakeDynamicRecord(
		CommitmentProofSTXOProofsType, stxoProofs, sizeFunc,
		CommitmentProofsEncoder,
		CommitmentProofsDecoder,
	)
}

func TapscriptProofTapPreimage1Record(
	preimage **commitment.TapscriptPreimage) tlv.Record {

	sizeFunc := func() uint64 {
		var buf bytes.Buffer
		err := commitment.TapscriptPreimageEncoder(
			&buf, preimage, &[8]byte{},
		)
		if err != nil {
			panic(err)
		}
		return uint64(len(buf.Bytes()))
	}
	return tlv.MakeDynamicRecord(
		TapscriptProofTapPreimage1, preimage,
		sizeFunc, commitment.TapscriptPreimageEncoder,
		commitment.TapscriptPreimageDecoder,
	)
}

func TapscriptProofTapPreimage2Record(
	preimage **commitment.TapscriptPreimage) tlv.Record {

	sizeFunc := func() uint64 {
		var buf bytes.Buffer
		err := commitment.TapscriptPreimageEncoder(
			&buf, preimage, &[8]byte{},
		)
		if err != nil {
			panic(err)
		}
		return uint64(len(buf.Bytes()))
	}
	return tlv.MakeDynamicRecord(
		TapscriptProofTapPreimage2, preimage,
		sizeFunc, commitment.TapscriptPreimageEncoder,
		commitment.TapscriptPreimageDecoder,
	)
}

func TapscriptProofBip86Record(bip86 *bool) tlv.Record {
	return tlv.MakeStaticRecord(
		TapscriptProofBip86, bip86, 1, BoolEncoder, BoolDecoder,
	)
}

func MetaRevealRecord(reveal **MetaReveal) tlv.Record {
	sizeFunc := func() uint64 {
		var buf bytes.Buffer
		err := MetaRevealEncoder(&buf, reveal, &[8]byte{})
		if err != nil {
			panic(err)
		}
		return uint64(len(buf.Bytes()))
	}
	return tlv.MakeDynamicRecord(
		MetaRevealType, reveal, sizeFunc, MetaRevealEncoder,
		MetaRevealDecoder,
	)
}

func MetaRevealTypeRecord(metaType *MetaType) tlv.Record {
	return tlv.MakeStaticRecord(
		MetaRevealEncodingType, metaType, 1, MetaTypeEncoder,
		MetaTypeDecoder,
	)
}

func MetaRevealDataRecord(data *[]byte) tlv.Record {
	sizeFunc := func() uint64 {
		if data == nil {
			return 0
		}
		return uint64(len(*data))
	}
	return tlv.MakeDynamicRecord(
		MetaRevealDataType, data, sizeFunc, tlv.EVarBytes,
		asset.DVarBytesWithLimit(MetaDataMaxSizeBytes),
	)
}

func MetaRevealDecimalDisplayRecord(
	decimalDisplay *fn.Option[uint32]) tlv.Record {

	// If the option is not set, we'll encode it as a zero-length record.
	// But because we'll not include the record at all if it's not set at
	// the call site when encoding, this will not be the case for this
	// specific record.
	var size uint64
	if decimalDisplay != nil && decimalDisplay.IsSome() {
		size = 4
	}

	return tlv.MakeStaticRecord(
		MetaRevealDecimalDisplay, decimalDisplay, size,
		EUint32Option, DUint32Option,
	)
}

func MetaRevealUniverseCommitmentsRecord(useCommitments *bool) tlv.Record {
	return tlv.MakeStaticRecord(
		MetaRevealUniverseCommitments, useCommitments, 1,
		BoolEncoder, BoolDecoder,
	)
}

func MetaRevealCanonicalUniversesRecord(
	addrs *fn.Option[[]url.URL]) tlv.Record {

	// If the option is not set, or it's an empty slice, we'll encode it as
	// a zero-length record. But because we'll not include the record at all
	// if it's not set at the call site when encoding, this will not be the
	// case for this specific record.
	recordSize := func() uint64 {
		var (
			b   bytes.Buffer
			buf [8]byte
		)
		if err := UrlSliceOptionEncoder(&b, addrs, &buf); err != nil {
			panic(err)
		}
		return uint64(len(b.Bytes()))
	}
	return tlv.MakeDynamicRecord(
		MetaRevealCanonicalUniversesType, addrs, recordSize,
		UrlSliceOptionEncoder, UrlSliceOptionDecoder,
	)
}

func MetaRevealDelegationKeyRecord(key *fn.Option[btcec.PublicKey]) tlv.Record {
	// If the option is not set, we'll encode it as a zero-length record.
	// But because we'll not include the record at all if it's not set at
	// the call site when encoding, this will not be the case for this
	// specific record.
	var size uint64
	if key != nil && key.IsSome() {
		size = btcec.PubKeyBytesLenCompressed
	}

	return tlv.MakeStaticRecord(
		MetaRevealDelegationKeyType, key, size,
		PublicKeyOptionEncoder, PublicKeyOptionDecoder,
	)
}

func GenesisRevealRecord(genesis **asset.Genesis) tlv.Record {
	recordSize := func() uint64 {
		var (
			b   bytes.Buffer
			buf [8]byte
		)
		if err := GenesisRevealEncoder(&b, genesis, &buf); err != nil {
			panic(err)
		}
		return uint64(len(b.Bytes()))
	}
	return tlv.MakeDynamicRecord(
		GenesisRevealType, genesis, recordSize, GenesisRevealEncoder,
		GenesisRevealDecoder,
	)
}

func GroupKeyRevealRecord(reveal *asset.GroupKeyReveal) tlv.Record {
	// recordSize returns the size of the record in bytes. This is used to
	// determine the size of the record when encoding it.
	recordSize := func() uint64 {
		if reveal == nil || *reveal == nil {
			return 0
		}

		var (
			b   bytes.Buffer
			buf [8]byte
		)
		err := asset.GroupKeyRevealEncoder(&b, reveal, &buf)
		if err != nil {
			panic(err)
		}

		return uint64(len(b.Bytes()))
	}

	return tlv.MakeDynamicRecord(
		GroupKeyRevealType, reveal, recordSize,
		asset.GroupKeyRevealEncoder, asset.GroupKeyRevealDecoder,
	)
}

func AltLeavesRecord(leaves *[]asset.AltLeaf[asset.Asset]) tlv.Record {
	sizeFunc := func() uint64 {
		var buf bytes.Buffer
		err := asset.AltLeavesEncoder(&buf, leaves, &[8]byte{})
		if err != nil {
			panic(err)
		}
		return uint64(len(buf.Bytes()))
	}
	return tlv.MakeDynamicRecord(
		AltLeavesType, leaves, sizeFunc, asset.AltLeavesEncoder,
		asset.AltLeavesDecoder,
	)
}
