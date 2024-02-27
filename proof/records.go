package proof

import (
	"bytes"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
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

	TaprootProofOutputIndexType     tlv.Type = 0
	TaprootProofInternalKeyType     tlv.Type = 2
	TaprootProofCommitmentProofType tlv.Type = 3
	TaprootProofTapscriptProofType  tlv.Type = 5

	// CommitmentProofTapSiblingPreimageType is the type of the TLV record
	// for the CommitmentProof's SiblingPreimage field. It continues the
	// count from where commitment.ProofTaprootAssetProofType left off.
	CommitmentProofTapSiblingPreimageType tlv.Type = 5

	TapscriptProofTapPreimage1 tlv.Type = 1
	TapscriptProofTapPreimage2 tlv.Type = 3
	TapscriptProofBip86        tlv.Type = 4

	MetaRevealEncodingType tlv.Type = 0
	MetaRevealDataType     tlv.Type = 2
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

func GroupKeyRevealRecord(reveal **asset.GroupKeyReveal) tlv.Record {
	recordSize := func() uint64 {
		if reveal == nil || *reveal == nil {
			return 0
		}
		r := *reveal
		return uint64(
			btcec.PubKeyBytesLenCompressed + len(r.TapscriptRoot),
		)
	}
	return tlv.MakeDynamicRecord(
		GroupKeyRevealType, reveal, recordSize, GroupKeyRevealEncoder,
		GroupKeyRevealDecoder,
	)
}
