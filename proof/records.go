package proof

import (
	"bytes"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightningnetwork/lnd/tlv"
)

const (
	PrevOutType          tlv.Type = 0
	BlockHeaderType      tlv.Type = 1
	AnchorTxType         tlv.Type = 2
	TxMerkleProofType    tlv.Type = 3
	AssetLeafType        tlv.Type = 4
	InclusionProofType   tlv.Type = 5
	ExclusionProofsType  tlv.Type = 6
	SplitRootProofType   tlv.Type = 7
	AdditionalInputsType tlv.Type = 8

	TaprootProofOutputIndexType     tlv.Type = 0
	TaprootProofInternalKeyType     tlv.Type = 1
	TaprootProofCommitmentProofType tlv.Type = 2
	TaprootProofTapscriptProofType  tlv.Type = 3

	// CommitmentProofTapSiblingPreimageType is the type of the TLV record
	// for the CommitmentProof's SiblingPreimage field. It continues the
	// count from where commitment.ProofTaroProofType left off.
	CommitmentProofTapSiblingPreimageType tlv.Type = 2

	TapscriptProofTapPreimage1 tlv.Type = 0
	TapscriptProofTapPreimage2 tlv.Type = 1
	TapscriptProofBIP86        tlv.Type = 2
)

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
	preimage **TapscriptPreimage) tlv.Record {

	sizeFunc := func() uint64 {
		// 1 byte for the type, and then the pre-image itself.
		return 1 + uint64(len((*preimage).SiblingPreimage))
	}
	return tlv.MakeDynamicRecord(
		CommitmentProofTapSiblingPreimageType, preimage, sizeFunc,
		TapscriptPreimageEncoder, TapscriptPreimageDecoder,
	)
}

func TapscriptProofTapPreimage1Record(preimage **TapscriptPreimage) tlv.Record {
	sizeFunc := func() uint64 {
		// 1 byte for the type, and then the pre-image itself.
		return 1 + uint64(len((*preimage).SiblingPreimage))
	}

	return tlv.MakeDynamicRecord(
		TapscriptProofTapPreimage1, preimage,
		sizeFunc, TapscriptPreimageEncoder, TapscriptPreimageDecoder,
	)
}

func TapscriptProofTapPreimage2Record(preimage **TapscriptPreimage) tlv.Record {
	sizeFunc := func() uint64 {
		// 1 byte for the type, and then the pre-image itself.
		return 1 + uint64(len((*preimage).SiblingPreimage))
	}

	return tlv.MakeDynamicRecord(
		TapscriptProofTapPreimage2, preimage,
		sizeFunc, TapscriptPreimageEncoder, TapscriptPreimageDecoder,
	)
}

func TapscriptProofBIP86Record(bip86 *bool) tlv.Record {
	return tlv.MakeStaticRecord(
		TapscriptProofBIP86, bip86, 1, BoolEncoder, BoolDecoder,
	)
}
