package commitment

import (
	"bytes"

	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/mssmt"
	"github.com/lightningnetwork/lnd/tlv"
)

const (
	AssetProofVersionType tlv.Type = 0
	AssetProofAssetIDType tlv.Type = 1
	AssetProofType        tlv.Type = 2

	TaroProofVersionType tlv.Type = 0
	TaroProofType        tlv.Type = 1

	ProofAssetProofType tlv.Type = 0
	ProofTaroProofType  tlv.Type = 1
)

func ProofAssetProofRecord(proof **AssetProof) tlv.Record {
	sizeFunc := func() uint64 {
		var buf bytes.Buffer
		err := AssetProofEncoder(&buf, proof, &[8]byte{})
		if err != nil {
			panic(err)
		}
		return uint64(len(buf.Bytes()))
	}
	return tlv.MakeDynamicRecord(
		ProofAssetProofType, proof, sizeFunc,
		AssetProofEncoder, AssetProofDecoder,
	)
}

func ProofTaroProofRecord(proof *TaroProof) tlv.Record {
	sizeFunc := func() uint64 {
		var buf bytes.Buffer
		err := TaroProofEncoder(&buf, proof, &[8]byte{})
		if err != nil {
			panic(err)
		}
		return uint64(len(buf.Bytes()))
	}
	return tlv.MakeDynamicRecord(
		ProofTaroProofType, proof, sizeFunc, TaroProofEncoder,
		TaroProofDecoder,
	)
}

func AssetProofVersionRecord(version *asset.Version) tlv.Record {
	return tlv.MakeStaticRecord(
		AssetProofVersionType, version, 1, asset.VersionEncoder,
		asset.VersionDecoder,
	)
}

func AssetProofAssetIDRecord(assetID *[32]byte) tlv.Record {
	return tlv.MakePrimitiveRecord(AssetProofAssetIDType, assetID)
}

func AssetProofRecord(proof *mssmt.Proof) tlv.Record {
	sizeFunc := func() uint64 {
		var buf bytes.Buffer
		if err := proof.Compress().Encode(&buf); err != nil {
			panic(err)
		}
		return uint64(len(buf.Bytes()))
	}
	return tlv.MakeDynamicRecord(
		AssetProofType, proof, sizeFunc, TreeProofEncoder,
		TreeProofDecoder,
	)
}

func TaroProofVersionRecord(version *asset.Version) tlv.Record {
	return tlv.MakeStaticRecord(
		TaroProofVersionType, version, 1, asset.VersionEncoder,
		asset.VersionDecoder,
	)
}

func TaroProofRecord(proof *mssmt.Proof) tlv.Record {
	sizeFunc := func() uint64 {
		var buf bytes.Buffer
		if err := proof.Compress().Encode(&buf); err != nil {
			panic(err)
		}
		return uint64(len(buf.Bytes()))
	}
	return tlv.MakeDynamicRecord(
		TaroProofType, proof, sizeFunc, TreeProofEncoder,
		TreeProofDecoder,
	)
}
