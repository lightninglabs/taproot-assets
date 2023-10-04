package commitment

import (
	"bytes"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightningnetwork/lnd/tlv"
)

const (
	AssetProofVersionType tlv.Type = 0
	AssetProofAssetIDType tlv.Type = 2
	AssetProofType        tlv.Type = 4

	TaprootAssetProofVersionType tlv.Type = 0
	TaprootAssetProofType        tlv.Type = 2

	ProofAssetProofType        tlv.Type = 1
	ProofTaprootAssetProofType tlv.Type = 2
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

func ProofTaprootAssetProofRecord(proof *TaprootAssetProof) tlv.Record {
	sizeFunc := func() uint64 {
		var buf bytes.Buffer
		err := TaprootAssetProofEncoder(&buf, proof, &[8]byte{})
		if err != nil {
			panic(err)
		}
		return uint64(len(buf.Bytes()))
	}
	return tlv.MakeDynamicRecord(
		ProofTaprootAssetProofType, proof, sizeFunc, TaprootAssetProofEncoder,
		TaprootAssetProofDecoder,
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

func TaprootAssetProofVersionRecord(version *asset.Version) tlv.Record {
	return tlv.MakeStaticRecord(
		TaprootAssetProofVersionType, version, 1, asset.VersionEncoder,
		asset.VersionDecoder,
	)
}

func TaprootAssetProofRecord(proof *mssmt.Proof) tlv.Record {
	sizeFunc := func() uint64 {
		var buf bytes.Buffer
		if err := proof.Compress().Encode(&buf); err != nil {
			panic(err)
		}
		return uint64(len(buf.Bytes()))
	}
	return tlv.MakeDynamicRecord(
		TaprootAssetProofType, proof, sizeFunc, TreeProofEncoder,
		TreeProofDecoder,
	)
}
