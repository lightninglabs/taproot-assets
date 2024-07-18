package commitment

import (
	"bytes"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
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

// KnownAssetProofTypes is a set of all known asset proof TLV types. This set
// is asserted to be complete by a check in the BIP test vector unit tests.
var KnownAssetProofTypes = fn.NewSet(
	AssetProofVersionType, AssetProofAssetIDType, AssetProofType,
)

// KnownTaprootAssetProofTypes is a set of all known taproot asset proof TLV
// types. This set is asserted to be complete by a check in the BIP test vector
// unit tests.
var KnownTaprootAssetProofTypes = fn.NewSet(
	TaprootAssetProofVersionType, TaprootAssetProofType,
)

// KnownProofTypes is a set of all known proof TLV types. This set is asserted
// to be complete by a check in the BIP test vector unit tests.
var KnownProofTypes = fn.NewSet(
	ProofAssetProofType, ProofTaprootAssetProofType,
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
		ProofTaprootAssetProofType, proof, sizeFunc,
		TaprootAssetProofEncoder, TaprootAssetProofDecoder,
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

func TaprootAssetProofVersionRecord(version *TapCommitmentVersion) tlv.Record {
	return tlv.MakeStaticRecord(
		TaprootAssetProofVersionType, version, 1,
		TapCommitmentVersionEncoder, TapCommitmentVersionDecoder,
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
