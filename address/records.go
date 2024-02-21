package address

import (
	"bytes"
	"net/url"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightningnetwork/lnd/tlv"
)

// addressTlvType represents the different TLV types for Address TLV records.
type addressTLVType = tlv.Type

const (
	// addrVersionType is the TLV type of the address format version.
	addrVersionType addressTLVType = 0

	// addrAssetVersionType is the TLV type of the asset version.
	addrAssetVersionType addressTLVType = 2

	// addrAssetIDType is the TLV type of the asset ID.
	addrAssetIDType addressTLVType = 4

	// addrGroupKeyType is the TLV type of the group key of the asset.
	addrGroupKeyType addressTLVType = 5

	// addrScriptKeyType is the TLV type of the script key for the asset.
	addrScriptKeyType addressTLVType = 6

	// addrInternalKeyType is the TLV type of the internal key for the asset.
	addrInternalKeyType addressTLVType = 8

	// addrTapscriptSiblingType is the TLV type of the tapscript sibling for
	// the asset commitment.
	addrTapscriptSiblingType addressTLVType = 9

	// addrAmountType is the TLV type of the amount of the asset.
	addrAmountType addressTLVType = 10

	// addrProofCourierType is the TLV type of the proof courier address.
	addrProofCourierAddrType addressTLVType = 12
)

func newAddressVersionRecord(version *Version) tlv.Record {
	return tlv.MakeStaticRecord(
		addrVersionType, version, 1, VersionEncoder, VersionDecoder,
	)
}

func newAddressAssetVersionRecord(version *asset.Version) tlv.Record {
	return tlv.MakeStaticRecord(
		addrAssetVersionType, version, 1, asset.VersionEncoder,
		asset.VersionDecoder,
	)
}

func newAddressAssetID(assetID *asset.ID) tlv.Record {
	return tlv.MakePrimitiveRecord(
		addrAssetIDType, (*[32]byte)(assetID),
	)
}

func newAddressGroupKeyRecord(groupKey **btcec.PublicKey) tlv.Record {
	return tlv.MakeStaticRecord(
		addrGroupKeyType, groupKey, btcec.PubKeyBytesLenCompressed,
		asset.CompressedPubKeyEncoder, asset.CompressedPubKeyDecoder,
	)
}

func newAddressScriptKeyRecord(scriptKey *btcec.PublicKey) tlv.Record {
	return tlv.MakeStaticRecord(
		addrScriptKeyType, scriptKey, btcec.PubKeyBytesLenCompressed,
		compressedPubKeyEncoder, compressedPubKeyDecoder,
	)
}

func newAddressInternalKeyRecord(internalKey *btcec.PublicKey) tlv.Record {
	return tlv.MakeStaticRecord(
		addrInternalKeyType, internalKey, btcec.PubKeyBytesLenCompressed,
		compressedPubKeyEncoder, compressedPubKeyDecoder,
	)
}

func newAddressTapscriptSiblingRecord(
	tapscriptSibling **commitment.TapscriptPreimage) tlv.Record {

	sizeFunc := func() uint64 {
		var buf bytes.Buffer
		err := commitment.TapscriptPreimageEncoder(
			&buf, tapscriptSibling, &[8]byte{},
		)
		if err != nil {
			panic(err)
		}
		return uint64(len(buf.Bytes()))
	}
	return tlv.MakeDynamicRecord(
		addrTapscriptSiblingType, tapscriptSibling, sizeFunc,
		commitment.TapscriptPreimageEncoder,
		commitment.TapscriptPreimageDecoder,
	)
}

func newAddressAmountRecord(amount *uint64) tlv.Record {
	recordSize := func() uint64 {
		return tlv.VarIntSize(*amount)
	}
	return tlv.MakeDynamicRecord(
		addrAmountType, amount, recordSize,
		asset.VarIntEncoder, asset.VarIntDecoder,
	)
}

func newProofCourierAddrRecord(addr *url.URL) tlv.Record {
	var addrBytes []byte
	if addr != nil {
		addrBytes = []byte((*addr).String())
	}
	recordSize := tlv.SizeVarBytes(&addrBytes)

	return tlv.MakeDynamicRecord(
		addrProofCourierAddrType, addr, recordSize,
		UrlEncoder, UrlDecoder,
	)
}
