package address

import (
	"crypto/sha256"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightningnetwork/lnd/tlv"
)

// AddressTlvType represents the different TLV types for Address TLV records.
type AddressTLVType = tlv.Type

const (
	AddressVersion     AddressTLVType = 0
	AddressID          AddressTLVType = 2
	AddressFamilyKey   AddressTLVType = 3
	AddressScriptKey   AddressTLVType = 4
	AddressInternalKey AddressTLVType = 6
	AddressAmount      AddressTLVType = 8
	AddressType        AddressTLVType = 9
)

func NewAddressVersionRecord(version *asset.Version) tlv.Record {
	return tlv.MakeStaticRecord(
		AddressVersion, version, 1, asset.VersionEncoder, asset.VersionDecoder,
	)
}

func NewAddressIDRecord(id *asset.ID) tlv.Record {
	return tlv.MakeStaticRecord(
		AddressID, id, sha256.Size, asset.IDEncoder, asset.IDDecoder,
	)
}

func NewAddressFamilyKeyRecord(familyKey **btcec.PublicKey) tlv.Record {
	return tlv.MakeStaticRecord(
		AddressFamilyKey, familyKey, schnorr.PubKeyBytesLen,
		asset.SchnorrPubKeyEncoder, asset.SchnorrPubKeyDecoder,
	)
}

func NewAddressScriptKeyRecord(scriptKey *btcec.PublicKey) tlv.Record {
	return tlv.MakeStaticRecord(
		AddressScriptKey, scriptKey, schnorr.PubKeyBytesLen,
		asset.SchnorrPubKeyEncoder, asset.SchnorrPubKeyDecoder,
	)
}

func NewAddressInternalKeyRecord(internalKey *btcec.PublicKey) tlv.Record {
	return tlv.MakeStaticRecord(
		AddressInternalKey, internalKey, schnorr.PubKeyBytesLen,
		asset.SchnorrPubKeyEncoder, asset.SchnorrPubKeyDecoder,
	)
}

func NewAddressAmountRecord(amount *uint64) tlv.Record {
	recordSize := func() uint64 {
		return tlv.VarIntSize(*amount)
	}
	return tlv.MakeDynamicRecord(
		AddressAmount, amount, recordSize, asset.VarIntEncoder, asset.VarIntDecoder,
	)
}

func NewAddressTypeRecord(assetType *asset.Type) tlv.Record {
	return tlv.MakeStaticRecord(
		AddressType, assetType, 1, asset.TypeEncoder, asset.TypeDecoder,
	)
}
