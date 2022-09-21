package address

import (
	"bytes"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightningnetwork/lnd/tlv"
)

// addressTlvType represents the different TLV types for Address TLV records.
type addressTLVType = tlv.Type

const (
	// addrVersionType is the TLV type of the addr version.
	addrVersionType addressTLVType = 0

	// addrAssetGenesisType is the TLV type of the asset genesis.
	addrAssetGenesisType addressTLVType = 2

	// addrFamKeyType is the TLV type of the family key of the asset.
	addrFamKeyType addressTLVType = 3

	// addrScriptKeyType is the TLV type of the script key for the asset.
	addrScriptKeyType addressTLVType = 4

	// addrInternalKeyType is the TLV type of the internal key for the asset.
	addrInternalKeyType addressTLVType = 6

	// addrAmountType is the TLV type of the amount of the asset.
	addrAmountType addressTLVType = 8
)

func newAddressVersionRecord(version *asset.Version) tlv.Record {
	return tlv.MakeStaticRecord(
		addrVersionType, version, 1, asset.VersionEncoder,
		asset.VersionDecoder,
	)
}

func newAddressGenesisRecord(genesis *asset.Genesis) tlv.Record {
	recordSize := func() uint64 {
		var (
			b   bytes.Buffer
			buf [8]byte
		)
		if err := asset.GenesisEncoder(&b, genesis, &buf); err != nil {
			panic(err)
		}
		return uint64(len(b.Bytes()))
	}
	return tlv.MakeDynamicRecord(
		addrAssetGenesisType, genesis, recordSize,
		asset.GenesisEncoder, asset.GenesisDecoder,
	)
}

func newAddressFamilyKeyRecord(familyKey **btcec.PublicKey) tlv.Record {
	return tlv.MakeStaticRecord(
		addrFamKeyType, familyKey, schnorr.PubKeyBytesLen,
		asset.SchnorrPubKeyEncoder, asset.SchnorrPubKeyDecoder,
	)
}

func newAddressScriptKeyRecord(scriptKey *btcec.PublicKey) tlv.Record {
	return tlv.MakeStaticRecord(
		addrScriptKeyType, scriptKey, schnorr.PubKeyBytesLen,
		schnorrPubKeyEncoder, schnorrPubKeyDecoder,
	)
}

func newAddressInternalKeyRecord(internalKey *btcec.PublicKey) tlv.Record {
	return tlv.MakeStaticRecord(
		addrInternalKeyType, internalKey, schnorr.PubKeyBytesLen,
		schnorrPubKeyEncoder, schnorrPubKeyDecoder,
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
