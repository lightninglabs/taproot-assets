package asset

import (
	"bytes"
	"crypto/sha256"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightningnetwork/lnd/tlv"
)

// LeafTlvType represents the different TLV types for Asset Leaf TLV records.
type LeafTlvType = tlv.Type

const (
	LeafVersion             LeafTlvType = 0
	LeafGenesis             LeafTlvType = 2
	LeafType                LeafTlvType = 4
	LeafAmount              LeafTlvType = 6
	LeafLockTime            LeafTlvType = 7
	LeafRelativeLockTime    LeafTlvType = 9
	LeafPrevWitness         LeafTlvType = 11
	LeafSplitCommitmentRoot LeafTlvType = 13
	LeafScriptVersion       LeafTlvType = 14
	LeafScriptKey           LeafTlvType = 16
	LeafGroupKey            LeafTlvType = 17

	// Types for future asset format.
	LeafAssetID LeafTlvType = 11
)

// WitnessTlvType represents the different TLV types for Asset Witness TLV
// records.
type WitnessTlvType = tlv.Type

const (
	WitnessPrevID          WitnessTlvType = 1
	WitnessTxWitness       WitnessTlvType = 3
	WitnessSplitCommitment WitnessTlvType = 5
)

func NewLeafVersionRecord(version *Version) tlv.Record {
	return tlv.MakeStaticRecord(
		LeafVersion, version, 1, VersionEncoder, VersionDecoder,
	)
}

func NewLeafIDRecord(id *ID) tlv.Record {
	const recordSize = sha256.Size
	return tlv.MakeStaticRecord(
		LeafAssetID, id, recordSize, IDEncoder, IDDecoder,
	)
}

func NewLeafGenesisRecord(genesis *Genesis) tlv.Record {
	recordSize := func() uint64 {
		var (
			b   bytes.Buffer
			buf [8]byte
		)
		if err := GenesisEncoder(&b, genesis, &buf); err != nil {
			panic(err)
		}
		return uint64(len(b.Bytes()))
	}
	return tlv.MakeDynamicRecord(
		LeafGenesis, genesis, recordSize, GenesisEncoder, GenesisDecoder,
	)
}

func NewLeafTypeRecord(assetType *Type) tlv.Record {
	return tlv.MakeStaticRecord(
		LeafType, assetType, 1, TypeEncoder, TypeDecoder,
	)
}

func NewLeafAmountRecord(amount *uint64) tlv.Record {
	recordSize := func() uint64 {
		return tlv.VarIntSize(*amount)
	}
	return tlv.MakeDynamicRecord(
		LeafAmount, amount, recordSize, VarIntEncoder, VarIntDecoder,
	)
}

func NewLeafLockTimeRecord(lockTime *uint64) tlv.Record {
	recordSize := func() uint64 {
		return tlv.VarIntSize(*lockTime)
	}
	return tlv.MakeDynamicRecord(
		LeafLockTime, lockTime, recordSize, VarIntEncoder,
		VarIntDecoder,
	)
}

func NewLeafRelativeLockTimeRecord(relativeLockTime *uint64) tlv.Record {
	recordSize := func() uint64 {
		return tlv.VarIntSize(*relativeLockTime)
	}
	return tlv.MakeDynamicRecord(
		LeafRelativeLockTime, relativeLockTime, recordSize,
		VarIntEncoder, VarIntDecoder,
	)
}

func NewLeafPrevWitnessRecord(prevWitnesses *[]Witness,
	encodeType EncodeType) tlv.Record {

	recordSize := func() uint64 {
		var (
			b   bytes.Buffer
			buf [8]byte
		)
		witnessEncoder := WitnessEncoderWithType(encodeType)
		if err := witnessEncoder(&b, prevWitnesses, &buf); err != nil {
			panic(err)
		}
		return uint64(len(b.Bytes()))
	}
	return tlv.MakeDynamicRecord(
		LeafPrevWitness, prevWitnesses, recordSize,
		WitnessEncoderWithType(encodeType), WitnessDecoder,
	)
}

func NewLeafSplitCommitmentRootRecord(root *mssmt.Node) tlv.Record {
	return tlv.MakeStaticRecord(
		LeafSplitCommitmentRoot, root, sha256.Size+8,
		SplitCommitmentRootEncoder, SplitCommitmentRootDecoder,
	)
}

func NewLeafScriptVersionRecord(version *ScriptVersion) tlv.Record {
	return tlv.MakeStaticRecord(
		LeafScriptVersion, version, 2, ScriptVersionEncoder,
		ScriptVersionDecoder,
	)
}

func NewLeafScriptKeyRecord(scriptKey **btcec.PublicKey) tlv.Record {
	const recordSize = btcec.PubKeyBytesLenCompressed
	return tlv.MakeStaticRecord(
		LeafScriptKey, scriptKey, recordSize,
		CompressedPubKeyEncoder, CompressedPubKeyDecoder,
	)
}

func NewLeafGroupKeyRecord(groupKey **GroupKey) tlv.Record {
	const recordSize = btcec.PubKeyBytesLenCompressed
	return tlv.MakeStaticRecord(
		LeafGroupKey, groupKey, recordSize, GroupKeyEncoder,
		GroupKeyDecoder,
	)
}

func NewWitnessPrevIDRecord(prevID **PrevID) tlv.Record {
	const recordSize = 36 + sha256.Size + btcec.PubKeyBytesLenCompressed
	return tlv.MakeStaticRecord(
		WitnessPrevID, prevID, recordSize, PrevIDEncoder, PrevIDDecoder,
	)
}

func NewWitnessTxWitnessRecord(witness *wire.TxWitness) tlv.Record {
	recordSize := func() uint64 {
		return uint64((*witness).SerializeSize())
	}
	return tlv.MakeDynamicRecord(
		WitnessTxWitness, witness, recordSize, TxWitnessEncoder,
		TxWitnessDecoder,
	)
}

func NewWitnessSplitCommitmentRecord(commitment **SplitCommitment) tlv.Record {
	recordSize := func() uint64 {
		var buf bytes.Buffer
		err := SplitCommitmentEncoder(&buf, commitment, &[8]byte{})
		if err != nil {
			panic(err)
		}
		return uint64(buf.Len())
	}
	return tlv.MakeDynamicRecord(
		WitnessSplitCommitment, commitment, recordSize,
		SplitCommitmentEncoder, SplitCommitmentDecoder,
	)
}
