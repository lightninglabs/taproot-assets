package asset

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightningnetwork/lnd/tlv"
	"golang.org/x/exp/maps"
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

// KnownAssetLeafTypes is a set of all known leaf types.
var KnownAssetLeafTypes = fn.NewSet(
	LeafVersion, LeafGenesis, LeafType, LeafAmount, LeafLockTime,
	LeafRelativeLockTime, LeafPrevWitness, LeafSplitCommitmentRoot,
	LeafScriptVersion, LeafScriptKey, LeafGroupKey,
)

// ErrUnknownType is returned when an unknown type is encountered while
// decoding a TLV stream.
type ErrUnknownType struct {
	// UnknownType is the type that was unknown.
	UnknownType tlv.Type

	// ValueBytes is the raw bytes of the value that was unknown.
	ValueBytes []byte
}

// Erorr returns the error message for the ErrUnknownType.
func (e ErrUnknownType) Error() string {
	return fmt.Errorf("unknown type %d", e.UnknownType).Error()
}

// AssertNoUnknownTypes asserts that the given parsed types do not contain any
// unknown types. We only care if there's an odd type that we don't know of. If
// we find an unknown type, then an error is returned detailing the type.
func AssertNoUnkownTypes(parsedTypes tlv.TypeMap,
	knownTypes fn.Set[tlv.Type]) error {

	// Run through the set of types that we parsed. We want to error out if
	// we encounter an unknown type that's odd.
	oddTypes := fn.Filter(maps.Keys(parsedTypes), func(t tlv.Type) bool {
		return t%2 == 1
	})

	// Now that we have all the odd types, we want to make sure that we
	// know of them all.
	for _, oddType := range oddTypes {
		if !knownTypes.Contains(oddType) {
			return ErrUnknownType{
				UnknownType: oddType,
				ValueBytes:  parsedTypes[oddType],
			}
		}
	}

	return nil
}

// TlvStrictDecode attempts to decode the passed bufer into the TLV stream. It
// takes the set of known types for a given stream, and returns an error if the
// buffer includes any unknown odd types.
func TlvStrictDecode(stream *tlv.Stream, r io.Reader,
	knownTypes fn.Set[tlv.Type]) error {

	parsedTypes, err := stream.DecodeWithParsedTypes(r)
	if err != nil {
		return err
	}
	if err := AssertNoUnkownTypes(parsedTypes, knownTypes); err != nil {
		return err
	}

	return nil
}

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
