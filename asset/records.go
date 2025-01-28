package asset

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"net/url"

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
)

// KnownAssetLeafTypes is a set of all known asset leaf TLV types. This set is
// asserted to be complete by a check in the BIP test vector unit tests.
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

// Error returns the error message for the ErrUnknownType.
func (e ErrUnknownType) Error() string {
	return fmt.Sprintf("unknown even TLV type %d encountered, consider "+
		"upgrading your tapd software version", e.UnknownType)
}

// AssertNoUnknownEvenTypes asserts that the given parsed types do not contain
// any unknown types. We only care if there's an even type that we don't know
// of, adopting the same strategy as the BOLTS do ("it's okay to be odd"),
// meaning that odd types are optional and therefore can be allowed to be
// unknown. If we find an unknown even type, then it means we're behind in our
// software version and an error is returned detailing the type.
func AssertNoUnknownEvenTypes(parsedTypes tlv.TypeMap,
	knownTypes fn.Set[tlv.Type]) error {

	// Run through the set of types that we parsed. We want to error out if
	// we encounter an unknown type that's even.
	evenTypes := fn.Filter(maps.Keys(parsedTypes), func(t tlv.Type) bool {
		return t%2 == 0
	})

	// Now that we have all the even types, we want to make sure that we
	// know of them all.
	for _, evenType := range evenTypes {
		if !knownTypes.Contains(evenType) {
			return ErrUnknownType{
				UnknownType: evenType,
				ValueBytes:  parsedTypes[evenType],
			}
		}
	}

	return nil
}

// FilterUnknownTypes filters out all types that are unknown from the given
// parsed types. The known types are specified as a set.
func FilterUnknownTypes(parsedTypes tlv.TypeMap,
	knownTypes fn.Set[tlv.Type]) tlv.TypeMap {

	result := make(tlv.TypeMap, len(parsedTypes))
	for t, v := range parsedTypes {
		if !knownTypes.Contains(t) {
			result[t] = v
		}
	}

	// Avoid failures due to comparisons with nil vs. empty map.
	if len(result) == 0 {
		return nil
	}

	return result
}

// TlvStrictDecode attempts to decode the passed buffer into the TLV stream. It
// takes the set of known types for a given stream, and returns an error if the
// buffer includes any unknown even types.
func TlvStrictDecode(stream *tlv.Stream, r io.Reader,
	knownTypes fn.Set[tlv.Type]) (tlv.TypeMap, error) {

	parsedTypes, err := stream.DecodeWithParsedTypes(r)
	if err != nil {
		return nil, err
	}

	err = AssertNoUnknownEvenTypes(parsedTypes, knownTypes)
	if err != nil {
		return nil, err
	}

	return FilterUnknownTypes(parsedTypes, knownTypes), nil
}

// TlvStrictDecodeP2P is identical to TlvStrictDecode except that the record
// size is capped at 65535. This should only be called from a p2p setting where
// untrusted input is being deserialized.
func TlvStrictDecodeP2P(stream *tlv.Stream, r io.Reader,
	knownTypes fn.Set[tlv.Type]) (tlv.TypeMap, error) {

	parsedTypes, err := stream.DecodeWithParsedTypesP2P(r)
	if err != nil {
		return nil, err
	}

	err = AssertNoUnknownEvenTypes(parsedTypes, knownTypes)
	if err != nil {
		return nil, err
	}

	return FilterUnknownTypes(parsedTypes, knownTypes), nil
}

// CombineRecords returns a new slice of records that combines the given records
// with the unparsed types converted to static records.
func CombineRecords(records []tlv.Record, unparsed tlv.TypeMap) []tlv.Record {
	stubRecords := make([]tlv.Record, 0, len(unparsed))
	for k, v := range unparsed {
		stubRecords = append(stubRecords, tlv.MakeStaticRecord(
			k, nil, uint64(len(v)), tlv.StubEncoder(v), nil,
		))
	}

	// Because the map above gives random access to the records, we need to
	// re-sort them to ensure that the records are in the correct order.
	combinedRecords := append(records, stubRecords...)
	tlv.SortRecords(combinedRecords)

	return combinedRecords
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

// UrlEncoder encodes a url.URL as a variable length byte slice.
func UrlEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(*url.URL); ok {
		addrBytes := []byte((*t).String())
		return tlv.EVarBytes(w, &addrBytes, buf)
	}
	return tlv.NewTypeForEncodingErr(val, "*url.URL")
}

// UrlDecoder decodes a variable length byte slice as an url.URL.
func UrlDecoder(r io.Reader, val any, buf *[8]byte, l uint64) error {
	if t, ok := val.(*url.URL); ok {
		var addrBytes []byte
		err := tlv.DVarBytes(r, &addrBytes, buf, l)
		if err != nil {
			return err
		}

		addr, err := url.ParseRequestURI(string(addrBytes))
		if err != nil {
			return err
		}
		*t = *addr

		return nil
	}
	return tlv.NewTypeForDecodingErr(val, "*url.URL", l, l)
}
