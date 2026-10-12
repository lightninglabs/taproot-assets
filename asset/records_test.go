package asset

import (
	"bytes"
	"io"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/tlv"
	"github.com/stretchr/testify/require"
)

// TestTlvStrictDecode tests that the strict decoding of TLV records works as
// expected.
func TestTlvStrictDecode(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		parsedTypes tlv.TypeMap
		knownTypes  fn.Set[tlv.Type]
		err         error
	}{
		// No unknown types.
		{
			parsedTypes: tlv.TypeMap{
				0: []byte{},
				2: []byte{},
			},
			knownTypes: fn.NewSet[tlv.Type](0, 2),
			err:        nil,
		},

		// Unknown type, but odd.
		{
			parsedTypes: tlv.TypeMap{
				0: []byte{},
				2: []byte{},
				3: []byte{},
			},
			knownTypes: fn.NewSet[tlv.Type](0, 2),
			err:        nil,
		},

		// Unknown even type, error.
		{
			parsedTypes: tlv.TypeMap{
				0: []byte{},
				2: []byte{},
				4: []byte{},
			},
			knownTypes: fn.NewSet[tlv.Type](0, 2),
			err: ErrUnknownType{
				UnknownType: 4,
				ValueBytes:  []byte{},
			},
		},
	}

	for _, testCase := range testCases {
		require.Equal(t, testCase.err, AssertNoUnknownEvenTypes(
			testCase.parsedTypes, testCase.knownTypes,
		))
	}
}

// TestFilterUnknownTypes tests that the filtering of unknown TLV records works
// as expected.
func TestFilterUnknownTypes(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		parsedTypes tlv.TypeMap
		knownTypes  fn.Set[tlv.Type]
		result      tlv.TypeMap
	}{
		// No unknown types.
		{
			parsedTypes: tlv.TypeMap{
				0: []byte{},
				2: []byte{},
			},
			knownTypes: fn.NewSet[tlv.Type](0, 2),
			result:     nil,
		},

		// Unknown type, but odd.
		{
			parsedTypes: tlv.TypeMap{
				0: []byte{},
				2: []byte{},
				3: []byte{},
			},
			knownTypes: fn.NewSet[tlv.Type](0, 2),
			result: tlv.TypeMap{
				3: []byte{},
			},
		},

		// Multiple unknown types, both odd and even.
		{
			parsedTypes: tlv.TypeMap{
				0: []byte{},
				2: []byte{},
				3: []byte{},
				4: []byte{},
			},
			knownTypes: fn.NewSet[tlv.Type](0, 2),
			result: tlv.TypeMap{
				3: []byte{},
				4: []byte{},
			},
		},
	}

	for _, testCase := range testCases {
		require.Equal(t, testCase.result, FilterUnknownTypes(
			testCase.parsedTypes, testCase.knownTypes,
		))
	}
}

// TestAssetUnknownOddType tests that an unknown odd type is allowed in an asset
// and that we can still arrive at the correct leaf hash with it.
func TestAssetUnknownOddType(t *testing.T) {
	knownAsset := RandAsset(t, Normal)
	knownAssetLeaf, err := knownAsset.Leaf()
	require.NoError(t, err)

	test.RunUnknownOddTypeTest(
		t, knownAsset, &ErrUnknownType{},
		func(buf *bytes.Buffer, asset *Asset) error {
			return asset.Encode(buf)
		},
		func(buf *bytes.Buffer) (*Asset, error) {
			var asset Asset
			return &asset, asset.Decode(buf)
		},
		func(parsedAsset *Asset, unknownTypes tlv.TypeMap) {
			// The unknown types should be reported correctly.
			require.Equal(
				t, unknownTypes, parsedAsset.UnknownOddTypes,
			)

			// The leaf should've changed, to make sure the unknown
			// value was taken into account when creating the
			// serialized leaf.
			parsedAssetLeaf, err := parsedAsset.Leaf()
			require.NoError(t, err)

			require.Equal(
				t, knownAssetLeaf.NodeSum(),
				parsedAssetLeaf.NodeSum(),
			)
			require.NotEqual(
				t, knownAssetLeaf.NodeHash(),
				parsedAssetLeaf.NodeHash(),
			)

			parsedAsset.UnknownOddTypes = nil

			// The group key's raw key and witness aren't
			// serialized, so we need to clear them out before
			// comparing.
			knownAsset.GroupKey.RawKey = keychain.KeyDescriptor{}
			knownAsset.GroupKey.Witness = nil

			require.Equal(t, knownAsset, parsedAsset)
		},
	)
}

// TestCompressedPubKeyDecoderZeroKey tests that an all-zero compressed public
// key is refused.
func TestCompressedPubKeyDecoderZeroKey(t *testing.T) {
	t.Parallel()

	var (
		key *btcec.PublicKey
		buf [8]byte
	)
	zeroKey := make([]byte, btcec.PubKeyBytesLenCompressed)
	err := CompressedPubKeyDecoder(
		bytes.NewReader(zeroKey), &key, &buf, uint64(len(zeroKey)),
	)
	require.Error(t, err)
	require.Nil(t, key)
}

// TestAltLeavesKeyParity tests that alt leaves whose script keys differ only
// in parity are refused as duplicates.
func TestAltLeavesKeyParity(t *testing.T) {
	t.Parallel()

	key := test.RandPrivKey().PubKey()
	flipped := key.SerializeCompressed()
	flipped[0] ^= 0x01
	negKey, err := btcec.ParsePubKey(flipped)
	require.NoError(t, err)

	var leaves []AltLeaf[Asset]
	for _, k := range []*btcec.PublicKey{key, negKey} {
		leaf, err := NewAltLeaf(NewScriptKey(k), ScriptV0)
		require.NoError(t, err)
		leaves = append(leaves, leaf)
	}

	var (
		encoded bytes.Buffer
		buf     [8]byte
	)
	err = AltLeavesEncoder(&encoded, &leaves, &buf)
	require.ErrorIs(t, err, ErrDuplicateScriptKeys)

	// Encode the leaves without the encoder's check, and decode them.
	encoded.Reset()
	require.NoError(t, tlv.WriteVarInt(&encoded, 2, &buf))
	for _, leaf := range leaves {
		var leafBuf bytes.Buffer
		require.NoError(t, leaf.EncodeAltLeaf(&leafBuf))

		leafBytes := leafBuf.Bytes()
		require.NoError(
			t, InlineVarBytesEncoder(&encoded, &leafBytes, &buf),
		)
	}

	var decoded []AltLeaf[Asset]
	err = AltLeavesDecoder(
		&encoded, &decoded, &buf, uint64(encoded.Len()),
	)
	require.ErrorIs(t, err, ErrDuplicateScriptKeys)
}

// editRecord returns the TLV stream with the value of the record of the given
// type replaced by its edit, and its length updated to match.
func editRecord(t *testing.T, stream []byte, typ tlv.Type,
	edit func([]byte) []byte) []byte {

	var (
		r     = bytes.NewReader(stream)
		out   bytes.Buffer
		buf   [8]byte
		found bool
	)
	for r.Len() > 0 {
		recType, err := tlv.ReadVarInt(r, &buf)
		require.NoError(t, err)

		l, err := tlv.ReadVarInt(r, &buf)
		require.NoError(t, err)

		val := make([]byte, l)
		_, err = io.ReadFull(r, val)
		require.NoError(t, err)

		if tlv.Type(recType) == typ {
			found = true
			val = edit(val)
		}

		require.NoError(t, tlv.WriteVarInt(&out, recType, &buf))
		require.NoError(
			t, tlv.WriteVarInt(&out, uint64(len(val)), &buf),
		)
		_, err = out.Write(val)
		require.NoError(t, err)
	}
	require.True(t, found)

	return out.Bytes()
}

// TestRecordLengthExact tests that asset and witness records are refused
// unless their values occupy exactly their declared lengths.
func TestRecordLengthExact(t *testing.T) {
	t.Parallel()

	witness := Witness{
		PrevID: &PrevID{
			ID:        RandID(t),
			ScriptKey: RandSerializedKey(t),
		},
		TxWitness: wire.TxWitness{{1}, {2}},
		SplitCommitment: &SplitCommitment{
			Proof:     *mssmt.RandProof(t),
			RootAsset: *RandAsset(t, Normal),
		},
	}

	a := RandAsset(t, Normal)
	a.LockTime = 1
	a.RelativeLockTime = 1
	a.PrevWitnesses = []Witness{witness}
	a.SplitCommitmentRoot = mssmt.NewComputedNode(
		mssmt.NodeHash(RandID(t)), 1,
	)

	var assetBuf, witnessBuf bytes.Buffer
	require.NoError(t, a.Encode(&assetBuf))
	require.NoError(t, witness.Encode(&witnessBuf))

	decodeAsset := func(b []byte) error {
		var decoded Asset
		return decoded.Decode(bytes.NewReader(b))
	}
	decodeWitness := func(b []byte) error {
		var decoded Witness
		return decoded.Decode(bytes.NewReader(b))
	}

	testCases := []struct {
		stream []byte
		decode func([]byte) error
		types  []tlv.Type
	}{{
		stream: assetBuf.Bytes(),
		decode: decodeAsset,
		types: []tlv.Type{
			LeafGenesis, LeafAmount, LeafLockTime,
			LeafRelativeLockTime, LeafPrevWitness,
			LeafSplitCommitmentRoot, LeafScriptKey, LeafGroupKey,
		},
	}, {
		stream: witnessBuf.Bytes(),
		decode: decodeWitness,
		types: []tlv.Type{
			WitnessPrevID, WitnessTxWitness,
			WitnessSplitCommitment,
		},
	}}

	grow := func(b []byte) []byte {
		return append(b, 0)
	}
	shrink := func(b []byte) []byte {
		return b[:len(b)-1]
	}

	for _, tc := range testCases {
		require.NoError(t, tc.decode(tc.stream))

		for _, typ := range tc.types {
			grown := editRecord(t, tc.stream, typ, grow)
			err := tc.decode(grown)
			require.ErrorIs(t, err, ErrRecordLength, "type %d", typ)

			shrunk := editRecord(t, tc.stream, typ, shrink)
			err = tc.decode(shrunk)
			require.Error(t, err, "type %d", typ)
		}
	}
}

// TestGenesisTypeMismatch tests that an asset whose type record differs from
// the type in its genesis record is refused.
func TestGenesisTypeMismatch(t *testing.T) {
	t.Parallel()

	var encoded bytes.Buffer
	require.NoError(t, RandAsset(t, Normal).Encode(&encoded))

	collectible := func([]byte) []byte {
		return []byte{byte(Collectible)}
	}
	mismatched := editRecord(t, encoded.Bytes(), LeafType, collectible)

	var decoded Asset
	err := decoded.Decode(bytes.NewReader(mismatched))
	require.ErrorIs(t, err, ErrGenesisTypeMismatch)
}
