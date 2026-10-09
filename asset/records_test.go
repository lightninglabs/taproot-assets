package asset

import (
	"bytes"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
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
