package asset

import (
	"bytes"
	"testing"

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
