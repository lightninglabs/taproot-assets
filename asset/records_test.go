package asset

import (
	"bytes"
	"testing"

	"github.com/lightninglabs/taproot-assets/fn"
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

	var buf bytes.Buffer
	err = knownAsset.Encode(&buf)
	require.NoError(t, err)

	// With the known asset now encoded, we can add an unknown even type to
	// the encoded bytes. That should provoke an error when parsed again.
	unknownTypeValue := []byte("I could be anything, really")
	unknownEvenType := append([]byte{
		byte(40),                    // Type 40 is unknown.
		byte(len(unknownTypeValue)), // Length of the value.
	}, unknownTypeValue...)
	buf.Write(unknownEvenType)

	// Try to parse it again.
	var parsedAsset Asset
	err = parsedAsset.Decode(&buf)
	require.ErrorAs(t, err, &ErrUnknownType{})

	// Now clear the buffer, encode the asset again, but this time add an
	// unknown _odd_ type, which should be allowed.
	unknownOddType := append([]byte{
		byte(39),                    // Type 39 is unknown.
		byte(len(unknownTypeValue)), // Length of the value.
	}, unknownTypeValue...)
	buf.Reset()
	err = knownAsset.Encode(&buf)
	require.NoError(t, err)
	buf.Write(unknownOddType)

	err = parsedAsset.Decode(&buf)
	require.NoError(t, err)

	expectedUnknownTypes := tlv.TypeMap{
		39: unknownTypeValue,
	}
	require.Equal(t, expectedUnknownTypes, parsedAsset.unknownOddTypes)

	// The leaf should've changed, to make sure the unknown value was taken
	// into account when creating the serialized leaf.
	parsedAssetLeaf, err := parsedAsset.Leaf()
	require.NoError(t, err)

	require.Equal(t, knownAssetLeaf.NodeSum(), parsedAssetLeaf.NodeSum())
	require.NotEqual(
		t, knownAssetLeaf.NodeHash(), parsedAssetLeaf.NodeHash(),
	)
}
