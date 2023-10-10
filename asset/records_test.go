package asset

import (
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

		// Unknown type, but even.
		{
			parsedTypes: tlv.TypeMap{
				0: []byte{},
				2: []byte{},
				4: []byte{},
			},
			knownTypes: fn.NewSet[tlv.Type](0, 2),
			err:        nil,
		},

		// Unknown odd type, error.
		{
			parsedTypes: tlv.TypeMap{
				0: []byte{},
				2: []byte{},
				5: []byte{},
			},
			knownTypes: fn.NewSet[tlv.Type](0, 2),
			err: ErrUnknownType{
				UnknownType: 5,
				ValueBytes:  []byte{},
			},
		},
	}

	for _, testCase := range testCases {

		require.Equal(t,
			testCase.err,
			AssertNoUnkownTypes(
				testCase.parsedTypes, testCase.knownTypes,
			),
		)
	}
}
