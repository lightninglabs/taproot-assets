package rfqmsg

import (
	"bytes"
	"math"
	"math/big"
	"testing"

	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightningnetwork/lnd/tlv"
	"github.com/stretchr/testify/require"
)

// TestNewID tests that we can easily derive 1000 new IDs without any errors.
func TestNewID(t *testing.T) {
	const numIDs = 1000

	for range numIDs {
		_, err := NewID()
		require.NoError(t, err)
	}
}

// TestTlvFixedPoint tests encoding and decoding of the TlvFixedPoint struct.
func TestTlvFixedPoint(t *testing.T) {
	// This is the test case structure which will be encoded and decoded.
	type testStruct struct {
		ExchangeRate tlv.RecordT[tlv.TlvType1, TlvFixedPoint]
	}

	type testCase struct {
		// name is the name of the test case.
		name string

		// tStruct is the test structure to encode and decode.
		tStruct testStruct
	}

	// Create a large coefficient to test encoding and decoding of a large
	// fixed-point value. Ensure it's larger than the maximum uint64 value.
	bigInt := new(big.Int)
	bigInt.SetUint64(math.MaxUint64)
	bigInt = bigInt.Mul(bigInt, bigInt)

	largeCFixedPoint := rfqmath.BigIntFixedPoint{
		Coefficient: rfqmath.NewBigInt(bigInt),
		Scale:       math.MaxUint8,
	}

	// Define test cases.
	//
	// nolint: lll
	testCases := []testCase{
		{
			name: "coefficient as uint64",
			tStruct: testStruct{
				ExchangeRate: tlv.NewRecordT[tlv.TlvType1](
					NewTlvFixedPointFromUint64(123456789, 7),
				),
			},
		},
		{
			name: "coefficient as large BigInt",
			tStruct: testStruct{
				ExchangeRate: tlv.NewRecordT[tlv.TlvType1](
					NewTlvFixedPointFromBigInt(largeCFixedPoint),
				),
			},
		},
	}

	for testCaseIdx := range testCases {
		tc := testCases[testCaseIdx]
		tStruct := tc.tStruct

		// Encode the test case.
		tlvStream, err := tlv.NewStream(tStruct.ExchangeRate.Record())
		require.NoError(t, err)

		var buf bytes.Buffer
		err = tlvStream.Encode(&buf)
		require.NoError(t, err)

		// Decode the test case.
		decodedTc := &testStruct{}
		tlvStream, err = tlv.NewStream(decodedTc.ExchangeRate.Record())
		require.NoError(t, err)

		err = tlvStream.Decode(&buf)
		require.NoError(t, err)

		// Compare the original and decoded test cases.
		//
		// Ensure scale is the same.
		require.Equal(
			t, tStruct.ExchangeRate.Val.fp.Scale,
			decodedTc.ExchangeRate.Val.fp.Scale,
		)

		// Ensure coefficient is the same.
		isEqual := tStruct.ExchangeRate.Val.fp.Coefficient.Equals(
			decodedTc.ExchangeRate.Val.fp.Coefficient,
		)
		require.True(t, isEqual)
	}
}
