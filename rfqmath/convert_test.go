package rfqmath

import (
	"fmt"
	"math"
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/davecgh/go-spew/spew"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

var (
	btcPricesCents = []uint64{
		1_000_00,
		3_456_78,
		5_000_00,

		10_000_00,
		20_000_00,
		34_567_89,
		50_000_00,
		50_702_12,

		100_000_00,
		345_678_90,
		500_000_00,

		1_000_000_00,
		3_456_789_01,
		5_000_000_00,

		10_000_000_00,
		34_567_890_12,
		50_000_000_00,
	}

	maxDecimalDisplay = 8

	invoiceAmountsMsat = []uint64{
		1,
		2,
		3,
		5,

		10,
		34,
		50,

		100,
		345,
		500,

		1_000,
		3_456,
		5_000,

		10_000,
		34_567,
		50_000,

		100_000,
		345_678,
		500_000,

		1_000_000,
		3_456_789,
		5_000_000,

		10_000_000,
		20_000_000,
		34_567_890,
		50_000_000,

		100_000_000,
		345_678_901,
		500_000_000,

		1_000_000_000,
		3_456_789_012,
		5_000_000_000,

		10_000_000_000,
		34_567_890_123,
		50_000_000_000,

		100_000_000_000,
		345_678_901_234,
		500_000_000_000,
	}
)

// newBig creates a new BigInt from the given int64.
func newBig(n uint64) BigInt {
	return NewInt[BigInt]().FromUint64(n)
}

// TestConvertFindDecimalDisplayBoundaries tests the maximum number of units
// that can be represented with a given decimal display, the smallest payable
// invoice amount, and the maximum MPP rounding error. The values are printed
// out on standard output.
func TestConvertFindDecimalDisplayBoundaries(t *testing.T) {
	limitsBitInt := calcLimits[BigInt]
	for _, btcPriceCents := range btcPricesCents {
		fmt.Printf("-------------\nBTC price: %d USD\n-------------\n",
			btcPriceCents/100)
		for decDisp := 2; decDisp <= maxDecimalDisplay; decDisp++ {
			unitsPerUsd := uint64(math.Pow10(decDisp))

			priceCents := FixedPoint[BigInt]{
				Value: new(BigInt).FromUint64(btcPriceCents),
				Scale: 2,
			}
			priceScaled := priceCents.ScaleTo(decDisp)

			numShards := float64(16)
			maxUnits, smallestAmount, mSatPerUnit := limitsBitInt(
				btcPriceCents, decDisp,
			)

			maxRoundMSat := uint64(mSatPerUnit * numShards)

			oneUsd := FixedPoint[BigInt]{
				Value: new(BigInt).FromUint64(1),
				Scale: 0,
			}.ScaleTo(decDisp)

			mSatPerUsd := UnitsToMilliSatoshi(oneUsd, priceScaled)
			unitsPerSat := MilliSatoshiToUnits(1000, priceScaled)

			fmt.Printf("decimalDisplay: %d\t\t\t%v units = 1 USD, "+
				"1 BTC = %v units\n"+
				"Max issuable units:\t\t\tcan represent %v "+
				"BTC\n"+
				"Min payable invoice amount:\t%d mSAT\n"+
				"Max MPP rounding error:\t\t%d mSAT (@%.0f "+
				"shards)\n"+
				"Satoshi per USD:\t\t\t%d\n"+
				"Satoshi per Asset Unit: \t%.5f\n"+
				"Asset Units per Satoshi: \t%v\n"+
				"Price In Asset: \t\t\t%v\n"+
				"Price Out Asset: \t\t\t%v\n\n",
				decDisp, unitsPerUsd, priceScaled,
				maxUnits, smallestAmount, maxRoundMSat,
				numShards, mSatPerUsd/1000, mSatPerUnit/1000,
				unitsPerSat, priceScaled,
				uint64(btcutil.SatoshiPerBitcoin*1000))
		}
	}
}

// calcLimits calculates the maximum number of units that can be represented
// with a given decimal display, the smallest payable invoice amount, and the
// maximum MPP rounding error for a given BTC price in cents, decimal display
// value and number of MPP shards.
func calcLimits[N Int[N]](btcPriceCent uint64, decDisplay int) (uint64, uint64,
	float64) {

	msatScale := defaultArithmeticScale

	// In the unit test, the price is always given as cents per BTC.
	var v N
	priceCents := FixedPoint[N]{
		Value: v.FromUint64(btcPriceCent),
		Scale: 2,
	}

	// priceScaled is the number of units per USD at the given price.
	priceScaled := priceCents.ScaleTo(decDisplay)

	// priceScaledF is the same as priceScaled, but in float64 format.
	priceScaledF := float64(btcPriceCent) * math.Pow10(decDisplay-2)

	// mSatPerUnitF is the number of mSAT per asset unit at the given
	// price.
	mSatPerUnitF := math.Pow10(msatScale) / priceScaledF

	// maxUnits is the maximum number of BTC that can be represented with
	// assets given the decimal display (assuming a uint64 is used).
	maxUnits := NewInt[N]().FromUint64(
		math.MaxUint64,
	).Div(priceScaled.Value)

	smallestAmount := uint64(0)
	for _, invoiceAmount := range invoiceAmountsMsat {
		invAmt := NewInt[N]().FromUint64(invoiceAmount)

		unitsForInvoice := invAmt.Mul(priceScaled.Value).ToUint64() /
			uint64(math.Pow10(msatScale))

		if unitsForInvoice > 0 && smallestAmount == 0 {
			smallestAmount = invoiceAmount
		}
	}

	return maxUnits.ToUint64(), smallestAmount, mSatPerUnitF
}

// TestConvertFixedPointFromUint64 tests the FixedPointFromUint64 scales up
// properly based on the passed scale and integer value.
func TestConvertFixedPointFromUint64(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		value       uint64
		scale       int
		expectedOut FixedPoint[BigInt]
	}{
		{
			name:  "scale 0",
			value: 1,
			scale: 0,
			expectedOut: FixedPoint[BigInt]{
				Value: newBig(1),
				Scale: 0,
			},
		},
		{
			name:  "scale 2",
			value: 1,
			scale: 2,
			expectedOut: FixedPoint[BigInt]{
				Value: newBig(100),
				Scale: 2,
			},
		},
		{
			name:  "scale 6",
			value: 1,
			scale: 6,
			expectedOut: FixedPoint[BigInt]{
				Value: newBig(1_000_000),
				Scale: 6,
			},
		},
		{
			name:  "scale 8",
			value: 1,
			scale: 8,
			expectedOut: FixedPoint[BigInt]{
				Value: newBig(100_000_000),
				Scale: 8,
			},
		},
		{
			name:  "scale 8 msat in BTC",
			value: btcutil.SatoshiPerBitcoin * 1000,
			scale: 8,
			expectedOut: FixedPoint[BigInt]{
				Value: newBig(uint64(
					10_000_000_000_000_000_000,
				)),
				Scale: 8,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			out := FixedPointFromUint64[BigInt](
				tc.value, tc.scale,
			)

			require.Equal(t, tc.expectedOut, out)
		})
	}
}

// TestConvertScaleTo tests the ScaleTo method of the FixedPoint type.
func TestConvertScaleTo(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		in          FixedPoint[BigInt]
		scaleTo     int
		expectedOut FixedPoint[BigInt]
	}{
		{
			name: "scale from 0 to 12",
			in: FixedPoint[BigInt]{
				Value: newBig(1),
				Scale: 0,
			},
			scaleTo: 12,
			expectedOut: FixedPoint[BigInt]{
				Value: newBig(1_000_000_000_000),
				Scale: 12,
			},
		},
		{
			name: "scale from 0 to 4",
			in: FixedPoint[BigInt]{
				Value: newBig(9),
				Scale: 0,
			},
			scaleTo: 4,
			expectedOut: FixedPoint[BigInt]{
				Value: newBig(90_000),
				Scale: 4,
			},
		},
		{
			name: "scale from 2 to 4",
			in: FixedPoint[BigInt]{
				Value: newBig(123_456),
				Scale: 2,
			},
			scaleTo: 4,
			expectedOut: FixedPoint[BigInt]{
				Value: newBig(12_345_600),
				Scale: 4,
			},
		},
		{
			name: "scale from 4 to 2, no precision loss",
			in: FixedPoint[BigInt]{
				Value: newBig(12_345_600),
				Scale: 4,
			},
			scaleTo: 2,
			expectedOut: FixedPoint[BigInt]{
				Value: newBig(123_456),
				Scale: 2,
			},
		},
		{
			name: "scale from 6 to 2, with precision loss",
			in: FixedPoint[BigInt]{
				Value: newBig(12_345_600),
				Scale: 6,
			},
			scaleTo: 2,
			expectedOut: FixedPoint[BigInt]{
				Value: newBig(1_234),
				Scale: 2,
			},
		},
		{
			name: "scale from 6 to 2, with full loss of value",
			in: FixedPoint[BigInt]{
				Value: newBig(12),
				Scale: 6,
			},
			scaleTo: 2,
			expectedOut: FixedPoint[BigInt]{
				Value: newBig(0),
				Scale: 2,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			out := tc.in.ScaleTo(tc.scaleTo)
			require.True(
				t, tc.expectedOut.Equals(out),
				"expected %v, got %v",
				spew.Sdump(tc.expectedOut), spew.Sdump(out),
			)
		})
	}
}

// TestConvertMilliSatoshiToUnits tests the MilliSatoshiToUnits function.
func TestConvertMilliSatoshiToUnits(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		invoiceAmount lnwire.MilliSatoshi
		price         FixedPoint[BigInt]
		expectedUnits uint64
	}{
		{
			// 5k USD per BTC @ decimal display 2.
			invoiceAmount: 200_000,
			price: FixedPoint[BigInt]{
				Value: newBig(5_000_00),
				Scale: 2,
			},
			expectedUnits: 1,
		},
		{
			// 5k USD per BTC @ decimal display 6.
			invoiceAmount: 200_000,
			price: FixedPoint[BigInt]{
				Value: newBig(5_000_00),
				Scale: 2,
			}.ScaleTo(6),
			expectedUnits: 10_000,
		},
		{
			// 50k USD per BTC @ decimal display 6.
			invoiceAmount: 1_973,
			price: FixedPoint[BigInt]{
				Value: newBig(50_702_00),
				Scale: 2,
			}.ScaleTo(6),
			expectedUnits: 1000,
		},
		{
			// 50M USD per BTC @ decimal display 6.
			invoiceAmount: 123_456_789,
			price: FixedPoint[BigInt]{
				Value: newBig(50_702_000_00),
				Scale: 2,
			}.ScaleTo(6),
			expectedUnits: 62595061158,
		},
		{
			// 50k USD per BTC @ decimal display 6.
			invoiceAmount: 5_070,
			price: FixedPoint[BigInt]{
				Value: newBig(50_702_12),
				Scale: 2,
			}.ScaleTo(6),
			expectedUnits: 2_570,
		},
		{
			// 7.341M JPY per BTC @ decimal display 6.
			invoiceAmount: 5_000,
			price: FixedPoint[BigInt]{
				Value: newBig(7_341_847),
				Scale: 0,
			}.ScaleTo(6),
			expectedUnits: 367_092,
		},
		{
			// 7.341M JPY per BTC @ decimal display 2.
			invoiceAmount: 5_000,
			price: FixedPoint[BigInt]{
				Value: newBig(7_341_847),
				Scale: 0,
			}.ScaleTo(4),
			expectedUnits: 3_670,
		},
	}

	for _, tc := range testCases {
		name := fmt.Sprintf("milliSat=%d,price=%s", tc.invoiceAmount,
			tc.price.String())

		t.Run(name, func(t *testing.T) {
			units := MilliSatoshiToUnits(tc.invoiceAmount, tc.price)
			require.Equal(t, tc.expectedUnits, units.ToUint64())

			mSat := UnitsToMilliSatoshi(units, tc.price)

			diff := tc.invoiceAmount - mSat
			require.LessOrEqual(t, diff, uint64(2), "mSAT diff")
		})
	}
}

// TestConvertUsdToJpy tests the conversion of USD to JPY using a BTC price in
// USD and a BTC price in JPY, both expressed as a FixedPoint.
func TestConvertUsdToJpy(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		usdPrice    FixedPoint[BigInt]
		jpyPrice    FixedPoint[BigInt]
		usdAmount   uint64
		expectedJpy uint64
	}{
		{
			name: "1 USD to JPY @ 2.840M JPY/BTC, 20k USD/BTC",
			usdPrice: FixedPoint[BigInt]{
				Value: newBig(20_000_00),
				Scale: 2,
			}.ScaleTo(6),
			jpyPrice: FixedPoint[BigInt]{
				Value: newBig(2_840_000),
				Scale: 0,
			}.ScaleTo(4),
			usdAmount:   1,
			expectedJpy: 142,
		},
		{
			name: "100 USD to JPY @ 7.341M JPY/BTC, 50'702 USD/BTC",
			usdPrice: FixedPoint[BigInt]{
				Value: newBig(50_702_12),
				Scale: 2,
			}.ScaleTo(6),
			jpyPrice: FixedPoint[BigInt]{
				Value: newBig(7_341_847),
				Scale: 0,
			}.ScaleTo(4),
			usdAmount:   100,
			expectedJpy: 14_480,
		},
		{
			name: "500 USD to JPY @ 142M JPY/BTC, 1M USD/BTC",
			usdPrice: FixedPoint[BigInt]{
				Value: newBig(1_000_000_00),
				Scale: 2,
			}.ScaleTo(6),
			jpyPrice: FixedPoint[BigInt]{
				Value: newBig(142_000_000),
				Scale: 0,
			}.ScaleTo(4),
			usdAmount:   500,
			expectedJpy: 71_000,
		},
	}

	for _, tc := range testCases {
		// Easy way to scale up the USD amount to 6 decimal display.
		dollarUnits := FixedPoint[BigInt]{
			Value: newBig(tc.usdAmount),
			Scale: 0,
		}.ScaleTo(6)

		// Convert the USD to mSAT.
		hundredUsdAsMilliSatoshi := UnitsToMilliSatoshi(
			dollarUnits, tc.usdPrice,
		)

		// Convert the mSAT to JPY.
		usdAmountAsJpy := MilliSatoshiToUnits(
			hundredUsdAsMilliSatoshi, tc.jpyPrice,
		)

		// Go from decimal display of 4 to 0 (full JPY).
		fullJpy := usdAmountAsJpy.ToUint64() / 10_000

		require.Equal(t, tc.expectedJpy, fullJpy)

		oneUsd := FixedPoint[BigInt]{
			Value: newBig(1),
			Scale: 0,
		}.ScaleTo(6)
		oneJpy := FixedPoint[BigInt]{
			Value: newBig(1),
			Scale: 0,
		}.ScaleTo(4)

		_, _, mSatPerUsdUnit := calcLimits[BigInt](
			tc.usdPrice.ScaleTo(2).ToUint64(), 6,
		)
		mSatPerUsd := UnitsToMilliSatoshi(oneUsd, tc.usdPrice)
		usdUnitsPerSat := MilliSatoshiToUnits(1000, tc.usdPrice)

		_, _, mSatPerJpyUnit := calcLimits[BigInt](
			tc.jpyPrice.ScaleTo(0).ToUint64(), 4,
		)
		mSatPerJpy := UnitsToMilliSatoshi(oneJpy, tc.jpyPrice)
		jpyUnitsPerSat := MilliSatoshiToUnits(1000, tc.jpyPrice)

		fmt.Printf("Satoshi per USD:\t\t\t\t%d\n"+
			"Satoshi per USD Asset Unit: \t%.5f\n"+
			"USD Asset Units per Satoshi: \t%v\n"+
			"Satoshi per JPY:\t\t\t\t%d\n"+
			"Satoshi per JPY Asset Unit: \t%.5f\n"+
			"JPY Asset Units per Satoshi: \t%v\n"+
			"Price In Asset: \t\t\t\t%v\n"+
			"Price Out Asset: \t\t\t\t%v\n"+
			"%3d USD in JPY: \t\t\t\t%d\n\n",
			mSatPerUsd/1000, mSatPerUsdUnit/1000, usdUnitsPerSat,
			mSatPerJpy/1000, mSatPerJpyUnit/1000, jpyUnitsPerSat,
			tc.usdPrice.Value, tc.jpyPrice.Value,
			tc.usdAmount, fullJpy)
	}
}

func testMilliSatoshiToUnits[N Int[N]](t *rapid.T) {
	unitsPerBtc := rapid.Uint64Range(1, 100_000_000).Draw(t, "unitsPerBtc")
	scale := rapid.IntRange(2, 9).Draw(t, "scale")

	msat := lnwire.MilliSatoshi(
		rapid.Uint64Range(1, math.MaxUint32).Draw(t, "msat"),
	)
	unitsPerBtcFP := FixedPointFromUint64[N](unitsPerBtc, scale)

	result := MilliSatoshiToUnits(msat, unitsPerBtcFP)

	// The result should have the same scale as unitsPerBtc.
	require.Equal(t, scale, result.Scale)

	// If we recompute the value using pure floats, then we should be
	// within a margin of error related to the scale: U = (X / M) * Y.
	//
	// TODO(roasbeef): make delta a function of scale
	xByMFloat := float64(msat) / float64(btcutil.SatoshiPerBitcoin*1000)
	unitsFloat := xByMFloat * float64(unitsPerBtc)
	require.InDelta(t, unitsFloat, result.ToFloat64(), 0.012)
}

func testUnitsToMilliSatoshi[N Int[N]](t *rapid.T) {
	units := rapid.Uint64Range(1, 1_000_000_000).Draw(t, "units")
	unitsPerBtc := rapid.Uint64Range(
		1_000, 100_000_000,
	).Draw(t, "unitsPerBtc")
	scale := rapid.IntRange(5, 9).Draw(t, "scale")

	unitsFP := FixedPointFromUint64[N](units, scale)
	unitsPerBtcFP := FixedPointFromUint64[N](unitsPerBtc, scale)

	result := UnitsToMilliSatoshi(unitsFP, unitsPerBtcFP)

	// If we recompute the value using pure floats, then we should be
	// within a margin of error related to the scale: X = (U / Y) * M.
	//
	// TODO(roasbeef): make delta a function of scale
	uByYFloat := float64(units) / float64(unitsPerBtc)
	msatFloat := uByYFloat * float64(btcutil.SatoshiPerBitcoin*1000)
	require.InEpsilon(t, uint64(msatFloat), uint64(result), 0.01)
}

func testRoundTripConversion[N Int[N]](t *rapid.T) {
	unitsPerBtc := rapid.Uint64Range(
		1_000, 100_000_000,
	).Draw(t, "unitsPerBtc")
	scale := rapid.IntRange(9, 10).Draw(t, "scale")

	msat := lnwire.MilliSatoshi(
		rapid.Uint64Range(1, math.MaxUint32).Draw(t, "msat"),
	)
	unitsPerBtcFP := FixedPointFromUint64[N](unitsPerBtc, scale)

	units := MilliSatoshiToUnits(msat, unitsPerBtcFP)
	msatResult := UnitsToMilliSatoshi(units, unitsPerBtcFP)

	// TODO(roasbeef): should it also round up to the nearest sat on the
	// other end?
	//  * can end up in cases where we have 0.9 msat

	// The round trip conversion should preserve the value.
	require.InDelta(t, uint64(msat), uint64(msatResult), 1)
}

// TestConversionMsat tests key invariant properties of the conversion
// functions.
func TestConversionMsat(t *testing.T) {
	t.Parallel()

	t.Run("msat_to_units", rapid.MakeCheck(testMilliSatoshiToUnits[BigInt]))
	t.Run("units_to_msat", rapid.MakeCheck(testUnitsToMilliSatoshi[BigInt]))
	t.Run(
		"roundtrip_conversion",
		rapid.MakeCheck(testRoundTripConversion[BigInt]),
	)
}
