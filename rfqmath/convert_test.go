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
				Coefficient: new(BigInt).FromUint64(
					btcPriceCents,
				),
				Scale: 2,
			}
			priceScaled := priceCents.ScaleTo(uint8(decDisp))

			numShards := float64(16)
			maxUnits, smallestAmount, mSatPerUnit := limitsBitInt(
				btcPriceCents, decDisp,
			)

			maxRoundMSat := uint64(mSatPerUnit * numShards)

			oneUsd := FixedPoint[BigInt]{
				Coefficient: new(BigInt).FromUint64(1),
				Scale:       0,
			}.ScaleTo(uint8(decDisp))

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
		Coefficient: v.FromUint64(btcPriceCent),
		Scale:       2,
	}

	// priceScaled is the number of units per USD at the given price.
	priceScaled := priceCents.ScaleTo(uint8(decDisplay))

	// priceScaledF is the same as priceScaled, but in float64 format.
	priceScaledF := float64(btcPriceCent) * math.Pow10(decDisplay-2)

	// mSatPerUnitF is the number of mSAT per asset unit at the given
	// price.
	mSatPerUnitF := math.Pow10(msatScale) / priceScaledF

	// maxUnits is the maximum number of BTC that can be represented with
	// assets given the decimal display (assuming a uint64 is used).
	maxUnits := NewInt[N]().FromUint64(
		math.MaxUint64,
	).Div(priceScaled.Coefficient)

	smallestAmount := uint64(0)
	for _, invoiceAmount := range invoiceAmountsMsat {
		invAmt := NewInt[N]().FromUint64(invoiceAmount)

		unitsForInvoice := invAmt.Mul(
			priceScaled.Coefficient,
		).ToUint64() / uint64(math.Pow10(msatScale))

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
		scale       uint8
		expectedOut FixedPoint[BigInt]
	}{
		{
			name:  "scale 0",
			value: 1,
			scale: 0,
			expectedOut: FixedPoint[BigInt]{
				Coefficient: newBig(1),
				Scale:       0,
			},
		},
		{
			name:  "scale 2",
			value: 1,
			scale: 2,
			expectedOut: FixedPoint[BigInt]{
				Coefficient: newBig(100),
				Scale:       2,
			},
		},
		{
			name:  "scale 6",
			value: 1,
			scale: 6,
			expectedOut: FixedPoint[BigInt]{
				Coefficient: newBig(1_000_000),
				Scale:       6,
			},
		},
		{
			name:  "scale 8",
			value: 1,
			scale: 8,
			expectedOut: FixedPoint[BigInt]{
				Coefficient: newBig(100_000_000),
				Scale:       8,
			},
		},
		{
			name:  "scale 8 msat in BTC",
			value: btcutil.SatoshiPerBitcoin * 1000,
			scale: 8,
			expectedOut: FixedPoint[BigInt]{
				Coefficient: newBig(uint64(
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
		scaleTo     uint8
		expectedOut FixedPoint[BigInt]
	}{
		{
			name: "scale from 0 to 12",
			in: FixedPoint[BigInt]{
				Coefficient: newBig(1),
				Scale:       0,
			},
			scaleTo: 12,
			expectedOut: FixedPoint[BigInt]{
				Coefficient: newBig(1_000_000_000_000),
				Scale:       12,
			},
		},
		{
			name: "scale from 0 to 4",
			in: FixedPoint[BigInt]{
				Coefficient: newBig(9),
				Scale:       0,
			},
			scaleTo: 4,
			expectedOut: FixedPoint[BigInt]{
				Coefficient: newBig(90_000),
				Scale:       4,
			},
		},
		{
			name: "scale from 2 to 4",
			in: FixedPoint[BigInt]{
				Coefficient: newBig(123_456),
				Scale:       2,
			},
			scaleTo: 4,
			expectedOut: FixedPoint[BigInt]{
				Coefficient: newBig(12_345_600),
				Scale:       4,
			},
		},
		{
			name: "scale from 4 to 2, no precision loss",
			in: FixedPoint[BigInt]{
				Coefficient: newBig(12_345_600),
				Scale:       4,
			},
			scaleTo: 2,
			expectedOut: FixedPoint[BigInt]{
				Coefficient: newBig(123_456),
				Scale:       2,
			},
		},
		{
			name: "scale from 6 to 2, with precision loss",
			in: FixedPoint[BigInt]{
				Coefficient: newBig(12_345_600),
				Scale:       6,
			},
			scaleTo: 2,
			expectedOut: FixedPoint[BigInt]{
				Coefficient: newBig(1_234),
				Scale:       2,
			},
		},
		{
			name: "scale from 6 to 2, with full loss of value",
			in: FixedPoint[BigInt]{
				Coefficient: newBig(12),
				Scale:       6,
			},
			scaleTo: 2,
			expectedOut: FixedPoint[BigInt]{
				Coefficient: newBig(0),
				Scale:       2,
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
		invoiceAmount             lnwire.MilliSatoshi
		price                     FixedPoint[BigInt]
		expectedUnits             uint64
		expectedMinTransportUnits uint64
		expectedMinTransportMSat  lnwire.MilliSatoshi
	}{
		{
			// 5k USD per BTC @ decimal display 2.
			invoiceAmount: 200_000,
			price: FixedPoint[BigInt]{
				Coefficient: newBig(5_000_00),
				Scale:       2,
			},
			expectedUnits:             1,
			expectedMinTransportUnits: 1,
			expectedMinTransportMSat:  20_354_000,
		},
		{
			// 5k USD per BTC @ decimal display 6.
			invoiceAmount: 200_000,
			price: FixedPoint[BigInt]{
				Coefficient: newBig(5_000_00),
				Scale:       2,
			}.ScaleTo(6),
			expectedUnits:             10_000,
			expectedMinTransportUnits: 1,
			expectedMinTransportMSat:  20_354_000,
		},
		{
			// 50k USD per BTC @ decimal display 6.
			invoiceAmount: 1_973,
			price: FixedPoint[BigInt]{
				Coefficient: newBig(50_702_00),
				Scale:       2,
			}.ScaleTo(6),
			expectedUnits:             1000,
			expectedMinTransportUnits: 1,
			expectedMinTransportMSat:  2_326_308,
		},
		{
			// 50M USD per BTC @ decimal display 6.
			invoiceAmount: 123_456_789,
			price: FixedPoint[BigInt]{
				Coefficient: newBig(50_702_000_00),
				Scale:       2,
			}.ScaleTo(6),
			expectedUnits:             62595061158,
			expectedMinTransportUnits: 179,
			expectedMinTransportMSat:  355_972,
		},
		{
			// 50k USD per BTC @ decimal display 6.
			invoiceAmount: 5_070,
			price: FixedPoint[BigInt]{
				Coefficient: newBig(50_702_12),
				Scale:       2,
			}.ScaleTo(6),
			expectedUnits:             2_570,
			expectedMinTransportUnits: 1,
			expectedMinTransportMSat:  2_326_304,
		},
		{
			// 7.341M JPY per BTC @ decimal display 6.
			invoiceAmount: 5_000,
			price: FixedPoint[BigInt]{
				Coefficient: newBig(7_341_847),
				Scale:       0,
			}.ScaleTo(6),
			expectedUnits:             367_092,
			expectedMinTransportUnits: 25,
			expectedMinTransportMSat:  367_620,
		},
		{
			// 7.341M JPY per BTC @ decimal display 2.
			invoiceAmount: 5_000,
			price: FixedPoint[BigInt]{
				Coefficient: newBig(7_341_847),
				Scale:       0,
			}.ScaleTo(4),
			expectedUnits:             3_670,
			expectedMinTransportUnits: 25,
			expectedMinTransportMSat:  367_620,
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

			minUnitsFP := MinTransportableUnits(
				DefaultOnChainHtlcMSat, tc.price,
			)
			minUnits := minUnitsFP.ScaleTo(0).ToUint64()
			require.Equal(t, tc.expectedMinTransportUnits, minUnits)

			minMSat := MinTransportableMSat(
				DefaultOnChainHtlcMSat, tc.price,
			)
			require.Equal(t, tc.expectedMinTransportMSat, minMSat)
		})
	}
}

// TestPriceOracleRateExample demonstrates how to use the price oracle to
// convert an asset amount to milli-satoshis.
func TestPriceOracleRateExample(t *testing.T) {
	// A query is sent to the price oracle to obtain the conversion rate
	// between the tap asset and BTC.
	//
	// The price oracle recognizes the tap asset as a USD stablecoin and
	// retrieves the current BTC price in USD: 67,918.90 USD/BTC, which is
	// equivalent to 1,472 satoshis per USD. In other words, 1 BTC is equal
	// to 67,918.90 USD dollars.
	//
	// This floating-point rate of 67,918.90 USD/BTC will be converted into
	// a fixed-point representation to eliminate floating-point precision
	// issues.
	//
	// The fixed-point value is constructed by multiplying the rate by 10^2,
	// resulting in 67918_90, where the scale of 2 accounts for the two
	// decimal places in the rate.
	dollarPerBtc := NewBigIntFixedPoint(67918_90, 2)
	require.Equal(t, "67918.90", dollarPerBtc.String())

	// The taproot asset is a USD stablecoin, where each USD dollar is
	// equivalent to 10,000 (=10^4) tap asset units. Thus, the asset has a
	// decimal display of 4.
	//
	// Using this decimal display, it’s possible to convert an amount of the
	// tap asset into its equivalent in USD. For example: 20,000 tap asset
	// units equal 2 dollars.
	//
	// The price oracle does not return the dollar per BTC rate directly.
	// Instead, it provides the tap asset units per BTC rate. This approach
	// ensures that the asset-to-BTC rate in RFQ wire messages and internal
	// tapd calculations of asset amounts to satoshis are independent of the
	// asset's decimal display.
	//
	// To achieve this, the price oracle internally converts the dollar per
	// BTC rate into tap asset units per BTC by applying a multiplier
	// (`dollarToTap`) based on the asset’s decimal display.
	decimalDisplay := 4
	dollarToTap := NewBigIntFromUint64(uint64(math.Pow10(decimalDisplay)))

	// Calculating the asset units per BTC rate is done by multiplying the
	// dollar per BTC rate by the decimal display multiplier dollarToTap. It
	// is not a matter of re-scaling the dollar per BTC rate fixed-point.
	// The new fixed-point when evaluated as an int will have a different
	// value.
	//
	// Since we're effectively multiplying a fixed-point `dollarPerBtc` by
	// an integer `dollarToTap`, we can just create a new coefficient and
	// use the same scale as `dollarPerBtc`. Fixed-point and integer
	// multiplication:
	assetUnitsPerBtc := BigIntFixedPoint{
		Coefficient: dollarPerBtc.Coefficient.Mul(dollarToTap),
		Scale:       2,
	}
	require.Equal(t, "679189000.00", assetUnitsPerBtc.String())

	// Now we'll use the asset units per BTC rate to convert an asset amount
	// to milli-satoshis.
	//
	// The decimal display of the asset is 4, which means 10_000 units are
	// equal to 1 dollar. Note that previously we said that
	// 67,918.90 USD/BTC is equivalent to 1472 satoshi per USD.
	assetAmount := NewBigIntFixedPoint(10_000, 0)
	mSat := UnitsToMilliSatoshi(assetAmount, assetUnitsPerBtc)
	require.EqualValues(t, 1472, mSat.ToSatoshis())

	// The asset amount fixed point can have any scale and does not need to
	// match the asset's decimal display. This is because the price oracle
	// returns an asset units per BTC rate and not a dollar per BTC rate.
	assetAmount = NewBigIntFixedPoint(10_000_000, 3)
	mSat = UnitsToMilliSatoshi(assetAmount, assetUnitsPerBtc)
	require.EqualValues(t, 1472, mSat.ToSatoshis())
}

// TestAssetAmtScaleRedundant ensures that the asset amount, when represented
// as a fixed-point value, behaves consistently across different scale factors.
//
// The test validates that converting an asset amount to two different
// fixed-point representations (one with a scale of 0 and one with a random
// non-zero scale) will yield the same result when both are used in the
// `UnitsToMilliSatoshi` function.
//
// Specifically, the test does the following:
//  1. Generates a random `uint64` asset amount and constructs a fixed-point
//     representation with a scale of 0.
//  2. Generates a random scale greater than 0 and constructs another
//     fixed-point representation of the same asset amount with this non-zero
//     scale.
//  3. Validates that the two fixed-point representations yield the same
//     result when used with a randomly generated asset unit to BTC rate
//     in the `UnitsToMilliSatoshi` function.
//
// The test ensures that despite differences in scale, the conversion to
// milli-satoshis remains equivalent, confirming that the scale factor
// does not introduce inconsistencies.
//
// The test demonstrates that including the decimal display value (as the scale
// value or otherwise) when defining the asset amount has no effect on the
// result calculated using `UnitsToMilliSatoshi`.
func TestAssetAmtScaleRedundant(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		// Compute the asset amount as a `uint64`. We will convert this
		// value to two different FixedPoint values, one with a scale of
		// 0 and one with a random scale value greater than 0.
		assetAmt :=
			rapid.Uint64Range(1, 100_000_000).Draw(t, "assetAmt")

		// Construct asset amount fixed-point with a scale value of 0.
		//
		// Note: We use the `NewBigIntFixedPoint` helper function to
		// construct the fixed-point value with a scale of 0. This is
		// equivalent to:
		//
		// assetAmtBigInt := new(big.Int).SetUint64(assetAmt)
		// assetAmtZeroScale := FixedPoint[BigInt]{
		//	Coefficient: NewBigInt(assetAmtBigInt),
		//	Scale:       uint8(0),
		// }
		assetAmtZeroScale := NewBigIntFixedPoint(assetAmt, 0)
		require.Equal(t, assetAmtZeroScale.Scale, uint8(0))

		// Construct a second asset amount fixed-point with a random
		// scale value which is greater than 0.
		assetAmtFpScale := uint8(
			rapid.IntRange(2, 9).Draw(t, "assetAmountFpScale"),
		)
		assetAmtNonZeroScale := FixedPointFromUint64[BigInt](
			assetAmt, assetAmtFpScale,
		)
		require.Greater(t, assetAmtNonZeroScale.Scale, uint8(0))

		// Ensure that both asset amounts, when used with
		// UnitsToMilliSatoshi, yield the same result.
		//
		// Construct a random asset unit to BTC rate.
		assetRate :=
			rapid.Uint64Range(1, 100_000_000).Draw(t, "assetRate")
		scale := uint8(rapid.IntRange(2, 9).Draw(t, "scale"))
		assetRateFp := FixedPointFromUint64[BigInt](assetRate, scale)

		// Call UnitsToMilliSatoshi with both asset amount fixed-point
		// numbers.
		mSat1 := UnitsToMilliSatoshi(assetAmtZeroScale, assetRateFp)
		mSat2 := UnitsToMilliSatoshi(assetAmtNonZeroScale, assetRateFp)

		require.Equal(t, mSat1, mSat2)
		require.Greater(t, uint64(mSat1), uint64(0))
	})
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
				Coefficient: newBig(20_000_00),
				Scale:       2,
			}.ScaleTo(6),
			jpyPrice: FixedPoint[BigInt]{
				Coefficient: newBig(2_840_000),
				Scale:       0,
			}.ScaleTo(4),
			usdAmount:   1,
			expectedJpy: 142,
		},
		{
			name: "100 USD to JPY @ 7.341M JPY/BTC, 50'702 USD/BTC",
			usdPrice: FixedPoint[BigInt]{
				Coefficient: newBig(50_702_12),
				Scale:       2,
			}.ScaleTo(6),
			jpyPrice: FixedPoint[BigInt]{
				Coefficient: newBig(7_341_847),
				Scale:       0,
			}.ScaleTo(4),
			usdAmount:   100,
			expectedJpy: 14_480,
		},
		{
			name: "500 USD to JPY @ 142M JPY/BTC, 1M USD/BTC",
			usdPrice: FixedPoint[BigInt]{
				Coefficient: newBig(1_000_000_00),
				Scale:       2,
			}.ScaleTo(6),
			jpyPrice: FixedPoint[BigInt]{
				Coefficient: newBig(142_000_000),
				Scale:       0,
			}.ScaleTo(4),
			usdAmount:   500,
			expectedJpy: 71_000,
		},
	}

	for _, tc := range testCases {
		// Easy way to scale up the USD amount to 6 decimal display.
		dollarUnits := FixedPoint[BigInt]{
			Coefficient: newBig(tc.usdAmount),
			Scale:       0,
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
			Coefficient: newBig(1),
			Scale:       0,
		}.ScaleTo(6)
		oneJpy := FixedPoint[BigInt]{
			Coefficient: newBig(1),
			Scale:       0,
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
			tc.usdPrice.Coefficient, tc.jpyPrice.Coefficient,
			tc.usdAmount, fullJpy)
	}
}

func testMilliSatoshiToUnits[N Int[N]](t *rapid.T) {
	unitsPerBtc := rapid.Uint64Range(1, 100_000_000).Draw(t, "unitsPerBtc")
	scale := uint8(rapid.IntRange(2, 9).Draw(t, "scale"))

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
	scale := uint8(rapid.IntRange(5, 9).Draw(t, "scale"))

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
	scale := uint8(rapid.IntRange(9, 10).Draw(t, "scale"))

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

// TestConversionSatsPerAsset tests the conversion of satoshis per asset to an
// asset per BTC rate.
func TestConversionSatsPerAsset(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		satsPerAsset  uint64
		expectedValue uint64
	}{
		{
			satsPerAsset:  5,
			expectedValue: 20_000_000,
		},
		{
			satsPerAsset:  10,
			expectedValue: 10_000_000,
		},
		{
			satsPerAsset:  20,
			expectedValue: 5_000_000,
		},
		{
			satsPerAsset:  1,
			expectedValue: 100_000_000,
		},
		{
			satsPerAsset:  50,
			expectedValue: 2_000_000,
		},
		{
			satsPerAsset:  100,
			expectedValue: 1_000_000,
		},
		{
			satsPerAsset:  0,
			expectedValue: 0,
		},
	}

	for idx := range testCases {
		testCase := testCases[idx]

		t.Run(fmt.Sprintf("SatsPerAsset=%d", testCase.satsPerAsset),
			func(t *testing.T) {
				actual := SatsPerAssetToAssetRate(
					testCase.satsPerAsset,
				)
				expected := NewBigIntFixedPoint(
					testCase.expectedValue, 0,
				)
				require.Equal(t, expected, actual)
			},
		)
	}
}
