package tapchannel

import (
	"testing"

	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// TestUnitConversionTolerance demonstrates the unit conversion loss of
// precision issue that lead to the increased tolerance value in the invoice
// manager.
func TestUnitConversionTolerance(t *testing.T) {
	const (
		invoiceAmtUnits = 6_000_000
		numHTLCs        = 2
	)
	var (
		rate = rfqmath.BigIntFixedPoint{
			Coefficient: rfqmath.NewBigIntFromUint64(9852216748),
			Scale:       0,
		}
	)

	t.Logf("Initial amount in asset units: %d", invoiceAmtUnits)

	assetAmountFP := rfqmath.NewBigIntFixedPoint(invoiceAmtUnits, 0)
	invoiceAmtMsat := rfqmath.UnitsToMilliSatoshi(assetAmountFP, rate)

	t.Logf("Invoice amount in msat: %d", invoiceAmtMsat)

	numAssetUnitsFp := rfqmath.MilliSatoshiToUnits(invoiceAmtMsat, rate)
	numAssetUnits := numAssetUnitsFp.ScaleTo(0).ToUint64()

	msatPerUnit := float64(invoiceAmtMsat) / float64(numAssetUnits)
	t.Logf("Calculated msat per asset unit: %.2f", msatPerUnit)

	t.Logf("Number of asset units after round trip: %d", numAssetUnits)

	shardSizeMSat := invoiceAmtMsat / numHTLCs

	shardSizeFP := rfqmath.MilliSatoshiToUnits(shardSizeMSat, rate)
	shardSizeUnit := shardSizeFP.ScaleTo(0).ToUint64()
	t.Logf("Sum of %d shards in asset units: %d", numHTLCs,
		shardSizeUnit*numHTLCs)

	shardSumFP := rfqmath.NewBigIntFixedPoint(shardSizeUnit*numHTLCs, 0)
	inboundAmountMSat := rfqmath.UnitsToMilliSatoshi(shardSumFP, rate)

	t.Logf("Inbound amount in msat: %d", inboundAmountMSat)
	t.Logf("Total tolerance required in msat: %d",
		invoiceAmtMsat-inboundAmountMSat)

	marginAssetUnits := rfqmath.NewBigIntFixedPoint(numHTLCs, 0)
	allowedMarginMSat := rfqmath.UnitsToMilliSatoshi(marginAssetUnits, rate)

	newMarginAssetUnits := rfqmath.NewBigIntFixedPoint(numHTLCs+1, 0)
	newAllowedMarginMSat := rfqmath.UnitsToMilliSatoshi(
		newMarginAssetUnits, rate,
	)

	t.Logf("Old tolerance allowed in msat: %d", allowedMarginMSat)
	t.Logf("New tolerance allowed in msat: %d", newAllowedMarginMSat)
}

// TestUnitConversionToleranceRapid uses rapid to randomly draw invoice amounts,
// HTLC counts, and coefficients to test unit conversion tolerance. This ensures
// the conversion logic is robust against a wide range of values.
func TestUnitConversionToleranceRapid(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		invoiceAmtUnits := rapid.Uint64Range(1, 10_000_000).
			Draw(t, "invoiceAmtUnits")
		numHTLCs := rapid.Uint64Range(1, 16).
			Draw(t, "numHTLCs")
		coefficient := rapid.Uint64Range(1, 300_000_000_000).
			Draw(t, "coefficient")

		rate := rfqmath.BigIntFixedPoint{
			Coefficient: rfqmath.NewBigIntFromUint64(coefficient),
			Scale:       0,
		}

		assetAmountFP := rfqmath.NewBigIntFixedPoint(invoiceAmtUnits, 0)
		invoiceAmtMsat := rfqmath.UnitsToMilliSatoshi(
			assetAmountFP, rate,
		)

		shardSizeMSat := invoiceAmtMsat / lnwire.MilliSatoshi(numHTLCs)
		shardSizeFP := rfqmath.MilliSatoshiToUnits(shardSizeMSat, rate)
		shardSizeUnit := shardSizeFP.ScaleTo(0).ToUint64()

		shardSumFP := rfqmath.NewBigIntFixedPoint(
			shardSizeUnit*numHTLCs, 0,
		)
		inboundAmountMSat := rfqmath.UnitsToMilliSatoshi(
			shardSumFP, rate,
		)

		newMarginAssetUnits := rfqmath.NewBigIntFixedPoint(
			numHTLCs+1, 0,
		)
		newAllowedMarginMSat := rfqmath.UnitsToMilliSatoshi(
			newMarginAssetUnits, rate,
		)

		// The difference should be within the newly allowed margin.
		require.LessOrEqual(
			t,
			invoiceAmtMsat-inboundAmountMSat, newAllowedMarginMSat,
		)
	})
}
