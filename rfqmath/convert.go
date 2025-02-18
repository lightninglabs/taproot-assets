package rfqmath

import (
	"math"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwire"
)

var (
	// DefaultOnChainHtlcSat is the default amount that we consider as the
	// smallest HTLC amount that can be sent on-chain. This needs to be
	// greater than the dust limit for an HTLC.
	DefaultOnChainHtlcSat = lnwallet.DustLimitForSize(
		input.UnknownWitnessSize,
	)

	// DefaultOnChainHtlcMSat is the default amount that we consider as the
	// smallest HTLC amount that can be sent on-chain in milli-satoshis.
	DefaultOnChainHtlcMSat = lnwire.NewMSatFromSatoshis(
		DefaultOnChainHtlcSat,
	)
)

// defaultArithmeticScale is the default scale used for arithmetic operations.
// This is used to ensure that we don't lose precision when doing arithmetic
// operations.
const defaultArithmeticScale = 11

// MilliSatoshiToUnits converts the given milli-satoshi amount to units using
// the given price in units per bitcoin as a fixed point in the asset's desired
// resolution (scale equal to decimal display).
//
// Given the amount of mSat (X), and the number of units per BTC (Y), we can
// compute the total amount of units (U) as follows:
//   - U = (X / M) * Y
//   - where M is the number of mSAT in a BTC (100,000,000,000).
func MilliSatoshiToUnits[N Int[N]](milliSat lnwire.MilliSatoshi,
	unitsPerBtc FixedPoint[N]) FixedPoint[N] {

	// We take the max of the target arithmetic scale and the given unit's
	// scale, which is expected to be the asset's decimal display value.
	arithmeticScale := uint8(math.Max(
		float64(defaultArithmeticScale), float64(unitsPerBtc.Scale),
	))

	// Before we do any computation, we'll scale everything up to our
	// arithmetic scale.
	mSatFixed := FixedPointFromUint64[N](
		uint64(milliSat), arithmeticScale,
	)
	scaledUnitsPerBtc := unitsPerBtc.ScaleTo(arithmeticScale)

	// Next, we'll convert the amount of mSAT to BTC. We do this by
	// dividing by the number of mSAT in a BTC.
	oneBtcInMilliSat := FixedPointFromUint64[N](
		uint64(btcutil.SatoshiPerBitcoin*1_000), arithmeticScale,
	)
	amtBTC := mSatFixed.Div(oneBtcInMilliSat)

	// Now that we have the amount of BTC as input, and the amount of units
	// per BTC, we multiply the two to get the total amount of units.
	amtUnits := amtBTC.Mul(scaledUnitsPerBtc)

	// The final response will need to scale back down to the original
	// amount of units that were passed in.
	scaledAmt := amtUnits.ScaleTo(unitsPerBtc.Scale)

	return scaledAmt
}

// UnitsToMilliSatoshi converts the given number of asset units to a
// milli-satoshi amount, using the given price in units per bitcoin as a fixed
// point in the asset's desired resolution (scale equal to decimal display).
//
// Given the amount of asset units (U), and the number of units per BTC (Y), we
// compute the total amount of mSAT (X) as follows:
//   - X = (U / Y) * M
//   - where M is the number of mSAT in a BTC (100,000,000,000).
//
// TODO(ffranr): This function only works with BigInt as the underlying
// integer type. For built-in integer types, oneBtcInMilliSat overflows.
// We should remove the type generic or reformulate.
func UnitsToMilliSatoshi[N Int[N]](assetUnits,
	unitsPerBtc FixedPoint[N]) lnwire.MilliSatoshi {

	// We take the max of the target arithmetic scale and the given unit's
	// scale, which is expected to be the asset's decimal display value.
	arithmeticScale := uint8(math.Max(
		float64(defaultArithmeticScale), float64(unitsPerBtc.Scale),
	))

	// Before we do the computation, we'll scale everything up to our
	// arithmetic scale.
	assetUnits = assetUnits.ScaleTo(arithmeticScale)
	unitsPerBtc = unitsPerBtc.ScaleTo(arithmeticScale)

	// We have the number of units, and the number of units per BTC, so we
	// can arrive at the number of BTC via: BTC = units / (units/BTC).
	amtBTC := assetUnits.Div(unitsPerBtc)

	// Now that we have the amount of BTC, we can map to mSat by
	// multiplying by the number of mSAT in a BTC.
	oneBtcInMilliSat := FixedPointFromUint64[N](
		uint64(btcutil.SatoshiPerBitcoin*1_000), arithmeticScale,
	)

	amtMsat := amtBTC.Mul(oneBtcInMilliSat)

	// We did the computation in terms of the scaled integers, so no we'll
	// go back to a normal mSAT value scaling down to zero (no decimals)
	// along the way.
	return lnwire.MilliSatoshi(amtMsat.ScaleTo(0).ToUint64())
}

// MinTransportableUnits computes the minimum number of transportable units
// of an asset given its asset rate and the constant HTLC dust limit. This
// function can be used to enforce a minimum invoice amount to prevent
// forwarding failures due to invalid fees.
//
// Given a wallet end user A, an edge node B, an asset rate of 100 milli-
// satoshi per asset unit and a flat 0.1% routing fee (to simplify the
// scenario), the following invoice based receive events can occur:
//  1. Success case: User A creates an invoice over 5,000 units (500,000 milli-
//     satoshis) that is paid by the network. An HTLC over 500,500 milli-
//     satoshis arrives at B. B converts the HTLC to 5,000 units and sends
//     354,000 milli-satoshis to A.
//     A receives a total "worth" of 854,000 milli-satoshis, which is already
//     more than the invoice amount. But at least the forwarding rule in `lnd`
//     for B is not violated (outgoing amount mSat < incoming amount mSat).
//  2. Failure case: User A creates an invoice over 3,530 units (353,000 milli-
//     satoshis) that is paid by the network. An HTLC over 353,530 milli-
//     satoshis arrives at B. B converts the HTLC to 3,530 units and sends
//     354,000 milli-satoshis to A.
//     This fails in the `lnd` forwarding logic, because the outgoing amount
//     (354,000 milli-satoshis) is greater than the incoming amount (353,530
//     milli-satoshis).
func MinTransportableUnits(dustLimit lnwire.MilliSatoshi,
	rate BigIntFixedPoint) BigIntFixedPoint {

	// We can only transport an asset unit equivalent amount that's greater
	// than the dust limit for an HTLC, since we'll always want an HTLC that
	// carries an HTLC to be reflected in an on-chain output.
	units := MilliSatoshiToUnits(dustLimit, rate)

	// If the asset's rate is such that a single unit represents more than
	// the dust limit in satoshi, then the above calculation will come out
	// as 0. But we can't transport zero units, so we'll set the minimum to
	// one unit.
	if units.ScaleTo(0).ToUint64() == 0 {
		units = NewBigIntFixedPoint(1, 0)
	}

	return units
}

// MinTransportableMSat computes the minimum amount of milli-satoshis that can
// be represented in a Lightning Network payment when transferring an asset,
// given the asset rate and the constant HTLC dust limit. This function can be
// used to enforce a minimum payable amount with assets, as any invoice amount
// below this value would be uneconomical as the total amount sent would exceed
// the total invoice amount.
func MinTransportableMSat(dustLimit lnwire.MilliSatoshi,
	rate BigIntFixedPoint) lnwire.MilliSatoshi {

	// We can only transport at least one asset unit in an HTLC. And we
	// always have to send out an HTLC with a BTC amount of 354 satoshi. So
	// the minimum amount of milli-satoshi we can transport is 354,000 plus
	// the milli-satoshi equivalent of a single asset unit.
	oneAssetUnit := NewBigIntFixedPoint(1, 0)
	return dustLimit + UnitsToMilliSatoshi(oneAssetUnit, rate)
}

// SatsPerAssetToAssetRate converts a satoshis per asset rate to an asset to
// BTC rate.
func SatsPerAssetToAssetRate(satsPerAsset uint64) BigIntFixedPoint {
	if satsPerAsset == 0 {
		return NewBigIntFixedPoint(0, 0)
	}

	satsPerAssetFp := NewBigIntFixedPoint(satsPerAsset, 0)
	satsPerBTC := NewBigIntFixedPoint(100_000_000, 0)

	return satsPerBTC.Div(satsPerAssetFp)
}
