package rfqmath

import (
	"errors"
	"math"

	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/lightningnetwork/lnd/lnwire"
)

// ErrMsatOverflow is returned when a computed milli-satoshi amount does not
// fit in a uint64. Without this signal, lnwire.MilliSatoshi(BigInt.ToUint64())
// would return the low 64 bits.
var ErrMsatOverflow = errors.New("rfqmath: mSat amount exceeds uint64")

var (
	// DefaultOnChainHtlcSat is the default amount that we consider as
	// the smallest HTLC amount that can be sent on-chain. Under
	// DeterministicHTLCs the on-chain value of an HTLC is split three
	// ways by the pre-signed second-level tx:
	//
	//   1. Its baked-in fee, which lnd sets to 1.1x the relay floor
	//      (chainfee.FeePerKwFloor) over the second-level weight
	//      including the anchor output: ~227 sats for the timeout
	//      variant, ~243 sats for the success variant. The fee cannot
	//      be changed later, since the peer's signature commits to the
	//      whole transaction.
	//
	//   2. A 330-sat (lnwallet.AnchorSize) CPFP anchor output, which is
	//      how the transaction gets fee-bumped: the sweeper spends it
	//      with a wallet-funded child.
	//
	//   3. The remaining second-level HTLC output, which must clear the
	//      354-sat dust limit AND still be able to fund the sweep that
	//      finally claims it (the CSV sweep, or the justice sweep after
	//      a breach), which needs sweepAnchorOutputAmt on its own
	//      output.
	//
	// That puts the strict minimum at ~930 sats (243 + 330 + 354). 1200
	// sats keeps headroom for point 3 and rounds the user-facing minimum
	// to a clean value. Replaces the prior 6x-the-dust-limit multiplier;
	// the anchor (rather than fee headroom on the HTLC itself) handles
	// fee bumping under DeterministicHTLCs.
	//
	// TODO(GeorgeTsagk): revisit this once package relay is available.
	// Both deductions above exist only because the pre-signed parent has
	// to be independently relayable today, and that is also why it is
	// pinned to a mere 1.1x the relay floor (~1.11 sat/vB): a parent the
	// mempool rejects cannot be CPFP'd by its own anchor, so it becomes
	// unrelayable whenever the dynamic mempool minimum climbs above that
	// (i.e. any time the mempool is full and evicting above ~1 sat/vB).
	// Submitting the parent together with its fee-paying child via
	// package relay removes both constraints at once: the package feerate
	// is what gets evaluated, so the parent no longer needs its own fee,
	// and with a TRUC/v3 parent the anchor can be a 0-value P2A output.
	// Deduction 1 and 2 then go to zero, and this constant can drop to
	// roughly what point 3 alone requires (~600 sats), which also lowers
	// the minimum asset payment we quote over RFQ.
	DefaultOnChainHtlcSat = btcutil.Amount(1200)

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
	unitsPerBtc FixedPoint[N]) (lnwire.MilliSatoshi, error) {

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

	// We did the computation in terms of the scaled integers, so now we'll
	// go back to a normal mSAT value scaling down to zero (no decimals)
	// along the way. Use the checked conversion so an amtMsat that does
	// not fit in a uint64 returns an error rather than the low 64 bits.
	v, ok := amtMsat.ScaleTo(0).ToUint64Checked()
	if !ok {
		return 0, ErrMsatOverflow
	}
	return lnwire.MilliSatoshi(v), nil
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
	rate BigIntFixedPoint) (lnwire.MilliSatoshi, error) {

	// We can only transport at least one asset unit in an HTLC. And we
	// always have to send out an HTLC with a BTC amount of 354 satoshi. So
	// the minimum amount of milli-satoshi we can transport is 354,000 plus
	// the milli-satoshi equivalent of a single asset unit.
	oneAssetUnit := NewBigIntFixedPoint(1, 0)
	oneUnitMSat, err := UnitsToMilliSatoshi(oneAssetUnit, rate)
	if err != nil {
		return 0, err
	}
	return dustLimit + oneUnitMSat, nil
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
