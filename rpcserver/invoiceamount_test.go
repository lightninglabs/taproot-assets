package rpcserver

import (
	"testing"

	"github.com/lightninglabs/taproot-assets/taprpc/rfqrpc"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/stretchr/testify/require"
)

// TestValidateInvoiceAmountPartialFill checks that passing a
// capped asset amount to validateInvoiceAmount produces a
// proportionally smaller msat value than the full amount.
func TestValidateInvoiceAmountPartialFill(t *testing.T) {
	t.Parallel()

	// Rate: 10,000,000 cents/BTC ($100k).
	quote := &rfqrpc.PeerAcceptedBuyQuote{
		AskAssetRate: &rfqrpc.FixedPoint{
			Coefficient: "10000000",
			Scale:       0,
		},
		AssetMaxAmount:    1000,
		AcceptedMaxAmount: 500,
	}

	emptyInv := &lnrpc.Invoice{}

	fullMsat, err := validateInvoiceAmount(
		quote, 1000, emptyInv,
	)
	require.NoError(t, err)

	cappedMsat, err := validateInvoiceAmount(
		quote, 500, emptyInv,
	)
	require.NoError(t, err)

	require.Greater(t, fullMsat, cappedMsat)

	// The capped amount should be exactly half the full
	// amount, since 500 is half of 1000.
	require.Equal(t, fullMsat/2, cappedMsat)
}

// TestValidateInvoiceAmountSatPartialFill checks that a
// sat-denominated invoice is rejected when the negotiated fill
// quantity (AcceptedMaxAmount) cannot carry the requested msat.
func TestValidateInvoiceAmountSatPartialFill(t *testing.T) {
	t.Parallel()

	// Rate: 10,000,000 units/BTC.
	quote := &rfqrpc.PeerAcceptedBuyQuote{
		AskAssetRate: &rfqrpc.FixedPoint{
			Coefficient: "10000000",
			Scale:       0,
		},
		AssetMaxAmount:    1000,
		AcceptedMaxAmount: 500,
	}

	// At this rate, 1000 units ≈ 10,000,000 msat and 500 units
	// ≈ 5,000,000 msat. Request an amount between the two so it
	// passes with AssetMaxAmount but fails with the negotiated
	// AcceptedMaxAmount.
	inv := &lnrpc.Invoice{
		ValueMsat: 7_000_000,
	}

	_, err := validateInvoiceAmount(quote, 0, inv)
	require.ErrorContains(t, err, "max routable amount")
}
