package rpcserver

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/stretchr/testify/require"
)

// paymentWithRouteData returns a payment with a single succeeded HTLC
// attempt whose route carries the given custom channel data.
func paymentWithRouteData(routeData []byte) *lnrpc.Payment {
	return &lnrpc.Payment{
		PaymentHash: "00",
		Htlcs: []*lnrpc.HTLCAttempt{{
			Status: lnrpc.HTLCAttempt_SUCCEEDED,
			Route: &lnrpc.Route{
				CustomChannelData: routeData,
			},
		}},
	}
}

// TestAssetAmountsFromPayment checks that assetAmountsFromPayment only
// classifies a payment as an asset payment if at least one HTLC attempt
// actually carries asset balances, or the payment-level first hop custom
// records mark it as such. Non-asset payments can end up with route custom
// channel data that decodes to an empty balance list (issue #2230), and
// those must not be classified as asset payments.
func TestAssetAmountsFromPayment(t *testing.T) {
	t.Parallel()

	var assetID asset.ID
	copy(assetID[:], bytes.Repeat([]byte{0x01}, 32))
	assetIDHex := hex.EncodeToString(assetID[:])

	t.Run("empty json stamp is not an asset payment", func(t *testing.T) {
		// This is what lnd's aux data parser produces for a route
		// whose first hop custom records contain no asset records.
		stamp := []byte(`{"balances": [], "rfq_id": ""}`)

		amounts, isAsset, err := assetAmountsFromPayment(
			paymentWithRouteData(stamp),
		)
		require.NoError(t, err)
		require.False(t, isAsset)
		require.Empty(t, amounts)
	})

	t.Run("non-asset tlv stamp is not an asset payment",
		func(t *testing.T) {
			// Without an aux data parser configured in lnd (tapd
			// in remote mode), the same route data surfaces as
			// the raw TLV encoding of the first hop custom
			// records. lnd adds the experimental accountability
			// signal to every payment by default.
			records := lnwire.CustomRecords{
				uint64(lnwire.ExperimentalAccountableType): {
					lnwire.ExperimentalUnaccountable,
				},
			}
			blob, err := records.Serialize()
			require.NoError(t, err)

			amounts, isAsset, err := assetAmountsFromPayment(
				paymentWithRouteData(blob),
			)
			require.NoError(t, err)
			require.False(t, isAsset)
			require.Empty(t, amounts)
		})

	t.Run("no route data is not an asset payment", func(t *testing.T) {
		amounts, isAsset, err := assetAmountsFromPayment(
			paymentWithRouteData(nil),
		)
		require.NoError(t, err)
		require.False(t, isAsset)
		require.Empty(t, amounts)
	})

	t.Run("asset balances mark an asset payment", func(t *testing.T) {
		jsonHtlc, err := json.Marshal(&rfqmsg.JsonHtlc{
			Balances: []*rfqmsg.JsonAssetTranche{{
				AssetID: assetIDHex,
				Amount:  42,
			}},
		})
		require.NoError(t, err)

		amounts, isAsset, err := assetAmountsFromPayment(
			paymentWithRouteData(jsonHtlc),
		)
		require.NoError(t, err)
		require.True(t, isAsset)
		require.Equal(t, map[asset.ID]uint64{assetID: 42}, amounts)
	})

	t.Run("first hop asset records mark an asset payment",
		func(t *testing.T) {
			// A fully failed asset payment has no usable HTLC
			// attempts, but its payment-level first hop custom
			// records still identify it as an asset payment.
			htlc := rfqmsg.NewHtlc(
				[]*rfqmsg.AssetBalance{
					rfqmsg.NewAssetBalance(assetID, 42),
				},
				fn.None[rfqmsg.ID](),
				fn.None[[]rfqmsg.ID](),
			)
			records, err := htlc.ToCustomRecords()
			require.NoError(t, err)

			amounts, isAsset, err := assetAmountsFromPayment(
				&lnrpc.Payment{
					PaymentHash:           "00",
					FirstHopCustomRecords: records,
				},
			)
			require.NoError(t, err)
			require.True(t, isAsset)
			require.Empty(t, amounts)
		})
}
