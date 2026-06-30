//go:build itest

package custom_channels

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"slices"
	"testing"

	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/lightninglabs/taproot-assets/itest"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	tchrpc "github.com/lightninglabs/taproot-assets/taprpc/tapchannelrpc"
	fn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/invoicesrpc"
	"github.com/lightningnetwork/lnd/lntest/node"
	"github.com/lightningnetwork/lnd/lntest/port"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/stretchr/testify/require"
)

// testCustomChannelsListInvoicesAndPayments asserts that tapd's ListInvoices
// and ListPayments RPCs return the expected asset-aware view of invoices and
// payments, filter out records that don't involve any asset, and pass
// pagination offsets through from lnd.
//
//nolint:lll
func testCustomChannelsListInvoicesAndPayments(_ context.Context,
	net *itest.IntegratedNetworkHarness, t *ccHarnessTest) {

	lndArgs := slices.Clone(lndArgsTemplate)
	tapdArgs := slices.Clone(tapdArgsTemplate)

	// We use Alice as the proof courier. But in order for Alice to also
	// use itself, we need to define its port upfront.
	alicePort := port.NextAvailablePort()
	tapdArgs = append(tapdArgs, fmt.Sprintf(
		"--proofcourieraddr=%s://%s",
		proof.UniverseRpcCourierType,
		fmt.Sprintf(node.ListenerFormat, alicePort),
	))

	aliceLndArgs := slices.Clone(lndArgs)
	aliceLndArgs = append(aliceLndArgs, fmt.Sprintf(
		"--rpclisten=127.0.0.1:%d", alicePort,
	))
	alice := net.NewNode("Alice", aliceLndArgs, tapdArgs)
	bob := net.NewNode("Bob", lndArgs, tapdArgs)

	nodes := []*itest.IntegratedNode{alice, bob}
	connectAllNodes(t.t, net, nodes)
	fundAllNodes(t.t, net, nodes)

	// Mint a grouped asset on Alice (we use a group so we can verify that
	// the response surfaces the tweaked group key alongside the tranche
	// asset_id) and open an asset channel from Alice to Bob.
	groupedAsset := *ccItestAsset
	groupedAsset.NewGroupedAsset = true
	mintedAssets := itest.MintAssetsConfirmBatch(
		t.t, net.Miner, asTapd(alice),
		[]*mintrpc.MintAssetRequest{
			{Asset: &groupedAsset},
		},
	)
	cents := mintedAssets[0]
	assetID := cents.AssetGenesis.AssetId
	require.NotNil(t.t, cents.AssetGroup)
	expectedGroupKey := cents.AssetGroup.TweakedGroupKey

	t.Logf("Minted %d lightning cents, syncing universes...", cents.Amount)
	syncUniverses(t.t, alice, bob)

	ctx := context.Background()
	t.Logf("Opening asset channel...")
	assetFundResp, err := asTapd(alice).FundChannel(
		ctx, &tchrpc.FundChannelRequest{
			AssetAmount:        fundingAmount,
			AssetId:            assetID,
			PeerPubkey:         bob.PubKey[:],
			FeeRateSatPerVbyte: 5,
		},
	)
	require.NoError(t.t, err)

	assetChanPoint := &lnrpc.ChannelPoint{
		OutputIndex: uint32(assetFundResp.OutputIndex),
		FundingTxid: &lnrpc.ChannelPoint_FundingTxidStr{
			FundingTxidStr: assetFundResp.Txid,
		},
	}

	// With the channel open, mine a block to confirm it.
	mineBlocks(t, net, 6, 1)

	require.NoError(t.t, net.AssertNodeKnown(alice, bob))
	require.NoError(t.t, net.AssertNodeKnown(bob, alice))

	// Push a small keysend through the channel before Bob creates his
	// invoice. AddInvoice's RFQ hop-hint construction needs the inbound
	// channel policy from Alice's side; on a freshly-opened channel that
	// edge update may not have been gossiped yet, and the keysend forces
	// both sides to exchange policies.
	sendAssetKeySendPayment(
		t.t, alice, bob, 100, assetID, fn.None[int64](),
	)

	// Create a plain BTC invoice on Alice. We never settle it, but we use
	// it later to verify that tapd's ListInvoices filters out invoices
	// that don't involve any asset.
	btcInvoice := createNormalInvoice(t.t, alice, btcutil.Amount(1234))
	require.NotEmpty(t.t, btcInvoice.RHash)

	// Create and pay an asset invoice on Bob.
	const assetInvoiceAmount = 1_500
	invoiceResp := createAssetInvoice(
		t.t, alice, bob, assetInvoiceAmount, assetID,
	)
	sentUnits, _ := payInvoiceWithAssets(
		t.t, alice, bob, invoiceResp.PaymentRequest, assetID,
	)
	require.NotZero(t.t, sentUnits)
	t.Logf("Paid asset invoice: %d units sent", sentUnits)

	waitForAssetChannelHtlcSettlement(t.t, alice, assetChanPoint)

	// Create an asset hodl invoice, send an HTLC to it, then cancel it.
	// ListInvoices should still include the invoice as asset-related, but
	// should not count the canceled HTLC's asset amount as delivered.
	const canceledAssetInvoiceAmount = 750
	canceledInvoice := createAssetHodlInvoice(
		t.t, alice, bob, canceledAssetInvoiceAmount, assetID,
	)
	payInvoiceWithAssets(
		t.t, alice, bob, canceledInvoice.payReq, assetID,
		withFailure(lnrpc.Payment_IN_FLIGHT, failureNone),
	)

	canceledHash := canceledInvoice.preimage.Hash()
	_, err = bob.InvoicesClient.CancelInvoice(
		ctx, &invoicesrpc.CancelInvoiceMsg{
			PaymentHash: canceledHash[:],
		},
	)
	require.NoError(t.t, err)
	assertNumHtlcsAll(t.t, 0, alice, bob)

	// Create another asset hodl invoice and settle it explicitly. This
	// exercises the same hodl invoice code path as the canceled case above,
	// but verifies that settled HTLC amounts are still reported by
	// ListInvoices.
	const settledHodlInvoiceAmount = 900
	settledHodlInvoice := createAssetHodlInvoice(
		t.t, alice, bob, settledHodlInvoiceAmount, assetID,
	)
	settledHodlUnits, _ := payInvoiceWithAssets(
		t.t, alice, bob, settledHodlInvoice.payReq, assetID,
		withFailure(lnrpc.Payment_IN_FLIGHT, failureNone),
	)
	require.NotZero(t.t, settledHodlUnits)

	settledHodlHash := settledHodlInvoice.preimage.Hash()
	_, err = bob.InvoicesClient.SettleInvoice(
		ctx, &invoicesrpc.SettleInvoiceMsg{
			Preimage: settledHodlInvoice.preimage[:],
		},
	)
	require.NoError(t.t, err)
	waitForAssetChannelHtlcSettlement(t.t, alice, assetChanPoint)

	// -----------------------------------------------------------------
	// ListInvoices on Bob: Bob has four asset invoices: the warm-up
	// keysend (auto-generated), the asset invoice we explicitly paid, the
	// canceled hodl invoice, and the settled hodl invoice above. We locate
	// the settled invoices by payment hash and verify their decoded asset
	// metadata.
	// -----------------------------------------------------------------
	var bobInvoices *tchrpc.ListInvoicesResponse
	err = wait.NoError(func() error {
		var err error
		bobInvoices, err = asTapd(bob).ListInvoices(
			ctx, &tchrpc.ListInvoicesRequest{
				Request: &lnrpc.ListInvoiceRequest{
					NumMaxInvoices: 100,
				},
			},
		)
		if err != nil {
			return err
		}

		canceledInv := findAssetInvoiceOptional(
			bobInvoices, canceledHash[:],
		)
		if canceledInv == nil {
			return fmt.Errorf("canceled asset invoice not listed")
		}
		if canceledInv.Invoice.State != lnrpc.Invoice_CANCELED {
			return fmt.Errorf("invoice state is %v, want %v",
				canceledInv.Invoice.State, lnrpc.Invoice_CANCELED)
		}
		if len(canceledInv.AssetAmounts) != 0 {
			return fmt.Errorf("canceled invoice has asset amounts: %v",
				canceledInv.AssetAmounts)
		}

		settledHodlInv := findAssetInvoiceOptional(
			bobInvoices, settledHodlHash[:],
		)
		if settledHodlInv == nil {
			return fmt.Errorf("settled hodl asset invoice not listed")
		}
		if settledHodlInv.Invoice.State != lnrpc.Invoice_SETTLED {
			return fmt.Errorf("invoice state is %v, want %v",
				settledHodlInv.Invoice.State,
				lnrpc.Invoice_SETTLED)
		}
		if len(settledHodlInv.AssetAmounts) != 1 {
			return fmt.Errorf("settled hodl invoice has %d asset "+
				"amounts, want 1", len(settledHodlInv.AssetAmounts))
		}

		return nil
	}, wait.DefaultTimeout)
	require.NoError(t.t, err)

	require.Len(t.t, bobInvoices.Invoices, 4)
	canceledInv := findAssetInvoice(t.t, bobInvoices, canceledHash[:])
	require.Equal(t.t, lnrpc.Invoice_CANCELED, canceledInv.Invoice.State)
	require.Empty(t.t, canceledInv.AssetAmounts)
	require.NotEmpty(t.t, canceledInv.Invoice.Htlcs)
	for _, htlc := range canceledInv.Invoice.Htlcs {
		require.Equal(
			t.t, lnrpc.InvoiceHTLCState_CANCELED, htlc.State,
		)
	}

	settledHodlInv := findAssetInvoice(
		t.t, bobInvoices, settledHodlHash[:],
	)
	require.Equal(t.t, lnrpc.Invoice_SETTLED, settledHodlInv.Invoice.State)
	require.Len(t.t, settledHodlInv.AssetAmounts, 1)
	require.Equal(t.t, assetID, settledHodlInv.AssetAmounts[0].AssetId)
	require.Equal(
		t.t, settledHodlUnits, settledHodlInv.AssetAmounts[0].Amount,
	)
	require.Equal(
		t.t, expectedGroupKey, settledHodlInv.AssetAmounts[0].GroupKey,
	)
	require.NotEmpty(t.t, settledHodlInv.Invoice.Htlcs)
	for _, htlc := range settledHodlInv.Invoice.Htlcs {
		require.Equal(t.t, lnrpc.InvoiceHTLCState_SETTLED, htlc.State)
	}

	assetInv := findAssetInvoice(t.t, bobInvoices, invoiceResp.RHash)
	require.NotNil(t.t, assetInv.Invoice)
	require.Len(t.t, assetInv.AssetAmounts, 1)
	require.Equal(t.t, assetID, assetInv.AssetAmounts[0].AssetId)
	require.Equal(
		t.t, sentUnits, assetInv.AssetAmounts[0].Amount,
	)
	require.Equal(
		t.t, expectedGroupKey, assetInv.AssetAmounts[0].GroupKey,
	)

	// Pagination offsets must come straight from lnd.
	require.NotZero(t.t, bobInvoices.LastIndexOffset)

	// -----------------------------------------------------------------
	// ListInvoices on Alice: she only has the BTC invoice, which must be
	// filtered out (no asset HTLCs).
	// -----------------------------------------------------------------
	aliceInvoices, err := asTapd(alice).ListInvoices(
		ctx, &tchrpc.ListInvoicesRequest{
			Request: &lnrpc.ListInvoiceRequest{
				NumMaxInvoices: 100,
			},
		},
	)
	require.NoError(t.t, err)
	require.Empty(t.t, aliceInvoices.Invoices)

	// Even though no asset invoices were returned, the BTC invoice in
	// lnd's DB advances the offset, so we expect it to be non-zero.
	require.NotZero(t.t, aliceInvoices.LastIndexOffset)

	// -----------------------------------------------------------------
	// ListPayments on Alice: Alice has four asset payments, the warm-up
	// keysend, the settled invoice payment, the canceled hodl payment, and
	// the settled hodl payment. Include incomplete payments so the failed
	// canceled hodl payment is returned.
	// -----------------------------------------------------------------
	var alicePayments *tchrpc.ListPaymentsResponse
	err = wait.NoError(func() error {
		var err error
		alicePayments, err = asTapd(alice).ListPayments(
			ctx, &tchrpc.ListPaymentsRequest{
				Request: &lnrpc.ListPaymentsRequest{
					MaxPayments:       100,
					IncludeIncomplete: true,
				},
			},
		)
		if err != nil {
			return err
		}

		canceledPayment := findAssetPaymentOptional(
			alicePayments, hex.EncodeToString(canceledHash[:]),
		)
		if canceledPayment == nil {
			return fmt.Errorf("canceled asset payment not listed")
		}
		if canceledPayment.Payment.Status != lnrpc.Payment_FAILED {
			return fmt.Errorf("payment state is %v, want %v",
				canceledPayment.Payment.Status,
				lnrpc.Payment_FAILED)
		}
		if len(canceledPayment.AssetAmounts) != 0 {
			return fmt.Errorf("failed payment has asset amounts: %v",
				canceledPayment.AssetAmounts)
		}

		settledHodlPayment := findAssetPaymentOptional(
			alicePayments, hex.EncodeToString(settledHodlHash[:]),
		)
		if settledHodlPayment == nil {
			return fmt.Errorf("settled hodl asset payment not listed")
		}
		if settledHodlPayment.Payment.Status != lnrpc.Payment_SUCCEEDED {
			return fmt.Errorf("payment state is %v, want %v",
				settledHodlPayment.Payment.Status,
				lnrpc.Payment_SUCCEEDED)
		}
		if len(settledHodlPayment.AssetAmounts) != 1 {
			return fmt.Errorf("settled hodl payment has %d asset "+
				"amounts, want 1",
				len(settledHodlPayment.AssetAmounts))
		}

		return nil
	}, wait.DefaultTimeout)
	require.NoError(t.t, err)

	require.Len(t.t, alicePayments.Payments, 4)
	canceledPayment := findAssetPayment(
		t.t, alicePayments, hex.EncodeToString(canceledHash[:]),
	)
	require.Equal(t.t, lnrpc.Payment_FAILED, canceledPayment.Payment.Status)
	require.Empty(t.t, canceledPayment.AssetAmounts)

	settledHodlPayment := findAssetPayment(
		t.t, alicePayments, hex.EncodeToString(settledHodlHash[:]),
	)
	require.Equal(t.t, lnrpc.Payment_SUCCEEDED, settledHodlPayment.Payment.Status)
	require.Len(t.t, settledHodlPayment.AssetAmounts, 1)
	require.Equal(
		t.t, assetID, settledHodlPayment.AssetAmounts[0].AssetId,
	)
	require.Equal(
		t.t, settledHodlUnits,
		settledHodlPayment.AssetAmounts[0].Amount,
	)
	require.Equal(
		t.t, expectedGroupKey,
		settledHodlPayment.AssetAmounts[0].GroupKey,
	)

	wantHash := hex.EncodeToString(invoiceResp.RHash)
	assetPay := findAssetPayment(t.t, alicePayments, wantHash)
	require.NotNil(t.t, assetPay.Payment)
	require.Len(t.t, assetPay.AssetAmounts, 1)
	require.Equal(t.t, assetID, assetPay.AssetAmounts[0].AssetId)
	require.Equal(
		t.t, sentUnits, assetPay.AssetAmounts[0].Amount,
	)
	require.Equal(
		t.t, expectedGroupKey, assetPay.AssetAmounts[0].GroupKey,
	)

	require.NotZero(t.t, alicePayments.LastIndexOffset)

	// -----------------------------------------------------------------
	// ListPayments on Bob: he hasn't sent anything, so the result must
	// be empty.
	// -----------------------------------------------------------------
	bobPayments, err := asTapd(bob).ListPayments(
		ctx, &tchrpc.ListPaymentsRequest{
			Request: &lnrpc.ListPaymentsRequest{
				MaxPayments: 100,
			},
		},
	)
	require.NoError(t.t, err)
	require.Empty(t.t, bobPayments.Payments)
}

// findAssetInvoiceOptional locates the asset invoice with the given r_hash in
// the response, returning nil if none is found.
func findAssetInvoiceOptional(resp *tchrpc.ListInvoicesResponse,
	rHash []byte) *tchrpc.AssetInvoice {

	for _, inv := range resp.Invoices {
		if inv.Invoice != nil && bytes.Equal(inv.Invoice.RHash, rHash) {
			return inv
		}
	}

	return nil
}

// findAssetInvoice locates the asset invoice with the given r_hash in the
// response, failing the test if none is found.
func findAssetInvoice(t *testing.T, resp *tchrpc.ListInvoicesResponse,
	rHash []byte) *tchrpc.AssetInvoice {

	t.Helper()
	inv := findAssetInvoiceOptional(resp, rHash)
	if inv != nil {
		return inv
	}

	require.Failf(t, "asset invoice not found",
		"no asset invoice with r_hash %x in %d results", rHash,
		len(resp.Invoices))
	return nil
}

// findAssetPaymentOptional locates the asset payment with the given
// hex-encoded payment_hash in the response, returning nil if none is found.
func findAssetPaymentOptional(resp *tchrpc.ListPaymentsResponse,
	hash string) *tchrpc.AssetPayment {

	for _, p := range resp.Payments {
		if p.Payment != nil && p.Payment.PaymentHash == hash {
			return p
		}
	}

	return nil
}

// findAssetPayment locates the asset payment with the given hex-encoded
// payment_hash in the response, failing the test if none is found.
func findAssetPayment(t *testing.T, resp *tchrpc.ListPaymentsResponse,
	hash string) *tchrpc.AssetPayment {

	t.Helper()
	p := findAssetPaymentOptional(resp, hash)
	if p != nil {
		return p
	}

	require.Failf(t, "asset payment not found",
		"no asset payment with hash %s in %d results", hash,
		len(resp.Payments))
	return nil
}
