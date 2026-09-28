//go:build itest

package custom_channels

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/lightninglabs/taproot-assets/itest"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapfreighter"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	tchrpc "github.com/lightninglabs/taproot-assets/taprpc/tapchannelrpc"
	"github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lntest/node"
	"github.com/lightningnetwork/lnd/lntest/port"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/stretchr/testify/require"
)

// testCustomChannelsRbfCoopClose exercises the RBF cooperative close flow
// (option_simple_close) for asset channels. Both parties bump the close fee
// a few times, which produces a new close transaction per round, each with
// its own asset outputs. Whichever of them confirms, both sides need to be
// able to finalize the close: the aux closer must have re-committed the
// assets in every candidate and must recognize the one that confirmed. The
// second part restarts the initiator after a bump, so the candidate that
// confirms is only known from the persisted close state.
func testCustomChannelsRbfCoopClose(ctx context.Context,
	net *itest.IntegratedNetworkHarness, t *ccHarnessTest) {

	lndArgs := slices.Clone(lndArgsTemplate)
	tapdArgs := slices.Clone(tapdArgsTemplate)

	// Charlie acts as the proof courier for both himself and Dave.
	charliePort := port.NextAvailablePort()
	tapdArgs = append(tapdArgs, fmt.Sprintf(
		"--proofcourieraddr=%s://%s",
		proof.UniverseRpcCourierType,
		fmt.Sprintf(node.ListenerFormat, charliePort),
	))

	charlieLndArgs := append(slices.Clone(lndArgs), fmt.Sprintf(
		"--rpclisten=127.0.0.1:%d", charliePort,
	))

	charlie := net.NewNode("Charlie", charlieLndArgs, tapdArgs)
	dave := net.NewNode("Dave", lndArgs, tapdArgs)

	nodes := []*itest.IntegratedNode{charlie, dave}
	connectAllNodes(t.t, net, nodes)
	fundAllNodes(t.t, net, nodes)

	// The fee estimate is set to the floor, so the fee rates we request
	// for the close rounds are always above it, and a close that is
	// re-negotiated after a restart doesn't replace the candidates we
	// bumped to explicitly.
	const floorFeeRate = chainfee.SatPerKWeight(250)
	net.FeeService.SetFeeRate(floorFeeRate, 1)
	net.FeeService.SetFeeRate(floorFeeRate, 6)

	mintedAssets := itest.MintAssetsConfirmBatch(
		t.t, net.Miner, asTapd(charlie),
		[]*mintrpc.MintAssetRequest{
			{Asset: ccItestAsset},
		},
	)
	cents := mintedAssets[0]
	assetID := cents.AssetGenesis.AssetId

	t.Logf("Minted %d cents, syncing universes...", cents.Amount)
	syncUniverses(t.t, charlie, dave)

	// Part 1: both parties bump the fee, then the last bump confirms.
	t.Logf("Opening first asset channel Charlie -> Dave...")
	chanPoint := openRbfTestChannel(ctx, t, net, charlie, dave, cents)

	// Charlie kicks things off at 5 sat/vB.
	charlieStream := rbfCloseChannel(t, charlie, chanPoint, 5)
	charlieTxid, feeRate := waitForRbfPendingUpdate(t, charlieStream, true)
	require.EqualValues(t.t, 5, feeRate)
	net.Miner.AssertTxInMempool(*charlieTxid)

	assertWaitingCloseChannelAssetData(t.t, charlie, chanPoint)
	assertWaitingCloseChannelAssetData(t.t, dave, chanPoint)

	// Dave bumps to 10 sat/vB with his own funds, which replaces Charlie's
	// transaction in the mempool.
	daveStream := rbfCloseChannel(t, dave, chanPoint, 10)
	daveTxid, feeRate := waitForRbfPendingUpdate(t, daveStream, true)
	require.EqualValues(t.t, 10, feeRate)
	require.NotEqual(t.t, charlieTxid, daveTxid)
	net.Miner.AssertTxInMempool(*daveTxid)

	// Charlie is told about Dave's transaction as well.
	remoteTxid, _ := waitForRbfPendingUpdate(t, charlieStream, false)
	require.Equal(t.t, daveTxid, remoteTxid)

	// Charlie bumps by too little for the mempool to accept the
	// replacement. The close is still negotiated, so the aux closers
	// track a candidate that never made it into the mempool.
	rejectedStream := rbfCloseChannel(t, charlie, chanPoint, 6)
	rejectedTxid, feeRate := waitForRbfPendingUpdate(
		t, rejectedStream, true,
	)
	require.EqualValues(t.t, 6, feeRate)
	require.NotEqual(t.t, daveTxid, rejectedTxid)
	net.Miner.AssertTxInMempool(*daveTxid)

	// Charlie bumps to 20 sat/vB, which replaces Dave's transaction.
	finalStream := rbfCloseChannel(t, charlie, chanPoint, 20)
	finalTxid, feeRate := waitForRbfPendingUpdate(t, finalStream, true)
	require.EqualValues(t.t, 20, feeRate)
	net.Miner.AssertTxInMempool(*finalTxid)

	charlieSendEvents, daveSendEvents := subscribeSendEvents(
		ctx, t, charlie, dave,
	)

	mineBlocks(t, net, 1, 1)

	closeUpdate, err := net.WaitForChannelClose(finalStream)
	require.NoError(t.t, err)

	closeTxid, err := chainhash.NewHash(closeUpdate.ClosingTxid)
	require.NoError(t.t, err)
	require.Equal(t.t, finalTxid, closeTxid)

	closeTx := net.Miner.GetRawTransaction(*closeTxid).MsgTx()
	t.Logf("First channel closed with txid: %v", closeTxid)

	// Both aux closers must have finalized the close, which means the
	// assets were re-committed in the confirmed transaction and the
	// transfers are recorded.
	waitForSendEvent(t.t, charlieSendEvents, tapfreighter.SendStateComplete)
	waitForSendEvent(t.t, daveSendEvents, tapfreighter.SendStateComplete)

	// Both parties have assets and BTC, so the close has an asset and a
	// BTC output for each of them.
	assertDefaultCoOpCloseBalance(true, true)(
		t.t, charlie, dave, closeTx, closeUpdate, [][]byte{assetID},
		nil, charlie,
	)

	assertClosedChannelAssetData(t.t, charlie, chanPoint)
	assertClosedChannelAssetData(t.t, dave, chanPoint)

	// Part 2: Charlie restarts after Dave bumped the fee. The candidate
	// that confirms was created before the restart, so Charlie's aux
	// closer can only finalize it from the persisted close state. The
	// close that's re-negotiated on reconnect uses the floor fee rate, so
	// it doesn't replace Dave's transaction.
	t.Logf("Opening second asset channel Charlie -> Dave...")
	chanPoint = openRbfTestChannel(ctx, t, net, charlie, dave, cents)

	charlieStream = rbfCloseChannel(t, charlie, chanPoint, 5)
	charlieTxid, _ = waitForRbfPendingUpdate(t, charlieStream, true)
	net.Miner.AssertTxInMempool(*charlieTxid)

	daveStream = rbfCloseChannel(t, dave, chanPoint, 10)
	daveTxid, _ = waitForRbfPendingUpdate(t, daveStream, true)
	net.Miner.AssertTxInMempool(*daveTxid)

	assertWaitingCloseChannelAssetData(t.t, charlie, chanPoint)
	assertWaitingCloseChannelAssetData(t.t, dave, chanPoint)

	t.Logf("Restarting Charlie with Dave's close tx in the mempool")
	charlie.Restart()
	net.EnsureConnected(t.t, charlie, dave)

	// Dave's transaction is still the one in the mempool.
	net.Miner.AssertTxInMempool(*daveTxid)

	charlieSendEvents, daveSendEvents = subscribeSendEvents(
		ctx, t, charlie, dave,
	)

	block := mineBlocks(t, net, 1, 1)[0]
	require.Len(t.t, block.Transactions, 2)
	require.Equal(t.t, *daveTxid, block.Transactions[1].TxHash())

	waitForSendEvent(t.t, charlieSendEvents, tapfreighter.SendStateComplete)
	waitForSendEvent(t.t, daveSendEvents, tapfreighter.SendStateComplete)

	assertClosedChannelAssetData(t.t, charlie, chanPoint)
	assertClosedChannelAssetData(t.t, dave, chanPoint)

	// With both channels closed, all the minted assets are back on chain,
	// split between the two parties.
	daveBalance := uint64(2 * rbfTestKeySendAmount)
	assertSpendableBalance(t.t, dave, assetID, nil, daveBalance)
	assertSpendableBalance(
		t.t, charlie, assetID, nil, cents.Amount-daveBalance,
	)
}

const (
	// rbfTestKeySendAmount is the amount of assets sent to Dave in each
	// channel, so both parties have an asset output on the close
	// transaction.
	rbfTestKeySendAmount = 1_000

	// rbfTestBtcKeySendAmount is the amount of satoshis sent to Dave in
	// each channel, so Dave can pay for fee bumps.
	rbfTestBtcKeySendAmount = 30_000
)

// openRbfTestChannel opens an asset channel from Charlie to Dave and sends
// some assets and BTC to Dave, so both parties have balances to close with.
// Dave needs a BTC balance to be able to pay for a fee bump: a party whose
// BTC output would be dust after paying the fee can't be the closer of an
// asset channel, as its asset output hangs off of its BTC output.
func openRbfTestChannel(ctx context.Context, t *ccHarnessTest,
	net *itest.IntegratedNetworkHarness,
	charlie, dave *itest.IntegratedNode,
	cents *taprpc.Asset) *lnrpc.ChannelPoint {

	t.t.Helper()

	assetID := cents.AssetGenesis.AssetId
	assetFundResp, err := asTapd(charlie).FundChannel(
		ctx, &tchrpc.FundChannelRequest{
			AssetAmount:        fundingAmount,
			AssetId:            assetID,
			PeerPubkey:         dave.PubKey[:],
			FeeRateSatPerVbyte: 5,
		},
	)
	require.NoError(t.t, err)

	mineBlocks(t, net, 6, 1)

	chanPoint := &lnrpc.ChannelPoint{
		OutputIndex: uint32(assetFundResp.OutputIndex),
		FundingTxid: &lnrpc.ChannelPoint_FundingTxidStr{
			FundingTxidStr: assetFundResp.Txid,
		},
	}

	assertAssetChan(
		t.t, charlie, dave, fundingAmount, []*taprpc.Asset{cents},
	)
	require.NoError(t.t, net.AssertNodeKnown(charlie, dave))
	require.NoError(t.t, net.AssertNodeKnown(dave, charlie))

	sendAssetKeySendPayment(
		t.t, charlie, dave, rbfTestKeySendAmount, assetID,
		fn.None[int64](),
	)
	sendKeySendPayment(t.t, charlie, dave, rbfTestBtcKeySendAmount)

	// The channel must be free of HTLCs before it can be closed.
	assertNumHtlcs(t.t, charlie, 0)
	assertNumHtlcs(t.t, dave, 0)

	return chanPoint
}

// rbfCloseChannel requests a cooperative close of the channel at the given
// fee rate. With the RBF close flow, a request for a channel that's already
// closing bumps the fee of the close transaction.
func rbfCloseChannel(t *ccHarnessTest, local *itest.IntegratedNode,
	chanPoint *lnrpc.ChannelPoint,
	feeRateSatPerVbyte uint64) lnrpc.Lightning_CloseChannelClient {

	t.t.Helper()

	closeStream, err := local.CloseChannel(
		context.Background(), &lnrpc.CloseChannelRequest{
			ChannelPoint: chanPoint,
			SatPerVbyte:  feeRateSatPerVbyte,
		},
	)
	require.NoError(t.t, err)

	return closeStream
}

// waitForRbfPendingUpdate reads close pending updates from the stream until
// one for a transaction signed by the requested party arrives, and returns
// its txid and fee rate.
func waitForRbfPendingUpdate(t *ccHarnessTest,
	closeStream lnrpc.Lightning_CloseChannelClient,
	wantLocal bool) (*chainhash.Hash, int64) {

	t.t.Helper()

	type pendingUpdate struct {
		txid    *chainhash.Hash
		feeRate int64
	}

	errChan := make(chan error, 1)
	updateChan := make(chan pendingUpdate, 1)
	go func() {
		for {
			closeResp, err := closeStream.Recv()
			if err != nil {
				errChan <- fmt.Errorf("unable to recv from "+
					"close stream: %w", err)

				return
			}

			pending := closeResp.GetClosePending()
			if pending == nil {
				errChan <- fmt.Errorf("expected close pending "+
					"update, instead got %v", closeResp)

				return
			}

			if pending.LocalCloseTx != wantLocal {
				continue
			}

			txid, err := chainhash.NewHash(pending.Txid)
			if err != nil {
				errChan <- err

				return
			}

			updateChan <- pendingUpdate{
				txid:    txid,
				feeRate: pending.FeePerVbyte,
			}

			return
		}
	}()

	select {
	case err := <-errChan:
		require.NoError(t.t, err)

	case update := <-updateChan:
		return update.txid, update.feeRate

	case <-time.After(wait.ChannelCloseTimeout):
		t.t.Fatalf("timeout waiting for close pending update")
	}

	return nil, 0
}

// subscribeSendEvents subscribes to the send events of both nodes, so the
// finalization of the close can be awaited on both sides.
func subscribeSendEvents(ctx context.Context, t *ccHarnessTest,
	charlie, dave *itest.IntegratedNode) (
	taprpc.TaprootAssets_SubscribeSendEventsClient,
	taprpc.TaprootAssets_SubscribeSendEventsClient) {

	t.t.Helper()

	charlieEvents, err := charlie.SubscribeSendEvents(
		ctx, &taprpc.SubscribeSendEventsRequest{},
	)
	require.NoError(t.t, err)

	daveEvents, err := dave.SubscribeSendEvents(
		ctx, &taprpc.SubscribeSendEventsRequest{},
	)
	require.NoError(t.t, err)

	return charlieEvents, daveEvents
}
