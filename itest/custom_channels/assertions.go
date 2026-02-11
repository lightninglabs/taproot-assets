package custom_channels

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/wire"
	"github.com/go-errors/errors"
	"github.com/lightninglabs/taproot-assets/itest"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"github.com/lightningnetwork/lnd/lntest"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

const (
	slowMineDelay = 20 * time.Millisecond
)

// ccHarnessTest wraps a testing.T providing enhanced error detection with
// stack traces, similar to LiT's harnessTest. It provides the test context for
// custom channel integration tests.
type ccHarnessTest struct {
	t *testing.T

	// testCase is the currently executing test case.
	testCase *ccTestCase

	// lndHarness is the integrated network harness.
	lndHarness *itest.IntegratedNetworkHarness
}

// Logf logs a formatted message.
func (h *ccHarnessTest) Logf(format string, args ...interface{}) {
	h.t.Logf(format, args...)
}

// Log logs a message.
func (h *ccHarnessTest) Log(args ...interface{}) {
	h.t.Log(args...)
}

// Fatalf causes the current active test case to fail with a fatal error. All
// integration tests should mark test failures solely with this method due to
// the error stack traces it produces.
func (h *ccHarnessTest) Fatalf(format string, a ...interface{}) {
	stacktrace := errors.Wrap(fmt.Sprintf(format, a...), 1).ErrorStack()

	if h.testCase != nil {
		h.t.Fatalf("Failed: (%v): exited with error: \n"+
			"%v", h.testCase.name, stacktrace)
	} else {
		h.t.Fatalf("Error outside of test: %v", stacktrace)
	}
}

// ccTestCase describes a single custom channel test.
type ccTestCase struct {
	name string
	test func(ctx context.Context, net *itest.IntegratedNetworkHarness,
		t *ccHarnessTest)
}

// openChannelAndAssert opens a channel between alice and bob, mines blocks for
// confirmation, and asserts both nodes see the channel.
func openChannelAndAssert(t *ccHarnessTest, net *itest.IntegratedNetworkHarness,
	alice, bob *itest.IntegratedNode,
	p lntest.OpenChannelParams) *lnrpc.ChannelPoint {

	t.t.Helper()

	chanOpenUpdate := openChannelStream(t, net, alice, bob, p)

	// Mine 6 blocks, then wait for the channel open notification. We mine
	// 6 blocks so that in the case that the channel is public, it is
	// announced to the network.
	block := mineBlocks(t, net, 6, 1)[0]

	fundingChanPoint, err := net.WaitForChannelOpen(chanOpenUpdate)
	require.NoError(t.t, err, "error while waiting for channel open")

	fundingTxID, err := lnrpc.GetChanPointFundingTxid(fundingChanPoint)
	require.NoError(t.t, err, "unable to get txid")

	assertTxInBlock(t, block, fundingTxID)

	// The channel should be listed in the peer information returned by
	// both peers.
	chanPoint := wire.OutPoint{
		Hash:  *fundingTxID,
		Index: fundingChanPoint.OutputIndex,
	}
	require.NoError(
		t.t, net.AssertChannelExists(alice, &chanPoint),
		"unable to assert channel existence",
	)
	require.NoError(
		t.t, net.AssertChannelExists(bob, &chanPoint),
		"unable to assert channel existence",
	)

	return fundingChanPoint
}

// openChannelStream opens a channel and returns the stream for receiving
// channel open events.
func openChannelStream(t *ccHarnessTest, net *itest.IntegratedNetworkHarness,
	alice, bob *itest.IntegratedNode,
	p lntest.OpenChannelParams) lnrpc.Lightning_OpenChannelClient {

	t.t.Helper()

	var chanOpenUpdate lnrpc.Lightning_OpenChannelClient
	err := wait.NoError(func() error {
		var err error
		chanOpenUpdate, err = net.OpenChannel(alice, bob, p)
		return err
	}, wait.DefaultTimeout)
	require.NoError(t.t, err, "unable to open channel")

	return chanOpenUpdate
}

// closeChannelAndAssert closes a channel and asserts the close transaction is
// mined. Returns the closing transaction hash.
func closeChannelAndAssert(t *ccHarnessTest,
	net *itest.IntegratedNetworkHarness,
	node *itest.IntegratedNode,
	fundingChanPoint *lnrpc.ChannelPoint,
	force bool) *chainhash.Hash {

	ctx, cancel := context.WithTimeout(
		context.Background(), wait.DefaultTimeout,
	)
	defer cancel()

	closeUpdates, _, err := net.CloseChannel(
		node, fundingChanPoint, force,
	)
	require.NoError(t.t, err, "unable to close channel")

	return assertChannelClosed(
		ctx, t, net, node, fundingChanPoint, closeUpdates,
	)
}

// assertChannelClosed asserts that the channel is properly cleaned up after
// initiating a cooperative or local close.
func assertChannelClosed(ctx context.Context, t *ccHarnessTest,
	net *itest.IntegratedNetworkHarness, node *itest.IntegratedNode,
	fundingChanPoint *lnrpc.ChannelPoint,
	closeUpdates lnrpc.Lightning_CloseChannelClient) *chainhash.Hash {

	txid, err := lnrpc.GetChanPointFundingTxid(fundingChanPoint)
	require.NoError(t.t, err, "unable to get txid")
	chanPointStr := fmt.Sprintf(
		"%v:%v", txid, fundingChanPoint.OutputIndex,
	)

	// If the channel appears in list channels, ensure that its state
	// contains ChanStatusCoopBroadcasted.
	listChansResp, err := node.ListChannels(
		ctx, &lnrpc.ListChannelsRequest{},
	)
	require.NoError(t.t, err, "unable to query for list channels")

	for _, channel := range listChansResp.Channels {
		if channel.ChannelPoint != chanPointStr {
			continue
		}

		require.Contains(
			t.t, channel.ChanStatusFlags,
			channeldb.ChanStatusCoopBroadcasted.String(),
			"channel not coop broadcasted",
		)
	}

	// At this point, the channel should now be marked as being in the
	// state of "waiting close".
	pendingChanResp, err := node.PendingChannels(
		ctx, &lnrpc.PendingChannelsRequest{},
	)
	require.NoError(t.t, err, "unable to query for pending channels")

	var found bool
	for _, pendingClose := range pendingChanResp.WaitingCloseChannels {
		if pendingClose.Channel.ChannelPoint == chanPointStr {
			found = true
			break
		}
	}
	require.True(t.t, found, "channel not marked as waiting close")

	// Mine one block for the close tx, then wait for the close update.
	block := mineBlocks(t, net, 1, 1)[0]

	closingUpdate, err := net.WaitForChannelClose(closeUpdates)
	require.NoError(t.t, err, "error while waiting for channel close")

	closingTxid, err := chainhash.NewHash(closingUpdate.ClosingTxid)
	require.NoError(t.t, err)
	assertTxInBlock(t, block, closingTxid)

	// The transaction should no longer be in the waiting close state.
	err = wait.Predicate(func() bool {
		resp, err := node.PendingChannels(
			ctx, &lnrpc.PendingChannelsRequest{},
		)
		if err != nil {
			return false
		}

		for _, pendingClose := range resp.WaitingCloseChannels {
			if pendingClose.Channel.ChannelPoint == chanPointStr {
				return false
			}
		}

		return true
	}, wait.DefaultTimeout)
	require.NoError(
		t.t, err, "closing transaction not marked as fully closed",
	)

	return closingTxid
}

// ccShutdownAndAssert shuts down the given integrated node and asserts no
// errors occur.
func ccShutdownAndAssert(net *itest.IntegratedNetworkHarness, t *ccHarnessTest,
	node *itest.IntegratedNode) {

	err := wait.NoError(func() error {
		node.Stop()
		return nil
	}, wait.DefaultTimeout)
	require.NoErrorf(t.t, err, "unable to shutdown %v", node.Cfg.Name)
}

// assertSweepExists asserts that a pending sweep with the given witness type
// exists for the node.
func assertSweepExists(t *testing.T, node *itest.IntegratedNode,
	witnessType walletrpc.WitnessType) {

	ctx := context.Background()
	err := wait.NoError(func() error {
		pendingSweeps, err := node.WalletKitClient.PendingSweeps(
			ctx, &walletrpc.PendingSweepsRequest{},
		)
		if err != nil {
			return err
		}

		for _, sweep := range pendingSweeps.PendingSweeps {
			if sweep.WitnessType == witnessType {
				return nil
			}
		}

		return fmt.Errorf("failed to find sweep: %v",
			ccToProtoJSON(t, pendingSweeps))
	}, wait.DefaultTimeout)
	require.NoError(t, err)
}

// ccToProtoJSON marshals a protobuf message to JSON for debugging output.
func ccToProtoJSON(t *testing.T, resp proto.Message) string {
	jsonBytes, err := taprpc.ProtoJSONMarshalOpts.Marshal(resp)
	require.NoError(t, err)

	return string(jsonBytes)
}

// mineBlocks mines 'num' blocks with a delay between each. numTxs is the
// expected number of transactions in the first mined block.
func mineBlocks(t *ccHarnessTest, net *itest.IntegratedNetworkHarness,
	num uint32, numTxs int) []*wire.MsgBlock {

	return mineBlocksSlow(t, net, num, numTxs)
}

// mineBlocksSlow mines blocks one at a time with a delay between each to give
// network participants time to catch up.
func mineBlocksSlow(t *ccHarnessTest, net *itest.IntegratedNetworkHarness,
	num uint32, numTxs int) []*wire.MsgBlock {

	t.t.Helper()

	// If we expect transactions in the first block, wait for them in the
	// mempool.
	var txids []*chainhash.Hash
	var err error
	if numTxs > 0 {
		txids, err = waitForNTxsInMempool(
			net.Miner.Client, numTxs,
			wait.MinerMempoolTimeout,
		)
		require.NoError(t.t, err, "unable to find txns in mempool")
	}

	blocks := make([]*wire.MsgBlock, num)
	blockHashes := make([]*chainhash.Hash, 0, num)

	for i := uint32(0); i < num; i++ {
		generatedHashes, err := net.Miner.Client.Generate(1)
		require.NoError(t.t, err, "generate blocks")
		blockHashes = append(blockHashes, generatedHashes...)

		time.Sleep(slowMineDelay)
	}

	for i, blockHash := range blockHashes {
		block, err := net.Miner.Client.GetBlock(blockHash)
		require.NoError(t.t, err, "get blocks")

		blocks[i] = block
	}

	// Assert that all the expected transactions were included in the first
	// block.
	for _, txid := range txids {
		assertTxInBlock(t, blocks[0], txid)
	}

	return blocks
}

// waitForNTxsInMempool polls until finding the desired number of transactions
// in the miner's mempool.
func waitForNTxsInMempool(minerClient *rpcclient.Client, n int,
	timeout time.Duration) ([]*chainhash.Hash, error) {

	breakTimeout := time.After(timeout)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	var err error
	var mempool []*chainhash.Hash
	for {
		select {
		case <-breakTimeout:
			return nil, fmt.Errorf("wanted %v, found %v txs "+
				"in mempool: %v", n, len(mempool), mempool)
		case <-ticker.C:
			mempool, err = minerClient.GetRawMempool()
			if err != nil {
				return nil, err
			}

			if len(mempool) == n {
				return mempool, nil
			}
		}
	}
}

// assertTxInBlock asserts that a transaction with the given hash is included
// in the block.
func assertTxInBlock(t *ccHarnessTest, block *wire.MsgBlock,
	txid *chainhash.Hash) {

	for _, tx := range block.Transactions {
		sha := tx.TxHash()
		if bytes.Equal(txid[:], sha[:]) {
			return
		}
	}

	t.Fatalf("tx was not included in block")
}
