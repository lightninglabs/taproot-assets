package loadtest

import (
	"context"
	"fmt"
	prand "math/rand"
	"testing"
	"time"

	"github.com/btcsuite/btcd/rpcclient"
	"github.com/lightninglabs/taproot-assets/itest"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/stretchr/testify/require"
)

var (
	statusDetected  = taprpc.AddrEventStatus_ADDR_EVENT_STATUS_TRANSACTION_DETECTED
	statusCompleted = taprpc.AddrEventStatus_ADDR_EVENT_STATUS_COMPLETED
)

// sendTest checks that we are able to send assets between the two nodes.
func sendTest(t *testing.T, ctx context.Context, cfg *Config) {
	// Start by initializing all our client connections.
	alice, bob, bitcoinClient := initClients(t, ctx, cfg)

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, cfg.TestTimeout)
	defer cancel()

	t.Logf("Running send test, sending %d asset(s) of type %v %d times",
		cfg.NumAssets, cfg.SendType, cfg.NumSends)
	for i := 1; i <= cfg.NumSends; i++ {
		send, receive, ok := pickSendNode(
			t, ctx, cfg.NumAssets, cfg.SendType, alice, bob,
		)
		if !ok {
			t.Fatalf("Aborting send test at attempt %d of %d as "+
				"no node has enough balance to send %d "+
				"assets of type %v", i, cfg.NumSends,
				cfg.NumAssets, cfg.SendType)
			return
		}

		sendAssets(
			t, ctxt, cfg.NumAssets, cfg.SendType, send, receive,
			bitcoinClient, cfg.TestTimeout,
		)

		t.Logf("Finished %d of %d send operations", i, cfg.NumSends)
	}
}

// sendAsset sends the given number of assets of the given type from the given
// node to the other node.
func sendAssets(t *testing.T, ctx context.Context, numAssets uint64,
	assetType taprpc.AssetType, send, receive *rpcClient,
	bitcoinClient *rpcclient.Client, timeout time.Duration) {

	// Query the asset we'll be sending, so we can assert some things about
	// it later.
	sendAsset := send.assetIDWithBalance(t, ctx, numAssets, assetType)
	t.Logf("Sending %d asset(s) with ID %x from %v to %v", numAssets,
		sendAsset.AssetGenesis.AssetId, send.cfg.Name, receive.cfg.Name)

	// Let's create an address on the receiving node and make sure it's
	// created correctly.
	addr, err := receive.NewAddr(ctx, &taprpc.NewAddrRequest{
		AssetId: sendAsset.AssetGenesis.AssetId,
		Amt:     numAssets,
		ProofCourierAddr: fmt.Sprintf(
			"%s://%s:%d", proof.UniverseRpcCourierType,
			send.cfg.Host, send.cfg.Port,
		),
	})
	require.NoError(t, err)
	itest.AssertAddrCreated(t, receive, sendAsset, addr)

	// Before we send the asset, we record the existing transfers on the
	// sending node, so we can easily select the new transfer once it
	// appears.
	transfersBefore := send.listTransfersSince(t, ctx, nil)

	// Initiate the send now.
	_, err = send.SendAsset(ctx, &taprpc.SendAssetRequest{
		TapAddrs: []string{addr.Encoded},
	})
	require.NoError(t, err)

	// Wait for the transfer to appear on the sending node.
	require.Eventually(t, func() bool {
		newTransfers := send.listTransfersSince(t, ctx, transfersBefore)
		return len(newTransfers) == 1
	}, timeout, wait.PollInterval)

	// And for it to be detected on the receiving node.
	itest.AssertAddrEventCustomTimeout(
		t, receive, addr, 1, statusDetected, timeout,
	)

	// Mine a block to confirm the transfer.
	itest.MineBlocks(t, bitcoinClient, 1, 1)

	// Now the transfer should go to completed eventually.
	itest.AssertAddrEventCustomTimeout(
		t, receive, addr, 1, statusCompleted, timeout,
	)
}

// pickSendNode picks a node at random, checks whether it has enough assets of
// the given type, and returns it. The second return value is the other node,
// which will be the receiving node. The boolean argument returns true if there
// is a node with sufficient balance. If that is false, the test should be
// skipped.
func pickSendNode(t *testing.T, ctx context.Context, minBalance uint64,
	assetType taprpc.AssetType, a, b *rpcClient) (*rpcClient, *rpcClient,
	bool) {

	send, receive := a, b
	if prand.Intn(1) == 0 {
		send, receive = b, a
	}

	// Check if the randomly picked send node has enough balance.
	if send.assetIDWithBalance(t, ctx, minBalance, assetType) != nil {
		return send, receive, true
	}

	// If we get here, the send node doesn't have enough balance. We'll try
	// the other one.
	send, receive = receive, send
	if send.assetIDWithBalance(t, ctx, minBalance, assetType) != nil {
		return send, receive, true
	}

	// None of the nodes have enough balance. We can't run the send test
	// currently.
	return nil, nil, false
}
