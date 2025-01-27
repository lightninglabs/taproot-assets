package loadtest

import (
	"context"
	"fmt"
	prand "math/rand"
	"math/rand/v2"
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

	sendType := stringToAssetType(cfg.SendAssetType)

	t.Logf("Running send test, sending %d asset(s) of type %v %d times",
		cfg.NumAssets, sendType, cfg.NumSends)
	for i := 1; i <= cfg.NumSends; i++ {
		send, receive, ok := pickSendNode(
			t, ctx, cfg.NumAssets, sendType, alice, bob,
		)
		if !ok {
			t.Fatalf("Aborting send test at attempt %d of %d as "+
				"no node has enough balance to send %d "+
				"assets of type %v", i, cfg.NumSends,
				cfg.NumAssets, sendType)
			return
		}

		sendAssets(
			t, ctxt, cfg.NumAssets, sendType, send, receive,
			bitcoinClient, cfg.TestTimeout,
		)

		t.Logf("Finished %d of %d send operations", i, cfg.NumSends)
	}
}

// sendTestV2 checks that we are able to send assets between the two nodes. It
// is a more performant and lightweight version of sendTest, as it uses less
// assertions and RPC calls.
func sendTestV2(t *testing.T, ctx context.Context, cfg *Config) {
	// Start by initializing all our client connections.
	alice, bob, bitcoinClient := initClients(t, ctx, cfg)

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, cfg.TestTimeout)
	defer cancel()

	sendType := stringToAssetType(cfg.SendAssetType)

	// Alice is set to be the minter in mintV2, so we use Alice's universe.
	uniHost := fmt.Sprintf("%s:%d", alice.cfg.Host, alice.cfg.Port)

	// Let's make sure Bob is aware of all the assets that Alice may have
	// minted.
	itest.SyncUniverses(
		ctx, t, bob, alice, uniHost, cfg.TestTimeout,
		itest.WithSyncMode(itest.SyncModeFull),
	)

	// We now retrieve Alice and Bob's balances just once, and will re-use
	// them in future function calls. Any update to the balances will be
	// directly applied to these response objects, to skip future calls to
	// ListBalances.
	resAlice, err := alice.ListBalances(ctx, &taprpc.ListBalancesRequest{
		GroupBy: &taprpc.ListBalancesRequest_AssetId{
			AssetId: true,
		},
	})
	require.NoError(t, err)

	resBob, err := bob.ListBalances(ctx, &taprpc.ListBalancesRequest{
		GroupBy: &taprpc.ListBalancesRequest_AssetId{
			AssetId: true,
		},
	})
	require.NoError(t, err)

	for i := 1; i <= cfg.NumSends; i++ {
		var (
			sender, receiver *rpcClient
			senderAssets     map[string]*taprpc.AssetBalance
		)

		// Assets may be sent in both directions, so we make a random
		// draw to conclude who the sender is.
		draw := rand.IntN(2)

		switch draw {
		case 0:
			sender = alice
			senderAssets = resAlice.AssetBalances
			receiver = bob

		case 1:
			sender = bob
			senderAssets = resBob.AssetBalances
			receiver = alice
		}

		sendAssetV2(
			t, ctxt, cfg.NumAssets, sendType, senderAssets,
			sender, receiver, bitcoinClient, cfg.TestTimeout,
		)
	}
}

// sendAssetV2 sends a certain amount of assets of a specific type from a sender
// to a receiver. It will scan the balance of the sender and find a suitable
// asset to carry out the send, then will dispatch the send and assert its
// completion.
func sendAssetV2(t *testing.T, ctx context.Context, numAssets uint64,
	assetType taprpc.AssetType, assets map[string]*taprpc.AssetBalance,
	sender, receiver *rpcClient, bitcoinClient *rpcclient.Client,
	timeout time.Duration) {

	// Look over the sender's balances to see if any asset balance qualifies
	// for this send.
	var (
		assetID []byte
		balance *taprpc.AssetBalance
	)
	for _, v := range assets {
		if v.Balance >= numAssets &&
			v.AssetGenesis.AssetType == assetType {

			assetID = v.AssetGenesis.AssetId
			balance = v

			break
		}
	}

	// No balance satisfies the amount of this send, we can skip this round.
	if assetID == nil {
		t.Logf("%s could not send %v assets, no available balance",
			sender.cfg.Name, numAssets)

		return
	}

	t.Logf("%s sending %v assets to %s", sender.cfg.Name, numAssets,
		receiver.cfg.Name)

	// Receiver creates the address to receive the assets.
	addr, err := receiver.NewAddr(ctx, &taprpc.NewAddrRequest{
		AssetId: assetID,
		Amt:     numAssets,
		ProofCourierAddr: fmt.Sprintf(
			"%s://%s:%d", proof.UniverseRpcCourierType,
			sender.cfg.Host, sender.cfg.Port,
		),
	})
	require.NoError(t, err)

	t.Logf("%s created address %v", receiver.cfg.Name, addr.String())

	// Sender initiates the send.
	_, err = sender.SendAsset(ctx, &taprpc.SendAssetRequest{
		TapAddrs: []string{addr.Encoded},
	})
	require.NoError(t, err)
	t.Logf("%s sent assets to address %v", sender.cfg.Name, addr.String())

	// We assert the receiver detects the spend.
	itest.AssertAddrEventCustomTimeout(
		t, receiver, addr, 1, statusDetected, timeout,
	)
	t.Logf("%s detected send", receiver.cfg.Name)

	// Mine a block to confirm the transfer.
	itest.MineBlocks(t, bitcoinClient, 1, 0)
	t.Log("Mined 1 block")

	// Assert that the transfer is now completed
	itest.AssertAddrEventCustomTimeout(
		t, receiver, addr, 1, statusCompleted, timeout,
	)
	t.Logf("%s completed send of %v assets", sender.cfg.Name, numAssets)

	// If everything completed correctly, subtract the asset amount from the
	// sender's asset balance.
	balance.Balance -= numAssets
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
