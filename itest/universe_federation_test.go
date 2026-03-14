package itest

import (
	"context"
	"time"

	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	unirpc "github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/stretchr/testify/require"
)

// testMintProofRepeatFedSyncAttempt tests that the minting node will retry
// pushing the minting proofs to the federation server peer node, if the peer
// node is offline at the time of the initial sync attempt.
func testMintProofRepeatFedSyncAttempt(t *harnessTest) {
	// Create a new minting node, without hooking it up to any existing
	// Universe server. We will also set the sync ticker to 2 second, so
	// that we can test that the proof push sync is retried and eventually
	// succeeds after the fed server peer node reappears online.
	syncTickerInterval := 2 * time.Second
	bobLnd := t.lndHarness.NewNodeWithCoins("Bob", nil)
	mintingNode := setupTapdHarness(
		t.t, t, bobLnd, nil, func(params *tapdHarnessParams) {
			params.fedSyncTickerInterval = &syncTickerInterval
			params.noDefaultUniverseSync = true
		},
	)
	defer func() {
		require.NoError(t.t, mintingNode.stop(!*noDelete))
	}()

	// We'll use the main node as our federation universe server
	// counterparty.
	fedServerNode := t.tapd

	// Keep a reference to the fed server node RPC host address, so that we
	// can assert that it has not changed after the restart. This is
	// important, because the minting node will be retrying the proof push
	// to this address.
	fedServerNodeRpcHost := fedServerNode.rpcHost()

	// Register the fedServerNode as a federation universe server with the
	// minting node.
	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	_, err := mintingNode.AddFederationServer(
		ctxt, &unirpc.AddFederationServerRequest{
			Servers: []*unirpc.UniverseFederationServer{
				{
					Host: fedServerNodeRpcHost,
				},
			},
		},
	)
	require.NoError(t.t, err)

	// Assert that the fed server node has not seen any asset proofs.
	AssertUniverseStats(t.t, fedServerNode, 0, 0, 0)

	// Stop the federation server peer node, so that it does not receive the
	// newly minted asset proofs immediately upon minting.
	t.Logf("Stopping fed server tapd node")
	require.NoError(t.t, fedServerNode.stop(false))

	// Now that federation peer node is inactive, we'll mint some assets.
	t.Logf("Minting assets on minting node")
	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, mintingNode,
		[]*mintrpc.MintAssetRequest{
			simpleAssets[0], issuableAssets[0],
		},
	)
	require.Len(t.t, rpcAssets, 2)

	t.lndHarness.MineBlocks(7)

	// Wait for the minting node to attempt (and fail) to push the minting
	// proofs to the fed peer node. We wait some multiple of the sync ticker
	// interval to ensure that the minting node has had time to retry the
	// proof push sync.
	time.Sleep(syncTickerInterval * 2)

	// Start the federation server peer node. The federation envoy component
	// of our minting node should currently be retrying the proof push sync
	// with the federation peer at each tick.
	t.Logf("Start (previously stopped) fed server tapd node")
	err = fedServerNode.start(false)
	require.NoError(t.t, err)

	// Ensure that the federation server node RPC host address has not
	// changed after the restart. If it has, then the minting node will be
	// retrying the proof push to the wrong address.
	require.Equal(t.t, fedServerNodeRpcHost, fedServerNode.rpcHost())

	t.Logf("Assert that fed peer node has seen the asset minting proofs")
	AssertUniverseStats(t.t, fedServerNode, 2, 2, 1)
}

// testDeleteUniverseAfterFedSync tests that DeleteAssetRoot succeeds
// after federation sync has created proof sync log entries. Pre-CASCADE
// fix this would fail with an FK violation.
func testDeleteUniverseAfterFedSync(t *harnessTest) {
	ctx := context.Background()
	miner := t.lndHarness.Miner().Client

	// Mint a simple asset on Alice (the main harness node).
	rpcAssets := MintAssetsConfirmBatch(
		t.t, miner, t.tapd, simpleAssets[:1],
	)
	require.Len(t.t, rpcAssets, 1)
	assetID := rpcAssets[0].AssetGenesis.AssetId

	// Create Bob without default universe sync.
	bobLnd := t.lndHarness.NewNodeWithCoins("Bob", nil)
	bob := setupTapdHarness(
		t.t, t, bobLnd, t.universeServer,
		func(p *tapdHarnessParams) {
			p.noDefaultUniverseSync = true
		},
	)
	defer func() {
		require.NoError(t.t, bob.stop(!*noDelete))
	}()

	// Add Alice as Bob's federation server.
	_, err := bob.AddFederationServer(
		ctx, &unirpc.AddFederationServerRequest{
			Servers: []*unirpc.UniverseFederationServer{
				{
					Host: t.tapd.rpcHost(),
				},
			},
		},
	)
	require.NoError(t.t, err)

	// Wait for Bob to sync from Alice. This creates
	// federation_proof_sync_log entries on Bob.
	require.Eventually(t.t, func() bool {
		return AssertUniverseStateEqual(t.t, bob, t.tapd)
	}, defaultWaitTimeout, wait.PollInterval)

	// Bob should have 1 proof, 1 asset, 0 groups.
	AssertUniverseStats(t.t, bob, 1, 1, 0)

	// Delete the universe root on Bob. Pre-CASCADE fix, this
	// would fail with an FK violation from sync log entries.
	_, err = bob.DeleteAssetRoot(ctx, &unirpc.DeleteRootQuery{
		Id: &unirpc.ID{
			Id: &unirpc.ID_AssetId{
				AssetId: assetID,
			},
			ProofType: unirpc.ProofType_PROOF_TYPE_ISSUANCE,
		},
	})
	require.NoError(t.t, err)

	// Verify the root is gone.
	roots, err := bob.AssetRoots(
		ctx, &unirpc.AssetRootRequest{},
	)
	require.NoError(t.t, err)
	require.Len(t.t, roots.UniverseRoots, 0)

	// Stats should be zeroed out.
	AssertUniverseStats(t.t, bob, 0, 0, 0)
}
