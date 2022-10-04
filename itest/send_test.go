package itest

import (
	"bytes"
	"context"

	"github.com/lightninglabs/taro/chanutils"
	"github.com/lightninglabs/taro/tarorpc"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/stretchr/testify/require"
)

// testBasicSend tests that we can properly send assets back and forth between
// nodes.
func testBasicSend(t *harnessTest) {
	// First, we'll make an normal assets with enough units to allow us to
	// send it around a few times.
	rpcAssets := mintAssetsConfirmBatch(
		t, t.tarod, []*tarorpc.MintAssetRequest{simpleAssets[0]},
	)

	genBootstrap := rpcAssets[0].AssetGenesis.GenesisBootstrapInfo

	ctxb := context.Background()

	// Now that we have the asset created, we'll make a new node that'll
	// serve as the node which'll receive the assets.
	secondTarod := setupTarodHarness(
		t.t, t, t.lndHarness.BackendCfg, t.lndHarness.Bob, t.universeServer,
	)
	defer func() {
		require.NoError(t.t, secondTarod.stop(true))
	}()

	// Next, we'll attempt to complete two transfers with distinct
	// addresses from our main node to Bob.
	const (
		numUnits = 10
		numSends = 2
	)
	for i := 0; i < numSends; i++ {
		bobAddr, err := secondTarod.NewAddr(ctxb, &tarorpc.NewAddrRequest{
			GenesisBootstrapInfo: genBootstrap,
			Amt:                  numUnits,
		})
		require.NoError(t.t, err)

		assertAddrCreated(t.t, secondTarod, rpcAssets[0], bobAddr)

		sendResp := sendAssetsToAddr(t, bobAddr)
		sendRespJSON, err := formatProtoJSON(sendResp)
		require.NoError(t.t, err)
		t.Logf("Got response from sending assets: %v", sendRespJSON)

		// Mine a block to force the send we created above to confirm.
		_ = mineBlocks(t, t.lndHarness, 1, len(rpcAssets))

		// Confirm that we can externally view the transfer.
		err = wait.Predicate(func() bool {
			resp, err := t.tarod.ListTransfers(
				ctxb, &tarorpc.ListTransfersRequest{},
			)
			require.NoError(t.t, err)
			require.Len(t.t, resp.Transfers, i+1)

			sameAssetID := func(xfer *tarorpc.AssetTransfer) bool {
				return bytes.Equal(xfer.AssetSpendDeltas[0].AssetId,
					rpcAssets[0].AssetGenesis.AssetId)
			}

			return chanutils.All(resp.Transfers, sameAssetID)
		}, defaultTimeout/2)
		require.NoError(t.t, err)
	}
}
