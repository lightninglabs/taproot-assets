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
	currentUnits := simpleAssets[0].Amount

	for i := 0; i < numSends; i++ {
		bobAddr, err := secondTarod.NewAddr(ctxb, &tarorpc.NewAddrRequest{
			GenesisBootstrapInfo: genBootstrap,
			Amt:                  numUnits,
		})
		require.NoError(t.t, err)

		// Deduct what we sent from the expected current number of
		// units.
		currentUnits -= numUnits

		assertAddrCreated(t.t, secondTarod, rpcAssets[0], bobAddr)

		sendResp := sendAssetsToAddr(t, t.tarod, bobAddr)

		// Check that we now have two new outputs, and that they differ
		// in outpoints and scripts.
		outputs := sendResp.TaroTransfer.NewOutputs
		require.Len(t.t, outputs, 2)

		outpoints := make(map[string]struct{})
		scripts := make(map[string]struct{})
		for _, o := range outputs {
			_, ok := outpoints[o.AnchorPoint]
			require.False(t.t, ok)

			_, ok = scripts[string(o.ScriptKey)]
			require.False(t.t, ok)

			outpoints[o.AnchorPoint] = struct{}{}
			scripts[string(o.ScriptKey)] = struct{}{}
		}

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

			// Assert the new outpoint, script and amount is in the
			// list.
			transfer := resp.Transfers[i]
			require.Contains(t.t, outpoints, transfer.NewAnchorPoint)

			delta := transfer.AssetSpendDeltas[0]
			require.Contains(t.t, scripts, string(delta.NewScriptKey))
			require.Equal(t.t, currentUnits, delta.NewAmt)

			sameAssetID := func(xfer *tarorpc.AssetTransfer) bool {
				return bytes.Equal(xfer.AssetSpendDeltas[0].AssetId,
					rpcAssets[0].AssetGenesis.AssetId)
			}

			// Check asset ID is unchanged.
			return chanutils.All(resp.Transfers, sameAssetID)
		}, defaultTimeout/2)
		require.NoError(t.t, err)
	}
}
