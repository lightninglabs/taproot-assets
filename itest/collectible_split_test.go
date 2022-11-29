package itest

import (
	"context"

	"github.com/lightninglabs/taro/tarorpc"
	"github.com/stretchr/testify/require"
)

// testCollectibleSend tests that we can properly send a collectible asset
// with split commitments.
func testCollectibleSend(t *harnessTest) {
	// First, we'll make a collectible with emission enabled.
	rpcAssets := mintAssetsConfirmBatch(
		t, t.tarod, []*tarorpc.MintAssetRequest{issuableAssets[1]},
	)

	groupKey := rpcAssets[0].AssetGroup.TweakedGroupKey
	genInfo := rpcAssets[0].AssetGenesis
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

	// Next, we'll attempt to complete three transfers of the full value of
	// the asset between our main node and Bob.
	var (
		numSends     = 3
		fullAmount   = rpcAssets[0].Amount
		receiverAddr *tarorpc.Addr
		err          error
	)

	for i := 0; i < numSends; i++ {
		// Create an address for the receiver and send the asset. We
		// start with Bob receiving the asset, then sending it back
		// to the main node, and so on.
		if i%2 == 0 {
			receiverAddr, err = secondTarod.NewAddr(
				ctxb, &tarorpc.NewAddrRequest{
					GenesisBootstrapInfo: genBootstrap,
					GroupKey:             groupKey,
					Amt:                  fullAmount,
				},
			)
			require.NoError(t.t, err)

			assertAddrCreated(
				t.t, secondTarod, rpcAssets[0], receiverAddr,
			)
			_ = sendAssetsToAddr(t, t.tarod, receiverAddr)
			confirmSend(
				t, t.tarod, secondTarod, receiverAddr, genInfo,
			)
		} else {
			receiverAddr, err = t.tarod.NewAddr(
				ctxb, &tarorpc.NewAddrRequest{
					GenesisBootstrapInfo: genBootstrap,
					GroupKey:             groupKey,
					Amt:                  fullAmount,
				},
			)
			require.NoError(t.t, err)

			assertAddrCreated(
				t.t, t.tarod, rpcAssets[0], receiverAddr,
			)
			_ = sendAssetsToAddr(t, secondTarod, receiverAddr)
			confirmSend(
				t, secondTarod, t.tarod, receiverAddr, genInfo,
			)
		}
	}

	// Check the final state of both nodes. The main node should list 2
	// zero-value transfers. and Bob should have 1. The main node should
	// show a balance of zero, and Bob should hold the total asset supply.
	assertTransfers(t.t, t.tarod, []int64{0, 0})
	assertBalance(t.t, t.tarod, genInfo.AssetId, int64(0))

	assertTransfers(t.t, secondTarod, []int64{0})
	assertBalance(t.t, secondTarod, genInfo.AssetId, int64(fullAmount))
}
