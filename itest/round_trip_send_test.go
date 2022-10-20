package itest

import (
	"context"

	"github.com/lightninglabs/taro/tarorpc"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/stretchr/testify/require"
)

// testRoundTripSend tests that we can properly send the full value of a
// normal asset.
func testRoundTripSend(t *harnessTest) {
	// First, we'll make an normal assets with enough units to allow us to
	// send it around a few times.
	rpcAssets := mintAssetsConfirmBatch(
		t, t.tarod, []*tarorpc.MintAssetRequest{simpleAssets[0]},
	)

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

	// We'll send half of the minted units to Bob, and then have Bob return
	// half of the units he received.
	fullAmt := rpcAssets[0].Amount
	bobAmt := fullAmt / 2
	aliceAmt := bobAmt / 2

	// First, we'll send half of the units to Bob.
	bobAddr, err := secondTarod.NewAddr(ctxb, &tarorpc.NewAddrRequest{
		GenesisBootstrapInfo: genBootstrap,
		Amt:                  bobAmt,
	})
	require.NoError(t.t, err)

	assertAddrCreated(t.t, secondTarod, rpcAssets[0], bobAddr)
	sendResp := sendAssetsToAddr(t, t.tarod, bobAddr)
	sendRespJSON, err := formatProtoJSON(sendResp)
	require.NoError(t.t, err)
	t.Logf("Got response from sending assets: %v", sendRespJSON)

	confirmSend(t, t.tarod, secondTarod, bobAddr, genInfo)

	// Now, Alice will request half of the assets she sent to Bob.
	aliceAddr, err := t.tarod.NewAddr(ctxb, &tarorpc.NewAddrRequest{
		GenesisBootstrapInfo: genBootstrap,
		Amt:                  aliceAmt,
	})
	require.NoError(t.t, err)

	assertAddrCreated(t.t, t.tarod, rpcAssets[0], aliceAddr)
	sendResp = sendAssetsToAddr(t, secondTarod, aliceAddr)
	sendRespJSON, err = formatProtoJSON(sendResp)
	require.NoError(t.t, err)
	t.Logf("Got response from sending assets: %v", sendRespJSON)

	confirmSend(t, secondTarod, t.tarod, aliceAddr, genInfo)

	// Check the final state of both nodes. Each node should list
	// one transfer, and Alice should have 3/4 of the total units.
	err = wait.NoError(func() error {
		assertTransfers(t.t, t.tarod, []int64{bobAmt})
		assertBalance(t.t, t.tarod, genInfo.AssetId, bobAmt+aliceAmt)

		assertTransfers(t.t, secondTarod, []int64{aliceAmt})
		assertBalance(t.t, secondTarod, genInfo.AssetId, aliceAmt)

		return nil
	}, defaultTimeout/2)
	require.NoError(t.t, err)
}

// confirmSend mines a new block and passes proofs for the asset transfer
// between the sender and receiver,
func confirmSend(t *harnessTest, src, dst *tarodHarness, rpcAddr *tarorpc.Addr,
	genInfo *tarorpc.GenesisInfo) {

	_ = mineBlocks(t, t.lndHarness, 1, 1)
	_ = sendProof(t, src, dst, rpcAddr, genInfo)
}
