package itest

import (
	"context"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	unirpc "github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	"github.com/lightningnetwork/lnd/lntest"
	"github.com/lightningnetwork/lnd/lntest/miner"
	"github.com/stretchr/testify/require"
)

// testReOrgMint tests that when a re-org occurs, minted asset proofs are
// updated accordingly.
func testReOrgMint(t *harnessTest) {
	// We create a second node for the second tapd instance. But because
	// NewNodeWithCoins mines a block, we need to do it before we do
	// anything else.
	lndBob := t.lndHarness.NewNodeWithCoins("Bob", nil)

	// First, we'll mint a few assets but don't confirm the batch TX.
	mintRequests := []*mintrpc.MintAssetRequest{
		issuableAssets[0], issuableAssets[1],
	}
	lndMiner := t.lndHarness.Miner()
	mintTXID, batchKey := MintAssetUnconfirmed(
		t.t, lndMiner.Client, t.tapd, mintRequests,
	)

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// Before we mine a block to confirm the mint TX, we create a temporary
	// miner.
	tempMiner := spawnTempMiner(t.t, t, ctxt)

	// And now we mine a block to confirm the assets.
	initialBlock := MineBlocks(t.t, lndMiner.Client, 1, 1)[0]
	initialBlockHash := initialBlock.BlockHash()
	WaitForBatchState(
		t.t, ctxt, t.tapd, defaultWaitTimeout, batchKey,
		mintrpc.BatchState_BATCH_STATE_FINALIZED,
	)

	// Make sure the original mint TX was mined in the first block.
	lndMiner.AssertTxInBlock(initialBlock, mintTXID)
	t.Logf("Mint TX %v mined in block %v", mintTXID, initialBlockHash)

	assetList := AssertAssetsMinted(
		t.t, t.tapd, mintRequests, mintTXID, initialBlockHash,
	)

	// Now that we have the asset created, we'll make a new node that'll
	// serve as the node which'll receive the assets. The existing tapd
	// node will be used to synchronize universe state.
	secondTapd := setupTapdHarness(t.t, t, lndBob, t.universeServer)
	defer func() {
		require.NoError(t.t, secondTapd.stop(!*noDelete))
	}()

	// We now generate the re-org.
	generateReOrg(t.t, t.lndHarness, tempMiner, 3, 2)

	// This should have caused a reorg, and Alice should sync to the longer
	// chain, where the funding transaction is not confirmed.
	_, tempMinerHeight, err := tempMiner.Client.GetBestBlock()
	require.NoError(t.t, err, "unable to get current block height")
	t.lndHarness.WaitForNodeBlockHeight(t.tapd.cfg.LndNode, tempMinerHeight)

	// At this point, the asset proofs should be invalid, since the mint TX
	// was re-organized out.
	for idx := range assetList {
		a := assetList[idx]
		AssertAssetProofsInvalid(t.t, t.tapd, a)
	}

	// Cleanup by mining the minting tx again.
	newBlock := t.lndHarness.MineBlocksAndAssertNumTxes(1, 1)[0]
	newBlockHash := newBlock.BlockHash()
	_, newBlockHeight := lndMiner.GetBestBlock()
	lndMiner.AssertTxInBlock(newBlock, mintTXID)
	t.Logf("Mint TX %v re-mined in block %v", mintTXID, newBlockHash)

	// Let's wait until we see that the proof for the first asset was
	// updated to the new block height.
	WaitForProofUpdate(t.t, t.tapd, assetList[0], newBlockHeight)

	// We now try to validate the issuance proof of the two assets we
	// minted again. The re-org watcher should have updated the proofs and
	// pushed them to the proof store. They should be valid now.
	chainClient := t.tapd.cfg.LndNode.RPC.ChainKit
	for idx := range assetList {
		a := assetList[idx]
		AssertAssetProofs(t.t, t.tapd, chainClient, a)
	}

	// Let's now bury the proofs under sufficient blocks to allow the re-org
	// watcher to stop watching the TX.
	t.lndHarness.MineBlocks(8)

	// The second tapd instance should now have a different universe state
	// since we only updated the issuance proofs in the first tapd instance.
	AssertUniverseRootEquality(t.t, t.tapd, secondTapd, false)

	// A universe sync should now bring both nodes back into sync.
	ctxt, cancel = context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()
	syncDiff, err := secondTapd.SyncUniverse(ctxt, &unirpc.SyncRequest{
		UniverseHost: t.tapd.rpcHost(),
		SyncMode:     unirpc.UniverseSyncMode_SYNC_ISSUANCE_ONLY,
	})
	require.NoError(t.t, err)
	require.Len(t.t, syncDiff.SyncedUniverses, len(assetList))

	AssertUniverseRootEquality(t.t, t.tapd, secondTapd, true)
}

// testReOrgSend tests that when a re-org occurs, sent asset proofs are updated
// accordingly.
func testReOrgSend(t *harnessTest) {
	// First, we'll mint a few assets and confirm the batch TX.
	mintRequests := []*mintrpc.MintAssetRequest{
		issuableAssets[0], issuableAssets[1],
	}
	lndMiner := t.lndHarness.Miner()
	assetList := MintAssetsConfirmBatch(
		t.t, lndMiner.Client, t.tapd, mintRequests,
	)

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// Now that we have the asset created, we'll make a new node that'll
	// serve as the node which'll receive the assets. The existing tapd
	// node will be used to synchronize universe state.
	lndBob := t.lndHarness.NewNodeWithCoins("Bob", nil)
	secondTapd := setupTapdHarness(t.t, t, lndBob, t.universeServer)
	defer func() {
		require.NoError(t.t, secondTapd.stop(!*noDelete))
	}()

	// Before we mine a block to confirm the mint TX, we create a temporary
	// miner.
	tempMiner := spawnTempMiner(t.t, t, ctxt)

	// Now to the second part of the test: We'll send an asset to Bob, and
	// then re-org the chain again.
	sendAsset := assetList[0]
	sendAssetGen := sendAsset.AssetGenesis
	sendAmount := uint64(500)
	bobAddr, err := secondTapd.NewAddr(ctxt, &taprpc.NewAddrRequest{
		AssetId: sendAssetGen.AssetId,
		Amt:     sendAmount,
	})
	require.NoError(t.t, err)
	AssertAddrCreated(t.t, secondTapd, sendAsset, bobAddr)
	sendResp, _ := sendAssetsToAddr(t, t.tapd, bobAddr)
	initialBlock := ConfirmAndAssertOutboundTransfer(
		t.t, lndMiner.Client, t.tapd, sendResp, sendAssetGen.AssetId,
		[]uint64{sendAsset.Amount - sendAmount, sendAmount}, 0, 1,
	)
	AssertNonInteractiveRecvComplete(t.t, secondTapd, 1)
	initialBlockHash := initialBlock.BlockHash()

	// Make sure the original send TX was mined in the first block.
	sendTXID, err := chainhash.NewHash(sendResp.Transfer.AnchorTxHash)
	require.NoError(t.t, err)
	lndMiner.AssertTxInBlock(initialBlock, *sendTXID)
	t.Logf("Send TX %v mined in block %v", sendTXID, initialBlockHash)

	// We now generate the re-org. That should put the minting TX back into
	// the mempool.
	generateReOrg(t.t, t.lndHarness, tempMiner, 3, 2)
	lndMiner.AssertNumTxsInMempool(1)

	// This should have caused a reorg, and Alice should sync to the longer
	// chain, where the funding transaction is not confirmed.
	_, tempMinerHeight, err := tempMiner.Client.GetBestBlock()
	require.NoError(t.t, err, "unable to get current block height")
	t.lndHarness.WaitForNodeBlockHeight(t.tapd.cfg.LndNode, tempMinerHeight)

	// At this point, the all asset proofs should be invalid, since the send
	// TX was re-organized out, and it also contained passive assets.
	listAssetRequest := &taprpc.ListAssetRequest{}
	aliceAssets, err := t.tapd.ListAssets(ctxb, listAssetRequest)
	require.NoError(t.t, err)
	bobAssets, err := secondTapd.ListAssets(ctxb, listAssetRequest)
	require.NoError(t.t, err)

	for idx := range aliceAssets.Assets {
		a := aliceAssets.Assets[idx]
		AssertAssetProofsInvalid(t.t, t.tapd, a)
	}
	for idx := range bobAssets.Assets {
		a := bobAssets.Assets[idx]
		AssertAssetProofsInvalid(t.t, secondTapd, a)
	}

	// Cleanup by mining the minting tx again.
	newBlock := t.lndHarness.MineBlocksAndAssertNumTxes(1, 1)[0]
	newBlockHash := newBlock.BlockHash()
	_, newBlockHeight := lndMiner.GetBestBlock()
	lndMiner.AssertTxInBlock(newBlock, *sendTXID)
	t.Logf("Send TX %v re-mined in block %v", sendTXID, newBlockHash)

	// Let's wait until we see that the proof for the first asset was
	// updated to the new block height.
	WaitForProofUpdate(t.t, t.tapd, aliceAssets.Assets[0], newBlockHeight)
	WaitForProofUpdate(t.t, secondTapd, bobAssets.Assets[0], newBlockHeight)

	// We now try to validate the send proofs of the delivered, change and
	// passive assets. The re-org watcher should have updated the proofs and
	// pushed them to the proof store. They should be valid now.
	aliceChainClient := t.tapd.cfg.LndNode.RPC.ChainKit
	for idx := range aliceAssets.Assets {
		a := aliceAssets.Assets[idx]
		AssertAssetProofs(t.t, t.tapd, aliceChainClient, a)
	}

	bobChainClient := secondTapd.cfg.LndNode.RPC.ChainKit
	for idx := range bobAssets.Assets {
		a := bobAssets.Assets[idx]
		AssertAssetProofs(t.t, secondTapd, bobChainClient, a)
	}

	// Let's now bury the proofs under sufficient blocks to allow the re-org
	// watcher to stop watching the TX.
	t.lndHarness.MineBlocks(8)
}

// testReOrgMintAndSend tests that when a re-org occurs, minted and directly
// sent asset proofs are updated accordingly.
func testReOrgMintAndSend(t *harnessTest) {
	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// We create a second node for the second tapd instance. But because
	// NewNodeWithCoins mines a block, we need to do it before we spawn the
	// temporary miner.
	lndBob := t.lndHarness.NewNodeWithCoins("Bob", nil)

	// Before we do anything, we spawn a miner. This is where the fork in
	// the chain starts.
	tempMiner := spawnTempMiner(t.t, t, ctxt)
	lndMiner := t.lndHarness.Miner()

	// Then, we'll mint a few assets and confirm the batch TX.
	mintRequests := []*mintrpc.MintAssetRequest{
		issuableAssets[0], issuableAssets[1],
	}
	assetList := MintAssetsConfirmBatch(
		t.t, lndMiner.Client, t.tapd, mintRequests,
	)

	// Now that we have the asset created, we'll make a new node that'll
	// serve as the node which'll receive the assets. The existing tapd
	// node will be used to synchronize universe state.
	secondTapd := setupTapdHarness(t.t, t, lndBob, t.universeServer)
	defer func() {
		require.NoError(t.t, secondTapd.stop(!*noDelete))
	}()

	// We'll send an asset to Bob, and then re-org the chain, which should
	// cause both the minting TX and the send TX to be un-confirmed.
	sendAsset := assetList[0]
	sendAssetGen := sendAsset.AssetGenesis
	sendAmount := uint64(500)
	bobAddr, err := secondTapd.NewAddr(ctxt, &taprpc.NewAddrRequest{
		AssetId: sendAssetGen.AssetId,
		Amt:     sendAmount,
	})
	require.NoError(t.t, err)
	AssertAddrCreated(t.t, secondTapd, sendAsset, bobAddr)
	sendResp, _ := sendAssetsToAddr(t, t.tapd, bobAddr)
	initialBlock := ConfirmAndAssertOutboundTransfer(
		t.t, lndMiner.Client, t.tapd, sendResp, sendAssetGen.AssetId,
		[]uint64{sendAsset.Amount - sendAmount, sendAmount}, 0, 1,
	)
	AssertNonInteractiveRecvComplete(t.t, secondTapd, 1)
	initialBlockHash := initialBlock.BlockHash()

	// Make sure the original send TX was mined in the first block.
	sendTXID, err := chainhash.NewHash(sendResp.Transfer.AnchorTxHash)
	require.NoError(t.t, err)
	lndMiner.AssertTxInBlock(initialBlock, *sendTXID)
	t.Logf("Send TX %v mined in block %v", sendTXID, initialBlockHash)

	// We now generate the re-org. That should put the minting and send TX
	// back into the mempool.
	generateReOrg(t.t, t.lndHarness, tempMiner, 4, 2)
	lndMiner.AssertNumTxsInMempool(2)

	// This should have caused a reorg, and Alice should sync to the longer
	// chain, where the funding transaction is not confirmed.
	_, tempMinerHeight, err := tempMiner.Client.GetBestBlock()
	require.NoError(t.t, err, "unable to get current block height")
	t.lndHarness.WaitForNodeBlockHeight(t.tapd.cfg.LndNode, tempMinerHeight)

	// At this point, the all asset proofs should be invalid, since the send
	// TX was re-organized out, and it also contained passive assets.
	listAssetRequest := &taprpc.ListAssetRequest{}
	aliceAssets, err := t.tapd.ListAssets(ctxb, listAssetRequest)
	require.NoError(t.t, err)
	bobAssets, err := secondTapd.ListAssets(ctxb, listAssetRequest)
	require.NoError(t.t, err)

	for idx := range aliceAssets.Assets {
		a := aliceAssets.Assets[idx]
		AssertAssetProofsInvalid(t.t, t.tapd, a)
	}
	for idx := range bobAssets.Assets {
		a := bobAssets.Assets[idx]
		AssertAssetProofsInvalid(t.t, secondTapd, a)
	}

	// We now also stop Bob to make sure he can still detect the re-org and
	// update the proofs once it comes back up.
	t.t.Logf("Stopping Bob's daemon")
	require.NoError(t.t, secondTapd.stop(false))

	// Cleanup by mining the minting tx again.
	newBlock := t.lndHarness.MineBlocksAndAssertNumTxes(1, 2)[0]
	newBlockHash := newBlock.BlockHash()
	_, newBlockHeight := lndMiner.GetBestBlock()
	lndMiner.AssertTxInBlock(newBlock, *sendTXID)
	t.Logf("Send TX %v re-mined in block %v", sendTXID, newBlockHash)

	// We now restart Bob's daemon, expecting it to pick up the re-org.
	t.t.Logf("Re-starting Bob's daemon so as to complete transfer")
	require.NoError(t.t, secondTapd.start(false))

	// Let's wait until we see that the proof for the mint, first and sent
	// assets were updated to the new block height.
	WaitForProofUpdate(t.t, t.tapd, assetList[0], newBlockHeight)
	WaitForProofUpdate(t.t, t.tapd, aliceAssets.Assets[0], newBlockHeight)
	WaitForProofUpdate(t.t, secondTapd, bobAssets.Assets[0], newBlockHeight)

	// We now try to validate the send proofs of the delivered, change and
	// passive assets. The re-org watcher should have updated the proofs and
	// pushed them to the proof store. They should be valid now.
	aliceChainClient := t.tapd.cfg.LndNode.RPC.ChainKit
	for idx := range aliceAssets.Assets {
		a := aliceAssets.Assets[idx]
		AssertAssetProofs(t.t, t.tapd, aliceChainClient, a)
	}

	bobChainClient := secondTapd.cfg.LndNode.RPC.ChainKit
	for idx := range bobAssets.Assets {
		a := bobAssets.Assets[idx]
		AssertAssetProofs(t.t, secondTapd, bobChainClient, a)
	}

	// Let's now bury the proofs under sufficient blocks to allow the re-org
	// watcher to stop watching the TX.
	t.lndHarness.MineBlocks(8)
}

// spawnTempMiner creates a temporary miner that uses the same chain backend
// and client as the main miner.
func spawnTempMiner(t *testing.T, ht *harnessTest,
	ctx context.Context) *miner.HarnessMiner {

	tempHarness := miner.NewMiner(ctx, t)
	tempHarness.Client = ht.lndHarness.Miner().Client
	return tempHarness.SpawnTempMiner()
}

// generateReOrg generates a re-org by mining a longer chain with a temporary
// miner, and then connecting the temporary miner to the original miner.
// Depending on when exactly the temporary miner was spawned, the expectedDelta
// might differ from the depth, if the "main" miner already has more blocks.
func generateReOrg(t *testing.T, lnd *lntest.HarnessTest,
	tempMiner *miner.HarnessMiner, depth uint32, expectedDelta int32) {

	// Now we generate a longer chain with the temp miner.
	tempMiner.MineEmptyBlocks(int(depth))

	// Ensure the chain lengths are what we expect, with the temp miner
	// being 2 blocks ahead.
	lnd.Miner().AssertMinerBlockHeightDelta(tempMiner, expectedDelta)

	// Now we disconnect lnd's chain backend from the original miner, and
	// connect the two miners together. Since the temporary miner knows
	// about a longer chain, both miners should sync to that chain.
	lnd.DisconnectMiner()

	// Connecting to the temporary miner should now cause our original
	// chain to be re-orged out.
	lnd.Miner().ConnectMiner(tempMiner)

	// Once again they should be on the same chain.
	lnd.Miner().AssertMinerBlockHeightDelta(tempMiner, 0)

	// Now we disconnect the two miners, and connect our original miner to
	// our chain backend once again.
	lnd.Miner().DisconnectMiner(tempMiner)

	lnd.ConnectMiner()
}
