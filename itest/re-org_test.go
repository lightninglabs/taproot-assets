package itest

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
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
		t.t, lndMiner, t.tapd, mintRequests,
	)

	ctx := context.Background()

	// Before we mine a block to confirm the mint TX, we create a temporary
	// miner.
	tempMiner := spawnTempMiner(t.t, t, ctx)

	// And now we mine a block to confirm the assets.
	initialBlock := MineBlocks(t.t, lndMiner, 1, 1)[0]
	initialBlockHash := initialBlock.BlockHash()
	WaitForBatchState(
		t.t, ctx, t.tapd, defaultWaitTimeout, batchKey,
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
	secondTapd := setupTapdHarness(
		t.t, t, lndBob, t.universeServer,
		func(params *tapdHarnessParams) {
			params.reOrgSafeDepth = 6
		},
	)
	defer func() {
		require.NoError(t.t, secondTapd.stop(!*noDelete))
	}()

	// We now generate the re-org.
	generateReOrg(t.t, t.lndHarness, tempMiner, 3, 2)

	// This should have caused a reorg, and Alice should sync to the longer
	// chain, where the funding transaction is not confirmed.
	_, tempMinerHeight := tempMiner.GetBestBlock()
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

	// Burial releases the act-gated universe publication through the
	// watcher's outbox; wait for the re-stamped issuance leaves to
	// land before comparing universe states.
	WaitForMintUniverseLeaves(t.t, t.tapd, assetList)

	// The second tapd instance should now have a different universe state
	// since we only updated the issuance proofs in the first tapd instance.
	AssertUniverseRootEquality(t.t, t.tapd, secondTapd, false)

	// A universe sync should now bring both nodes back into sync.
	ctxt, cancel := context.WithTimeout(ctx, defaultWaitTimeout)
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
		t.t, lndMiner, t.tapd, mintRequests, WithNoUniverseLeafWait(),
	)

	// At the re-org tests' burial depth of 6 the universe publication
	// is act-gated, so downstream nodes cannot discover the minted
	// assets yet. Bury the mint first; the re-org scenario under test
	// targets the send transaction, not the mint.
	t.lndHarness.MineBlocks(6)
	WaitForMintUniverseLeaves(t.t, t.tapd, assetList)

	ctx := context.Background()

	// Now that we have the asset created, we'll make a new node that'll
	// serve as the node which'll receive the assets. The existing tapd
	// node will be used to synchronize universe state.
	lndBob := t.lndHarness.NewNodeWithCoins("Bob", nil)
	secondTapd := setupTapdHarness(
		t.t, t, lndBob, t.universeServer,
		func(params *tapdHarnessParams) {
			params.reOrgSafeDepth = 6
		},
	)
	defer func() {
		require.NoError(t.t, secondTapd.stop(!*noDelete))
	}()

	// Before we mine a block to confirm the mint TX, we create a temporary
	// miner.
	tempMiner := spawnTempMiner(t.t, t, ctx)

	// Now to the second part of the test: We'll send an asset to Bob, and
	// then re-org the chain again.
	sendAsset := assetList[0]
	sendAssetGen := sendAsset.AssetGenesis
	sendAmount := uint64(500)
	bobAddr, err := secondTapd.NewAddr(ctx, &taprpc.NewAddrRequest{
		AssetId: sendAssetGen.AssetId,
		Amt:     sendAmount,
	})
	require.NoError(t.t, err)
	AssertAddrCreated(t.t, secondTapd, sendAsset, bobAddr)
	sendResp, _ := sendAssetsToAddr(t, t.tapd, bobAddr)
	initialBlock := ConfirmAndAssertOutboundTransfer(
		t.t, lndMiner, t.tapd, sendResp, sendAssetGen.AssetId,
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
	_, tempMinerHeight := tempMiner.GetBestBlock()
	t.lndHarness.WaitForNodeBlockHeight(t.tapd.cfg.LndNode, tempMinerHeight)

	// At this point, the all asset proofs should be invalid, since the send
	// TX was re-organized out, and it also contained passive assets.
	// The send transaction was re-organized out, and it anchored
	// passive assets too. The re-org watcher's potency-tier downgrade
	// reflects that honestly: the transfer and everything it anchors
	// are unconfirmed until the transaction confirms again, so no
	// confirmed assets or balances are reported in the meantime. The
	// legacy proof watcher has no such tier: the sender keeps listing
	// the transfer's outputs, with proofs that no longer verify.
	listAssetRequest := &taprpc.ListAssetRequest{}
	aliceAssets, err := t.tapd.ListAssets(ctx, listAssetRequest)
	require.NoError(t.t, err)
	if t.tapd.anchoringWatcherDisabled {
		require.NotEmpty(t.t, aliceAssets.Assets)
	} else {
		// The downgrade is delivered once the watcher senses the
		// re-org, asynchronously to the node's chain sync, so it
		// is awaited rather than asserted at once.
		require.Eventually(t.t, func() bool {
			aliceAssets, err = t.tapd.ListAssets(
				ctx, listAssetRequest,
			)

			return err == nil && len(aliceAssets.Assets) == 0 &&
				aliceAssets.UnconfirmedTransfers == 1
		}, defaultWaitTimeout, 200*time.Millisecond)
	}

	bobAssets, err := secondTapd.ListAssets(ctx, listAssetRequest)
	require.NoError(t.t, err)
	require.Empty(t.t, bobAssets.Assets)

	// Cleanup by mining the minting tx again.
	newBlock := t.lndHarness.MineBlocksAndAssertNumTxes(1, 1)[0]
	newBlockHash := newBlock.BlockHash()
	_, newBlockHeight := lndMiner.GetBestBlock()
	lndMiner.AssertTxInBlock(newBlock, *sendTXID)
	t.Logf("Send TX %v re-mined in block %v", sendTXID, newBlockHash)

	// With the send re-confirmed, the assets return to their
	// confirmed shape on both nodes.
	require.Eventually(t.t, func() bool {
		aliceAssets, err = t.tapd.ListAssets(ctx, listAssetRequest)
		return err == nil && len(aliceAssets.Assets) > 0
	}, defaultWaitTimeout, 200*time.Millisecond)
	require.Eventually(t.t, func() bool {
		bobAssets, err = secondTapd.ListAssets(ctx, listAssetRequest)
		return err == nil && len(bobAssets.Assets) > 0
	}, defaultWaitTimeout, 200*time.Millisecond)

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

	// Make sure the balances are shown correctly after the re-org.
	AssertBalances(
		t.t, t.tapd, sendAsset.Amount-sendAmount,
		WithAssetID(sendAssetGen.AssetId), WithNumUtxos(1),
	)
	AssertBalances(
		t.t, t.tapd, assetList[1].Amount,
		WithAssetID(assetList[1].AssetGenesis.AssetId), WithNumUtxos(1),
	)
	AssertBalances(
		t.t, secondTapd, sendAmount, WithAssetID(sendAssetGen.AssetId),
		WithNumUtxos(1),
	)
}

// testReOrgSendV2Address tests that when a re-org occurs with a v2 address,
// sent asset proofs are updated accordingly.
func testReOrgSendV2Address(t *harnessTest) {
	// First, we'll mint a few assets and confirm the batch TX.
	mintRequests := []*mintrpc.MintAssetRequest{
		issuableAssets[0], issuableAssets[1],
	}
	lndMiner := t.lndHarness.Miner()
	assetList := MintAssetsConfirmBatch(
		t.t, lndMiner, t.tapd, mintRequests, WithNoUniverseLeafWait(),
	)

	// At the re-org tests' burial depth of 6 the universe publication
	// is act-gated, so downstream nodes cannot discover the minted
	// assets yet. Bury the mint first; the re-org scenario under test
	// targets the send transaction, not the mint.
	t.lndHarness.MineBlocks(6)
	WaitForMintUniverseLeaves(t.t, t.tapd, assetList)

	ctx := context.Background()

	// Now that we have the asset created, we'll make a new node that'll
	// serve as the node which'll receive the assets. The existing tapd
	// node will be used to synchronize universe state.
	lndBob := t.lndHarness.NewNodeWithCoins("Bob", nil)
	secondTapd := setupTapdHarness(
		t.t, t, lndBob, t.universeServer,
		func(params *tapdHarnessParams) {
			params.reOrgSafeDepth = 6
		},
	)
	defer func() {
		require.NoError(t.t, secondTapd.stop(!*noDelete))
	}()

	// Before we mine a block to confirm the mint TX, we create a temporary
	// miner.
	tempMiner := spawnTempMiner(t.t, t, ctx)

	// Now to the second part of the test: We'll send an asset to Bob, and
	// then re-org the chain again.
	sendAsset := assetList[0]
	sendAssetGen := sendAsset.AssetGenesis
	sendAmount := uint64(500)
	bobAddrV2, err := secondTapd.NewAddr(ctx, &taprpc.NewAddrRequest{
		GroupKey:       sendAsset.AssetGroup.TweakedGroupKey,
		Amt:            sendAmount,
		AddressVersion: addrV2,
	})
	require.NoError(t.t, err)
	AssertAddrCreated(t.t, secondTapd, sendAsset, bobAddrV2)

	sendResp, _ := sendAssetsToAddr(t, t.tapd, bobAddrV2)
	initialBlock := ConfirmAndAssertOutboundTransfer(
		t.t, lndMiner, t.tapd, sendResp, sendAssetGen.AssetId,
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
	_, tempMinerHeight := tempMiner.GetBestBlock()
	t.lndHarness.WaitForNodeBlockHeight(t.tapd.cfg.LndNode, tempMinerHeight)

	// At this point, the all asset proofs should be invalid, since the send
	// TX was re-organized out, and it also contained passive assets.
	// The send transaction was re-organized out, and it anchored
	// passive assets too. The re-org watcher's potency-tier downgrade
	// reflects that honestly: the transfer and everything it anchors
	// are unconfirmed until the transaction confirms again, so no
	// confirmed assets or balances are reported in the meantime. The
	// legacy proof watcher has no such tier: the sender keeps listing
	// the transfer's outputs, with proofs that no longer verify.
	listAssetRequest := &taprpc.ListAssetRequest{}
	aliceAssets, err := t.tapd.ListAssets(ctx, listAssetRequest)
	require.NoError(t.t, err)
	if t.tapd.anchoringWatcherDisabled {
		require.NotEmpty(t.t, aliceAssets.Assets)
	} else {
		// The downgrade is delivered once the watcher senses the
		// re-org, asynchronously to the node's chain sync, so it
		// is awaited rather than asserted at once.
		require.Eventually(t.t, func() bool {
			aliceAssets, err = t.tapd.ListAssets(
				ctx, listAssetRequest,
			)

			return err == nil && len(aliceAssets.Assets) == 0 &&
				aliceAssets.UnconfirmedTransfers == 1
		}, defaultWaitTimeout, 200*time.Millisecond)
	}

	bobAssets, err := secondTapd.ListAssets(ctx, listAssetRequest)
	require.NoError(t.t, err)
	require.Empty(t.t, bobAssets.Assets)

	// Cleanup by mining the minting tx again.
	newBlock := t.lndHarness.MineBlocksAndAssertNumTxes(1, 1)[0]
	newBlockHash := newBlock.BlockHash()
	_, newBlockHeight := lndMiner.GetBestBlock()
	lndMiner.AssertTxInBlock(newBlock, *sendTXID)
	t.Logf("Send TX %v re-mined in block %v", sendTXID, newBlockHash)

	// With the send re-confirmed, the assets return to their
	// confirmed shape on both nodes.
	require.Eventually(t.t, func() bool {
		aliceAssets, err = t.tapd.ListAssets(ctx, listAssetRequest)
		return err == nil && len(aliceAssets.Assets) > 0
	}, defaultWaitTimeout, 200*time.Millisecond)
	require.Eventually(t.t, func() bool {
		bobAssets, err = secondTapd.ListAssets(ctx, listAssetRequest)
		return err == nil && len(bobAssets.Assets) > 0
	}, defaultWaitTimeout, 200*time.Millisecond)

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

	// Make sure the balances are shown correctly after the re-org.
	AssertBalances(
		t.t, t.tapd, sendAsset.Amount-sendAmount,
		WithAssetID(sendAssetGen.AssetId), WithNumUtxos(1),
	)
	AssertBalances(
		t.t, t.tapd, assetList[1].Amount,
		WithAssetID(assetList[1].AssetGenesis.AssetId), WithNumUtxos(1),
	)
	AssertBalances(
		t.t, secondTapd, sendAmount, WithAssetID(sendAssetGen.AssetId),
		WithNumUtxos(1),
	)
}

// testReOrgMintAndSend tests that when a re-org occurs shortly after a
// mint, sent asset proofs are updated accordingly — including for a
// receiver that was offline during the re-org and catches up on
// restart. The mint itself is buried before the send: under act-gated
// publication a receiver cannot learn of an unburied issuance, and
// re-organizing a buried mint would contradict its act-level
// certification — a distinct operator-attention condition by design,
// not the re-confirmation cycle exercised here.
func testReOrgMintAndSend(t *harnessTest) {
	ctx := context.Background()

	// We create a second node for the second tapd instance. But because
	// NewNodeWithCoins mines a block, we need to do it before we spawn the
	// temporary miner.
	lndBob := t.lndHarness.NewNodeWithCoins("Bob", nil)

	lndMiner := t.lndHarness.Miner()

	// Then, we'll mint a few assets and confirm the batch TX.
	mintRequests := []*mintrpc.MintAssetRequest{
		issuableAssets[0], issuableAssets[1],
	}
	assetList := MintAssetsConfirmBatch(
		t.t, lndMiner, t.tapd, mintRequests, WithNoUniverseLeafWait(),
	)

	// At the re-org tests' burial depth of 6 the universe publication
	// is act-gated, so downstream nodes cannot discover the minted
	// assets yet. Bury the mint first; the re-org scenario under test
	// targets the send transaction, not the mint.
	t.lndHarness.MineBlocks(6)
	WaitForMintUniverseLeaves(t.t, t.tapd, assetList)

	// The fork under test starts here: past the mint's burial, so the
	// re-org targets only the send transaction.
	tempMiner := spawnTempMiner(t.t, t, ctx)

	// Now that we have the asset created, we'll make a new node that'll
	// serve as the node which'll receive the assets. The existing tapd
	// node will be used to synchronize universe state.
	secondTapd := setupTapdHarness(
		t.t, t, lndBob, t.universeServer,
		func(params *tapdHarnessParams) {
			params.reOrgSafeDepth = 6
		},
	)
	defer func() {
		require.NoError(t.t, secondTapd.stop(!*noDelete))
	}()

	// We'll send an asset to Bob, and then re-org the chain, which should
	// un-confirm the send TX.
	sendAsset := assetList[0]
	sendAssetGen := sendAsset.AssetGenesis
	sendAmount := uint64(500)
	bobAddr, err := secondTapd.NewAddr(ctx, &taprpc.NewAddrRequest{
		AssetId: sendAssetGen.AssetId,
		Amt:     sendAmount,
	})
	require.NoError(t.t, err)
	AssertAddrCreated(t.t, secondTapd, sendAsset, bobAddr)
	sendResp, _ := sendAssetsToAddr(t, t.tapd, bobAddr)
	initialBlock := ConfirmAndAssertOutboundTransfer(
		t.t, lndMiner, t.tapd, sendResp, sendAssetGen.AssetId,
		[]uint64{sendAsset.Amount - sendAmount, sendAmount}, 0, 1,
	)
	AssertNonInteractiveRecvComplete(t.t, secondTapd, 1)
	initialBlockHash := initialBlock.BlockHash()

	// Make sure the original send TX was mined in the first block.
	sendTXID, err := chainhash.NewHash(sendResp.Transfer.AnchorTxHash)
	require.NoError(t.t, err)
	lndMiner.AssertTxInBlock(initialBlock, *sendTXID)
	t.Logf("Send TX %v mined in block %v", sendTXID, initialBlockHash)

	// Both nodes list the assets while the send is confirmed. These
	// are the listings the re-org hides, and whose stored proofs it
	// invalidates.
	listAssetRequest := &taprpc.ListAssetRequest{}
	aliceAssets, err := t.tapd.ListAssets(ctx, listAssetRequest)
	require.NoError(t.t, err)
	require.NotEmpty(t.t, aliceAssets.Assets)

	bobAssets, err := secondTapd.ListAssets(ctx, listAssetRequest)
	require.NoError(t.t, err)
	require.NotEmpty(t.t, bobAssets.Assets)

	// We now generate the re-org. That should put the send TX back
	// into the mempool.
	generateReOrg(t.t, t.lndHarness, tempMiner, 3, 2)
	lndMiner.AssertNumTxsInMempool(1)

	// This should have caused a reorg, and Alice should sync to the longer
	// chain, where the funding transaction is not confirmed.
	_, tempMinerHeight := tempMiner.GetBestBlock()
	t.lndHarness.WaitForNodeBlockHeight(t.tapd.cfg.LndNode, tempMinerHeight)

	// The send transaction was re-organized out, and it anchored a
	// passive asset too. The stored proofs still attest the discarded
	// block, so they no longer verify against the chain.
	for idx := range aliceAssets.Assets {
		AssertAssetProofsInvalid(t.t, t.tapd, aliceAssets.Assets[idx])
	}
	for idx := range bobAssets.Assets {
		AssertAssetProofsInvalid(t.t, secondTapd, bobAssets.Assets[idx])
	}

	// The potency-tier downgrade leaves the transfer and everything
	// it anchors unconfirmed until the transaction confirms again, so
	// neither node lists a confirmed asset in the meantime.
	aliceAssets, err = t.tapd.ListAssets(ctx, listAssetRequest)
	require.NoError(t.t, err)
	require.Empty(t.t, aliceAssets.Assets)

	bobAssets, err = secondTapd.ListAssets(ctx, listAssetRequest)
	require.NoError(t.t, err)
	require.Empty(t.t, bobAssets.Assets)

	// We now also stop Bob to make sure he can still detect the re-org and
	// update the proofs once it comes back up.
	t.t.Logf("Stopping Bob's daemon")
	require.NoError(t.t, secondTapd.stop(false))

	// Cleanup by mining the minting tx again.
	newBlock := t.lndHarness.MineBlocksAndAssertNumTxes(1, 1)[0]
	newBlockHash := newBlock.BlockHash()
	_, newBlockHeight := lndMiner.GetBestBlock()
	lndMiner.AssertTxInBlock(newBlock, *sendTXID)
	t.Logf("Send TX %v re-mined in block %v", sendTXID, newBlockHash)

	// We now restart Bob's daemon, expecting it to pick up the re-org.
	t.t.Logf("Re-starting Bob's daemon so as to complete transfer")
	require.NoError(t.t, secondTapd.start(false))

	// With the send re-confirmed, the assets return to their
	// confirmed shape on both nodes (Bob catches up after the
	// restart).
	require.Eventually(t.t, func() bool {
		aliceAssets, err = t.tapd.ListAssets(ctx, listAssetRequest)
		return err == nil && len(aliceAssets.Assets) > 0
	}, defaultWaitTimeout, 200*time.Millisecond)
	require.Eventually(t.t, func() bool {
		bobAssets, err = secondTapd.ListAssets(ctx, listAssetRequest)
		return err == nil && len(bobAssets.Assets) > 0
	}, defaultWaitTimeout, 200*time.Millisecond)

	// Let's wait until we see that the proofs of the change and sent
	// assets were updated to the new block height.
	WaitForProofUpdate(t.t, t.tapd, aliceAssets.Assets[0], newBlockHeight)
	WaitForProofUpdate(t.t, secondTapd, bobAssets.Assets[0], newBlockHeight)

	// Let's now bury the proofs under sufficient blocks to allow the re-org
	// watcher to stop watching the TX.
	t.lndHarness.MineBlocks(8)

	// With the send buried, both nodes report the balances the
	// transfer produced: Alice's change and her passively re-anchored
	// asset, and Bob's received amount.
	AssertBalances(
		t.t, t.tapd, sendAsset.Amount-sendAmount,
		WithAssetID(sendAssetGen.AssetId), WithNumUtxos(1),
	)
	AssertBalances(
		t.t, t.tapd, assetList[1].Amount,
		WithAssetID(assetList[1].AssetGenesis.AssetId), WithNumUtxos(1),
	)
	AssertBalances(
		t.t, secondTapd, sendAmount, WithAssetID(sendAssetGen.AssetId),
		WithNumUtxos(1),
	)

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
}

// spawnTempMiner creates a temporary miner that uses the same chain backend
// and client as the main miner.
func spawnTempMiner(t *testing.T, ht *harnessTest,
	ctx context.Context) *miner.HarnessMiner {

	tempMiner := ht.lndHarness.Miner().SpawnTempMiner()

	// Every temporary miner in the tranche saves logs from — and then
	// removes — the same shared directory when it stops, so the first
	// stop breaks the ones after it. The stops are cleanups on the
	// root harness T and run in LIFO order: registering this after
	// the spawn re-creates the directory just before this miner's own
	// stop reads it.
	ht.lndHarness.Cleanup(func() {
		_ = os.MkdirAll("regtest/.tempminerlogs/regtest", 0755)
	})

	return tempMiner
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
