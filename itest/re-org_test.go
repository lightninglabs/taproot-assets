package itest

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/rpcutils"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	unirpc "github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	"github.com/lightningnetwork/lnd/lnrpc/signrpc"
	"github.com/lightningnetwork/lnd/lntest"
	"github.com/lightningnetwork/lnd/lntest/miner"
	"github.com/lightningnetwork/lnd/lntest/wait"
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

	// The proofs are not the only state keyed to the anchor: the
	// database's chain-transaction row must re-stamp to the new block
	// too. ListAssets reports the recorded anchor block context
	// straight from those rows.
	require.Eventually(t.t, func() bool {
		listResp, err := t.tapd.ListAssets(
			ctx, &taprpc.ListAssetRequest{},
		)
		if err != nil || len(listResp.Assets) == 0 {
			return false
		}

		for _, a := range listResp.Assets {
			anchor := a.ChainAnchor
			if anchor.AnchorBlockHash != newBlockHash.String() {
				return false
			}
			if anchor.BlockHeight != uint32(newBlockHeight) {
				return false
			}
		}

		return true
	}, defaultWaitTimeout, 200*time.Millisecond)

	// The batch row itself must have remained finalized across the
	// re-org.
	WaitForBatchState(
		t.t, ctx, t.tapd, defaultWaitTimeout, batchKey,
		mintrpc.BatchState_BATCH_STATE_FINALIZED,
	)

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
	// downgrade is delivered once the watcher senses the re-org,
	// asynchronously to the node's chain sync, so it is awaited
	// rather than asserted at once.
	listAssetRequest := &taprpc.ListAssetRequest{}
	var aliceAssets *taprpc.ListAssetResponse
	require.Eventually(t.t, func() bool {
		var err error
		aliceAssets, err = t.tapd.ListAssets(ctx, listAssetRequest)

		return err == nil && len(aliceAssets.Assets) == 0 &&
			aliceAssets.UnconfirmedTransfers == 1
	}, defaultWaitTimeout, 200*time.Millisecond)

	bobAssets, err := secondTapd.ListAssets(ctx, listAssetRequest)
	require.NoError(t.t, err)
	require.Empty(t.t, bobAssets.Assets)

	// The downgrade is potency-tier only: nothing is compensated
	// while the send can still re-confirm, so the receiver's address
	// event keeps its completed status through the window.
	AssertAddrEvent(t.t, secondTapd, bobAddr, 1, statusCompleted)

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

	// The sender's transfer row must re-stamp its recorded anchor
	// block context to the new block as well; ListTransfers reports
	// it straight from the chain-transaction row.
	require.Eventually(t.t, func() bool {
		transfers, err := t.tapd.ListTransfers(
			ctx, &taprpc.ListTransfersRequest{},
		)
		if err != nil || len(transfers.Transfers) != 1 {
			return false
		}

		transfer := transfers.Transfers[0]
		if transfer.AnchorTxBlockHash == nil {
			return false
		}

		return bytes.Equal(
			transfer.AnchorTxBlockHash.Hash, newBlockHash[:],
		) && transfer.AnchorTxBlockHeight == uint32(newBlockHeight)
	}, defaultWaitTimeout, 200*time.Millisecond)

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
	// downgrade is delivered once the watcher senses the re-org,
	// asynchronously to the node's chain sync, so it is awaited
	// rather than asserted at once.
	listAssetRequest := &taprpc.ListAssetRequest{}
	var aliceAssets *taprpc.ListAssetResponse
	require.Eventually(t.t, func() bool {
		var err error
		aliceAssets, err = t.tapd.ListAssets(ctx, listAssetRequest)

		return err == nil && len(aliceAssets.Assets) == 0 &&
			aliceAssets.UnconfirmedTransfers == 1
	}, defaultWaitTimeout, 200*time.Millisecond)

	bobAssets, err := secondTapd.ListAssets(ctx, listAssetRequest)
	require.NoError(t.t, err)
	require.Empty(t.t, bobAssets.Assets)

	// The downgrade is potency-tier only: nothing is compensated
	// while the send can still re-confirm, so the receiver's address
	// event keeps its completed status through the window.
	AssertAddrEvent(t.t, secondTapd, bobAddrV2, 1, statusCompleted)

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

	// The sender's transfer row must re-stamp its recorded anchor
	// block context to the new block as well; ListTransfers reports
	// it straight from the chain-transaction row.
	require.Eventually(t.t, func() bool {
		transfers, err := t.tapd.ListTransfers(
			ctx, &taprpc.ListTransfersRequest{},
		)
		if err != nil || len(transfers.Transfers) != 1 {
			return false
		}

		transfer := transfers.Transfers[0]
		if transfer.AnchorTxBlockHash == nil {
			return false
		}

		return bytes.Equal(
			transfer.AnchorTxBlockHash.Hash, newBlockHash[:],
		) && transfer.AnchorTxBlockHeight == uint32(newBlockHeight)
	}, defaultWaitTimeout, 200*time.Millisecond)

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

// testReOrgNestedHistory tests a re-org over a history the proof DAG
// nests. Bob receives two outputs of one asset, the second carved from
// the first send's change, and spends both in one transfer back to
// Alice, so Alice's proof file carries the second input's history
// nested inside its tip. A re-org then moves all three transfers, and
// the repair must reach the occurrences inside the nested file as well
// as those on the main lineage: every transfer in Alice's file sits in
// the new block at every depth, the file verifies against the chain,
// and the holding can be sent on.
func testReOrgNestedHistory(t *harnessTest) {
	ctx := context.Background()

	// Bob's lnd node is created before the temporary miner, since
	// creating it mines a block.
	lndBob := t.lndHarness.NewNodeWithCoins("Bob", nil)
	lndMiner := t.lndHarness.Miner()

	// Mint and bury the mint: the fork under test starts past it, so
	// the re-org targets only the transfers.
	mintRequests := []*mintrpc.MintAssetRequest{issuableAssets[0]}
	assetList := MintAssetsConfirmBatch(
		t.t, lndMiner, t.tapd, mintRequests, WithNoUniverseLeafWait(),
	)
	t.lndHarness.MineBlocks(6)
	WaitForMintUniverseLeaves(t.t, t.tapd, assetList)

	secondTapd := setupTapdHarness(
		t.t, t, lndBob, t.universeServer,
		func(params *tapdHarnessParams) {
			params.reOrgSafeDepth = 6
		},
	)
	defer func() {
		require.NoError(t.t, secondTapd.stop(!*noDelete))
	}()

	tempMiner := spawnTempMiner(t.t, t, ctx)

	minted := assetList[0]
	assetID := minted.AssetGenesis.AssetId

	// send moves an amount between the nodes through an address and
	// confirms it, returning the anchor transaction's hash.
	send := func(from, to *tapdHarness, amount, change uint64,
		transferIdx, inbound int) chainhash.Hash {

		addr, err := to.NewAddr(ctx, &taprpc.NewAddrRequest{
			AssetId: assetID,
			Amt:     amount,
		})
		require.NoError(t.t, err)
		AssertAddrCreated(t.t, to, minted, addr)
		sendResp, _ := sendAssetsToAddr(t, from, addr)
		ConfirmAndAssertOutboundTransfer(
			t.t, lndMiner, from, sendResp, assetID,
			[]uint64{change, amount}, transferIdx, transferIdx+1,
		)
		AssertNonInteractiveRecvComplete(t.t, to, inbound)

		txid, err := chainhash.NewHash(sendResp.Transfer.AnchorTxHash)
		require.NoError(t.t, err)

		return *txid
	}

	// Two sends give Bob two outputs of the asset; the second spends
	// the first send's change, so Bob's second file holds the first
	// send in its history too.
	const firstAmount, secondAmount = uint64(400), uint64(100)
	firstTxid := send(
		t.tapd, secondTapd, firstAmount, minted.Amount-firstAmount,
		0, 1,
	)
	secondTxid := send(
		t.tapd, secondTapd, secondAmount,
		minted.Amount-firstAmount-secondAmount, 1, 2,
	)
	AssertBalances(
		t.t, secondTapd, firstAmount+secondAmount,
		WithAssetID(assetID), WithNumUtxos(2),
	)

	// Bob sends both outputs back to Alice in one transfer: a merge,
	// whose proof nests the second input's file.
	mergeTxid := send(
		secondTapd, t.tapd, firstAmount+secondAmount, 0, 0, 1,
	)
	transfers := map[chainhash.Hash]struct{}{
		firstTxid: {}, secondTxid: {}, mergeTxid: {},
	}

	listAssetRequest := &taprpc.ListAssetRequest{}
	received := func() *taprpc.Asset {
		assets, err := t.tapd.ListAssets(ctx, listAssetRequest)
		require.NoError(t.t, err)
		for _, a := range assets.Assets {
			if a.Amount == firstAmount+secondAmount {
				return a
			}
		}
		require.Fail(t.t, "received asset not listed")

		return nil
	}
	exportFile := func(a *taprpc.Asset) *proof.File {
		exportResp, err := t.tapd.ExportProof(
			ctx, &taprpc.ExportProofRequest{
				AssetId:   assetID,
				ScriptKey: a.ScriptKey,
			},
		)
		require.NoError(t.t, err)
		file, err := proof.Blob(exportResp.RawProofFile).AsFile()
		require.NoError(t.t, err)

		return file
	}

	// The received file nests the second input's history at its tip.
	merged := received()
	tip, err := exportFile(merged).LastProof()
	require.NoError(t.t, err)
	require.Len(t.t, tip.AdditionalInputs, 1)

	// The fork drops all three transfers; they return to the mempool
	// and both nodes stop listing the assets they anchor.
	generateReOrg(t.t, t.lndHarness, tempMiner, 5, 2)
	lndMiner.AssertNumTxsInMempool(3)

	_, tempMinerHeight := tempMiner.GetBestBlock()
	t.lndHarness.WaitForNodeBlockHeight(t.tapd.cfg.LndNode, tempMinerHeight)
	t.lndHarness.WaitForNodeBlockHeight(lndBob, tempMinerHeight)
	require.Eventually(t.t, func() bool {
		assets, err := t.tapd.ListAssets(ctx, listAssetRequest)
		return err == nil && len(assets.Assets) == 0
	}, defaultWaitTimeout, 200*time.Millisecond)

	// All three re-confirm in one block.
	newBlock := t.lndHarness.MineBlocksAndAssertNumTxes(1, 3)[0]
	_, newBlockHeight := lndMiner.GetBestBlock()
	t.Logf("Transfers re-mined in block %v", newBlock.BlockHash())

	require.Eventually(t.t, func() bool {
		assets, err := t.tapd.ListAssets(ctx, listAssetRequest)
		return err == nil && len(assets.Assets) == 2
	}, defaultWaitTimeout, 200*time.Millisecond)
	merged = received()
	WaitForProofUpdate(t.t, t.tapd, merged, newBlockHeight)

	// Every occurrence of a transfer in the received file, at any
	// depth, now sits in the new block: the merge at the tip, the
	// first send below it, and the first and second sends inside the
	// nested input file.
	var occurrences int
	var walk func(file *proof.File)
	walk = func(file *proof.File) {
		for idx := 0; idx < file.NumProofs(); idx++ {
			p, err := file.ProofAt(uint32(idx))
			require.NoError(t.t, err)
			for inputIdx := range p.AdditionalInputs {
				walk(&p.AdditionalInputs[inputIdx])
			}

			txid := p.AnchorTx.TxHash()
			if _, ok := transfers[txid]; !ok {
				continue
			}
			occurrences++
			require.EqualValues(
				t.t, newBlockHeight, p.BlockHeight,
				"transfer %v stale at depth %d", txid, idx,
			)
		}
	}
	walk(exportFile(merged))
	require.Equal(t.t, 4, occurrences)

	// The file verifies against the chain as it is now.
	aliceChainClient := t.tapd.cfg.LndNode.RPC.ChainKit
	AssertAssetProofs(t.t, t.tapd, aliceChainClient, merged)

	// Bury the transfers, then spend the whole holding on to Bob: the
	// repaired history, nested part included, is what Bob verifies.
	t.lndHarness.MineBlocks(8)
	send(t.tapd, secondTapd, minted.Amount, 0, 2, 3)
	AssertBalances(
		t.t, secondTapd, minted.Amount, WithAssetID(assetID),
		WithNumUtxos(1),
	)
	bobAssets, err := secondTapd.ListAssets(ctx, listAssetRequest)
	require.NoError(t.t, err)
	require.Len(t.t, bobAssets.Assets, 1)
	bobChainClient := secondTapd.cfg.LndNode.RPC.ChainKit
	AssertAssetProofs(t.t, secondTapd, bobChainClient, bobAssets.Assets[0])
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

// testReOrgSendConflictingSpend tests the different-transaction re-org
// shape: the transfer's anchor transaction confirms, a re-org orphans
// it (unwitnessed re-entry), and a conflicting transaction the porter
// did not broadcast then claims the transfer's asset input. While the
// conflicting spend sits at potency depth both anchorings report
// conflicted and nothing is compensated; once it buries at the safe
// depth, the chain has decided against the transfer with act-level
// finality: the sender's porter anchoring abandons and compensates
// (inputs un-spent, materialized outputs removed), and the receiver's
// anchoring follows, removing the received assets and resetting the
// address event.
func testReOrgSendConflictingSpend(t *harnessTest) {
	// First, we'll mint a few assets and confirm the batch TX.
	mintRequests := []*mintrpc.MintAssetRequest{
		issuableAssets[0], issuableAssets[1],
	}
	lndMiner := t.lndHarness.Miner()
	assetList := MintAssetsConfirmBatch(
		t.t, lndMiner, t.tapd, mintRequests, WithNoUniverseLeafWait(),
	)

	// Bury the mint: the re-org scenario under test targets the send
	// transaction, and the fork point must sit past the mint's
	// burial.
	t.lndHarness.MineBlocks(6)
	WaitForMintUniverseLeaves(t.t, t.tapd, assetList)

	ctx := context.Background()

	// Bob will receive the assets on a second tapd instance.
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

	// Both minted assets share one anchor UTXO, and the send below
	// will spend it. Craft the conflicting spend of that outpoint
	// now: a pure-BTC transaction claiming the anchor output for the
	// miner, to be mined on the re-org fork.
	utxos, err := t.tapd.ListUtxos(ctx, &taprpc.ListUtxosRequest{})
	require.NoError(t.t, err)
	require.Len(t.t, utxos.ManagedUtxos, 1)

	var anchorUtxo *taprpc.ManagedUtxo
	for outpoint := range utxos.ManagedUtxos {
		anchorUtxo = utxos.ManagedUtxos[outpoint]
	}
	conflictTx := craftConflictingSpend(t, anchorUtxo)

	// Before we mine a block to confirm the send TX, we create a
	// temporary miner: its fork will carry the conflicting spend.
	tempMiner := spawnTempMiner(t.t, t, ctx)

	// Send to Bob and confirm at one confirmation. The proof courier
	// fires at the potency tier, so Bob's receive completes without
	// waiting for burial.
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
	ConfirmAndAssertOutboundTransfer(
		t.t, lndMiner, t.tapd, sendResp, sendAssetGen.AssetId,
		[]uint64{sendAsset.Amount - sendAmount, sendAmount}, 0, 1,
	)
	AssertNonInteractiveRecvComplete(t.t, secondTapd, 1)

	// Both sides hold witnessed anchorings on the send now.
	assertAnchoringPhase(t.t, t.tapd, "tapfreighter.porter", "witnessed")
	assertAnchoringPhase(
		t.t, secondTapd, "tapcustody.receiver", "witnessed",
	)

	// Re-org the anchor transaction out: it returns to the mempool,
	// and with no spend of the trigger set on the dominant chain the
	// anchorings re-enter unwitnessed.
	generateReOrg(t.t, t.lndHarness, tempMiner, 3, 2)
	lndMiner.AssertNumTxsInMempool(1)

	_, tempMinerHeight := tempMiner.GetBestBlock()
	t.lndHarness.WaitForNodeBlockHeight(t.tapd.cfg.LndNode, tempMinerHeight)

	assertAnchoringPhase(t.t, t.tapd, "tapfreighter.porter", "unwitnessed")
	assertAnchoringPhase(
		t.t, secondTapd, "tapcustody.receiver", "unwitnessed",
	)

	// Now mine the conflicting spend. Connecting its block evicts the
	// orphaned anchor transaction from the mempool as a double spend:
	// the transfer can never confirm again.
	lndMiner.MineBlockWithTx(conflictTx)
	lndMiner.AssertNumTxsInMempool(0)

	// A foreign spend of the trigger set sits on the dominant chain:
	// both anchorings sense conflicted, and the potency-tier
	// downgrade unconfirms the transferred state without compensating
	// anything — the conflicting spend could itself re-org out.
	assertAnchoringPhase(t.t, t.tapd, "tapfreighter.porter", "conflicted")
	assertAnchoringPhase(
		t.t, secondTapd, "tapcustody.receiver", "conflicted",
	)

	listAssetRequest := &taprpc.ListAssetRequest{}
	aliceAssets, err := t.tapd.ListAssets(ctx, listAssetRequest)
	require.NoError(t.t, err)
	require.Empty(t.t, aliceAssets.Assets)
	require.EqualValues(t.t, 1, aliceAssets.UnconfirmedTransfers)

	bobAssets, err := secondTapd.ListAssets(ctx, listAssetRequest)
	require.NoError(t.t, err)
	require.Empty(t.t, bobAssets.Assets)

	AssertAddrEvent(t.t, secondTapd, bobAddr, 1, statusCompleted)

	// Restart the sender while the conflict sits at potency, before
	// any compensation: recovery must re-derive the conflicted
	// phase from the persisted candidates alone, without the live
	// subscriptions that observed it arise.
	t.t.Logf("Restarting sender in the conflicted window")
	require.NoError(t.t, t.tapd.stop(false))
	require.NoError(t.t, t.tapd.start(false))
	assertAnchoringPhase(t.t, t.tapd, "tapfreighter.porter", "conflicted")

	// Bury the conflicting spend at the safe depth: the chain's
	// decision against the transfer hardens into act, and both
	// anchorings abandon and compensate — the restarted daemon
	// carries its side through from recovered state.
	t.lndHarness.MineBlocks(6)

	assertAnchoringPhase(t.t, t.tapd, "tapfreighter.porter", "abandoned")
	assertAnchoringPhase(
		t.t, secondTapd, "tapcustody.receiver", "abandoned",
	)

	// The sender's compensation is bounded by the foreclosing
	// transaction: it claimed the anchor output carrying both the
	// transferred asset and the passive one, so the chain has given
	// those inputs away, and reviving them would report a balance
	// the sender no longer holds. Both stay spent, and no
	// unconfirmed transfer lingers.
	AssertBalances(t.t, t.tapd, 0, WithAssetID(sendAssetGen.AssetId))
	AssertBalances(
		t.t, t.tapd, 0,
		WithAssetID(assetList[1].AssetGenesis.AssetId),
	)

	aliceAssets, err = t.tapd.ListAssets(ctx, listAssetRequest)
	require.NoError(t.t, err)
	require.Empty(t.t, aliceAssets.Assets)
	require.EqualValues(t.t, 0, aliceAssets.UnconfirmedTransfers)

	// The receiver's compensation removes the materialized assets for
	// good and documents the failed receive: the address event
	// returns to the detected status.
	bobAssets, err = secondTapd.ListAssets(ctx, listAssetRequest)
	require.NoError(t.t, err)
	require.Empty(t.t, bobAssets.Assets)
	AssertAddrEvent(t.t, secondTapd, bobAddr, 1, statusDetected)
}

// assertAnchoringPhase waits until the given site's single anchoring
// reports the given phase, both sensed and delivered. Phase strings
// on the RPC surface are decorated with their evidence, so matching
// is by prefix.
func assertAnchoringPhase(t *testing.T, tapd *tapdHarness, site,
	phase string) {

	t.Helper()

	ctxb := context.Background()
	err := wait.NoError(func() error {
		resp, err := tapd.ListAnchorings(
			ctxb, &taprpc.ListAnchoringsRequest{Site: site},
		)
		if err != nil {
			return err
		}
		if len(resp.Anchorings) != 1 {
			return fmt.Errorf("expected 1 anchoring for site "+
				"%v, got %d", site, len(resp.Anchorings))
		}

		a := resp.Anchorings[0]
		if !strings.HasPrefix(a.Phase, phase) ||
			!strings.HasPrefix(a.DeliveredPhase, phase) {

			return fmt.Errorf("anchoring %d: phase %v "+
				"(delivered %v), want %v", a.Id, a.Phase,
				a.DeliveredPhase, phase)
		}

		return nil
	}, defaultWaitTimeout)
	require.NoError(t, err)
}

// craftConflictingSpend builds and signs a pure-BTC transaction that
// spends the given managed anchor UTXO to a miner address, signed
// through lnd with the anchor output's taproot tweak. The result
// conflicts with any transfer spending the same anchor outpoint.
func craftConflictingSpend(t *harnessTest,
	utxo *taprpc.ManagedUtxo) *wire.MsgTx {

	lndMiner := t.lndHarness.Miner()
	lndRPC := t.tapd.cfg.LndNode.RPC

	op, err := wire.NewOutPointFromString(utxo.OutPoint)
	require.NoError(t.t, err)

	prevTx := lndMiner.GetRawTransaction(op.Hash)
	prevOut := prevTx.MsgTx().TxOut[op.Index]

	// Recover the anchor internal key's locator: tapd derived it from
	// lnd's taproot-assets key family, so a scan over the first
	// indices finds it.
	var keyLoc *signrpc.KeyLocator
	for idx := int32(0); idx < 50; idx++ {
		desc := lndRPC.DeriveKey(&signrpc.KeyLocator{
			KeyFamily: asset.TaprootAssetsKeyFamily,
			KeyIndex:  idx,
		})
		if bytes.Equal(desc.RawKeyBytes, utxo.InternalKey) {
			keyLoc = &signrpc.KeyLocator{
				KeyFamily: asset.TaprootAssetsKeyFamily,
				KeyIndex:  idx,
			}

			break
		}
	}
	require.NotNil(t.t, keyLoc, "anchor internal key not found in "+
		"taproot-assets key family")

	// One input (the anchor outpoint), one output paying the miner.
	minerAddr := lndMiner.NewMinerAddress()
	minerScript, err := txscript.PayToAddrScript(minerAddr)
	require.NoError(t.t, err)

	const fee = 500
	conflictTx := wire.NewMsgTx(2)
	conflictTx.AddTxIn(&wire.TxIn{PreviousOutPoint: *op})
	conflictTx.AddTxOut(wire.NewTxOut(prevOut.Value-fee, minerScript))

	var txBuf bytes.Buffer
	require.NoError(t.t, conflictTx.Serialize(&txBuf))

	signResp := lndRPC.SignOutputRaw(&signrpc.SignReq{
		RawTxBytes: txBuf.Bytes(),
		SignDescs: []*signrpc.SignDescriptor{{
			KeyDesc: &signrpc.KeyDescriptor{
				KeyLoc: keyLoc,
			},
			TapTweak: utxo.MerkleRoot,
			Output: &signrpc.TxOut{
				Value:    prevOut.Value,
				PkScript: prevOut.PkScript,
			},
			InputIndex: 0,
			SignMethod: signrpc.
				SignMethod_SIGN_METHOD_TAPROOT_KEY_SPEND,
		}},
		PrevOutputs: []*signrpc.TxOut{{
			Value:    prevOut.Value,
			PkScript: prevOut.PkScript,
		}},
	})
	conflictTx.TxIn[0].Witness = wire.TxWitness{signResp.RawSigs[0]}

	return conflictTx
}

// testReOrgSupplyCommit tests the supply-commit site across a re-org:
// the commit transaction confirms, is re-organized out (potency-tier
// only: nothing is finalized or retracted while it can re-confirm),
// re-confirms in a new block, and buries at the safe depth — at which
// point, and only at which point, the commitment finalizes, carrying
// the re-organized confirmation's block context.
func testReOrgSupplyCommit(t *harnessTest) {
	ctxb := context.Background()
	lndMiner := t.lndHarness.Miner()

	// Mint a grouped asset with supply commitments enabled, and bury
	// the mint at the test's safe depth of 3: universe publication
	// and the mint's supply events are act-gated on its burial, and
	// the re-org under test targets the supply commit transaction.
	mintReq := CopyRequest(issuableAssets[0])
	mintReq.Asset.EnableSupplyCommitments = true
	assetList := MintAssetsConfirmBatch(
		t.t, lndMiner, t.tapd, []*mintrpc.MintAssetRequest{mintReq},
		WithNoUniverseLeafWait(),
	)
	require.Len(t.t, assetList, 1)
	rpcAsset := assetList[0]
	t.lndHarness.MineBlocks(3)
	WaitForMintUniverseLeaves(t.t, t.tapd, assetList)

	groupKeyBytes := rpcAsset.AssetGroup.TweakedGroupKey
	require.NotNil(t.t, groupKeyBytes)

	// An ignore entry gives the next commitment something to commit.
	ignoreAmt := rpcAsset.Amount
	respIgnore, err := t.tapd.IgnoreAssetOutPoint(
		ctxb, &unirpc.IgnoreAssetOutPointRequest{
			AssetOutPoint: &taprpc.AssetOutPoint{
				AnchorOutPoint: rpcAsset.ChainAnchor.
					AnchorOutpoint,
				AssetId:   rpcAsset.AssetGenesis.AssetId,
				ScriptKey: rpcAsset.ScriptKey,
			},
			Amount: ignoreAmt,
		},
	)
	require.NoError(t.t, err)
	require.NotNil(t.t, respIgnore)

	// The fork point: the commit transaction confirms past here.
	tempMiner := spawnTempMiner(t.t, t, ctxb)

	// Kick off the commitment and confirm its transaction once.
	groupKeyReq := &unirpc.UpdateSupplyCommitRequest_GroupKeyBytes{
		GroupKeyBytes: groupKeyBytes,
	}
	respUpdate, err := t.tapd.UpdateSupplyCommit(
		ctxb, &unirpc.UpdateSupplyCommitRequest{GroupKey: groupKeyReq},
	)
	require.NoError(t.t, err)
	require.NotNil(t.t, respUpdate)
	MineBlocks(t.t, lndMiner, 1, 1)

	// One confirmation is potency, not act: the anchoring is
	// witnessed, and no commitment is finalized yet.
	assertAnchoringPhase(
		t.t, t.tapd, "supplycommit.committer", "witnessed",
	)
	fetchReq := &unirpc.FetchSupplyCommitRequest{
		GroupKey: &unirpc.FetchSupplyCommitRequest_GroupKeyBytes{
			GroupKeyBytes: groupKeyBytes,
		},
		Locator: &unirpc.FetchSupplyCommitRequest_VeryFirst{
			VeryFirst: true,
		},
	}

	// The commitment row is staged at broadcast but carries no block
	// info until the burial handler finalizes it, so a fetch in this
	// window fails rather than serving unconfirmed chain data.
	_, err = t.tapd.FetchSupplyCommit(ctxb, fetchReq)
	require.ErrorContains(t.t, err, "no block info available")

	// Re-org the confirmation out: the commit transaction returns
	// to the mempool, and the anchoring honestly reports
	// unwitnessed. Still nothing finalized, nothing retracted.
	generateReOrg(t.t, t.lndHarness, tempMiner, 3, 2)
	lndMiner.AssertNumTxsInMempool(1)

	_, tempMinerHeight := tempMiner.GetBestBlock()
	t.lndHarness.WaitForNodeBlockHeight(
		t.tapd.cfg.LndNode, tempMinerHeight,
	)

	assertAnchoringPhase(
		t.t, t.tapd, "supplycommit.committer", "unwitnessed",
	)
	_, err = t.tapd.FetchSupplyCommit(ctxb, fetchReq)
	require.ErrorContains(t.t, err, "no block info available")

	// The commit transaction re-confirms in a new block and buries
	// at the safe depth: the commitment finalizes now, with the
	// re-organized confirmation's block context.
	newBlock := t.lndHarness.MineBlocksAndAssertNumTxes(1, 1)[0]
	newBlockHash := newBlock.BlockHash()
	_, newBlockHeight := lndMiner.GetBestBlock()

	assertAnchoringPhase(
		t.t, t.tapd, "supplycommit.committer", "witnessed",
	)

	t.lndHarness.MineBlocks(2)
	assertAnchoringPhase(
		t.t, t.tapd, "supplycommit.committer", "buried",
	)

	fetchResp, _ := WaitForSupplyCommit(
		t.t, ctxb, t.tapd, groupKeyBytes, fn.None[wire.OutPoint](),
		func(resp *unirpc.FetchSupplyCommitResponse) bool {
			return resp.ChainData.BlockHeight > 0 &&
				len(resp.ChainData.BlockHash) > 0
		},
	)
	require.Equal(
		t.t, newBlockHash[:], fetchResp.ChainData.BlockHash,
	)
	require.EqualValues(
		t.t, newBlockHeight, fetchResp.ChainData.BlockHeight,
	)

	// The finalized commitment carries the ignore entry.
	require.NotNil(t.t, fetchResp.IgnoreSubtreeRoot)
	require.EqualValues(
		t.t, ignoreAmt, fetchResp.IgnoreSubtreeRoot.RootNode.RootSum,
	)
}

// testReOrgGenesisReceive tests the genesis-shape receive across a
// re-org: an asset minted directly to the receiver's script key
// arrives as a single-proof file, which has no prior asset outpoint
// to watch — the receive anchoring seeds the genesis transaction
// itself as its candidate. The genesis is then re-orged out (the
// seeded anchoring honestly downgrades and the materialized asset
// disappears), re-confirms in a new block (the anchoring re-witnesses
// and the proof re-stamps), and buries at the receiver's safe depth.
func testReOrgGenesisReceive(t *harnessTest) {
	ctx := context.Background()
	lndMiner := t.lndHarness.Miner()

	// Bob's node holds the script key the mint below commits to.
	// His deeper safe depth keeps the receive anchoring at the
	// potency tier through the re-org window. NewNodeWithCoins
	// mines blocks, so it must precede the fork point.
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

	bobScriptKey, _ := DeriveKeys(t.t, secondTapd)

	// The fork point: the genesis confirmation lies past it.
	tempMiner := spawnTempMiner(t.t, t, ctx)

	// Alice mints directly to Bob's script key and buries the batch
	// at her safe depth of 3 (universe publication is act-gated on
	// that burial).
	mintReq := CopyRequest(simpleAssets[0])
	mintReq.Asset.ScriptKey = rpcutils.MarshalScriptKey(bobScriptKey)
	assetList := MintAssetsConfirmBatch(
		t.t, lndMiner, t.tapd, []*mintrpc.MintAssetRequest{mintReq},
		WithNoUniverseLeafWait(),
	)
	require.Len(t.t, assetList, 1)
	mintedAsset := assetList[0]
	assetID := mintedAsset.AssetGenesis.AssetId
	t.lndHarness.MineBlocks(2)
	WaitForMintUniverseLeaves(t.t, t.tapd, assetList)

	// Bob learns of the mint out of band: Alice exports the
	// single-proof genesis file and Bob registers the transfer,
	// which imports the proof, materializes the asset and stakes
	// the seeded receive anchoring.
	bobScriptKeyBytes := bobScriptKey.PubKey.SerializeCompressed()
	exportResp, err := t.tapd.ExportProof(
		ctx, &taprpc.ExportProofRequest{
			AssetId:   assetID,
			ScriptKey: bobScriptKeyBytes,
		},
	)
	require.NoError(t.t, err)
	ImportProofFile(t, secondTapd, exportResp.RawProofFile)

	// The genesis sits at depth 3, short of Bob's safe depth of 6:
	// the seeded anchoring is witnessed, and the asset shows.
	assertAnchoringPhase(
		t.t, secondTapd, "tapcustody.receiver", "witnessed",
	)
	AssertBalances(
		t.t, secondTapd, mintedAsset.Amount, WithAssetID(assetID),
		WithNumUtxos(1), WithScriptKeyType(asset.ScriptKeyBip86),
	)

	// Re-org the genesis out: the mint transaction returns to the
	// mempool, and with the seed off-chain and no trigger outpoint
	// to say anything else, Bob's anchoring honestly reports
	// unwitnessed and the materialized asset hides.
	generateReOrg(t.t, t.lndHarness, tempMiner, 6, 3)
	lndMiner.AssertNumTxsInMempool(1)

	_, tempMinerHeight := tempMiner.GetBestBlock()
	t.lndHarness.WaitForNodeBlockHeight(
		t.tapd.cfg.LndNode, tempMinerHeight,
	)
	t.lndHarness.WaitForNodeBlockHeight(lndBob, tempMinerHeight)

	assertAnchoringPhase(
		t.t, secondTapd, "tapcustody.receiver", "unwitnessed",
	)
	bobAssets, err := secondTapd.ListAssets(
		ctx, &taprpc.ListAssetRequest{},
	)
	require.NoError(t.t, err)
	require.Empty(t.t, bobAssets.Assets)

	// Alice's mint anchoring buried at depth 3 and the re-org
	// rewrote its evidence: a re-org past the safe depth is outside
	// the watcher's contract, so the anchoring stays buried, while
	// Bob's live anchoring simply re-derives, the same event treated
	// per anchoring by its own threshold.
	assertAnchoringPhase(t.t, t.tapd, "tapgarden.minter", "buried")

	// The genesis re-confirms in a new block: Bob's anchoring
	// re-witnesses and the tip proof re-stamps with the new block.
	t.lndHarness.MineBlocksAndAssertNumTxes(1, 1)
	_, newBlockHeight := lndMiner.GetBestBlock()

	assertAnchoringPhase(
		t.t, secondTapd, "tapcustody.receiver", "witnessed",
	)
	require.Eventually(t.t, func() bool {
		bobAssets, err = secondTapd.ListAssets(
			ctx, &taprpc.ListAssetRequest{},
		)
		return err == nil && len(bobAssets.Assets) == 1
	}, defaultWaitTimeout, 200*time.Millisecond)
	WaitForProofUpdate(
		t.t, secondTapd, bobAssets.Assets[0], newBlockHeight,
	)
	AssertAssetProofs(
		t.t, secondTapd, secondTapd.cfg.LndNode.RPC.ChainKit,
		bobAssets.Assets[0],
	)

	// Burial at Bob's safe depth settles the receive.
	t.lndHarness.MineBlocks(5)
	assertAnchoringPhase(
		t.t, secondTapd, "tapcustody.receiver", "buried",
	)
}
