package itest

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/lightninglabs/taproot-assets/chanutils"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"
	"golang.org/x/net/http2"
	"google.golang.org/protobuf/proto"
)

var (
	zeroHash chainhash.Hash

	simpleAssets = []*mintrpc.MintAssetRequest{
		{
			Asset: &mintrpc.MintAsset{
				AssetType: taprpc.AssetType_NORMAL,
				Name:      "itestbuxx",
				AssetMeta: &taprpc.AssetMeta{
					Data: []byte("some metadata"),
				},
				Amount: 5000,
			},
		},
		{
			Asset: &mintrpc.MintAsset{
				AssetType: taprpc.AssetType_COLLECTIBLE,
				Name:      "itestbuxx-collectible",
				AssetMeta: &taprpc.AssetMeta{
					Data: []byte("some metadata"),
				},
				Amount: 1,
			},
		},
	}
	issuableAssets = []*mintrpc.MintAssetRequest{
		{
			Asset: &mintrpc.MintAsset{
				AssetType: taprpc.AssetType_NORMAL,
				Name:      "itestbuxx-money-printer-brrr",
				AssetMeta: &taprpc.AssetMeta{
					Data: []byte("some metadata"),
				},
				Amount: 5000,
			},
			EnableEmission: true,
		},
		{
			Asset: &mintrpc.MintAsset{
				AssetType: taprpc.AssetType_COLLECTIBLE,
				Name:      "itestbuxx-collectible-brrr",
				AssetMeta: &taprpc.AssetMeta{
					Data: []byte("some metadata"),
				},
				Amount: 1,
			},
			EnableEmission: true,
		},
	}

	transport = &http2.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	client = http.Client{
		Transport: transport,
		Timeout:   1 * time.Second,
	}
)

// copyRequest is a helper function to copy a request so that we can modify it.
func copyRequest(req *mintrpc.MintAssetRequest) *mintrpc.MintAssetRequest {
	return proto.Clone(req).(*mintrpc.MintAssetRequest)
}

// copyRequests is a helper function to copy a slice of requests so that we can
// modify them.
func copyRequests(reqs []*mintrpc.MintAssetRequest) []*mintrpc.MintAssetRequest {
	copied := make([]*mintrpc.MintAssetRequest, len(reqs))
	for idx := range reqs {
		copied[idx] = copyRequest(reqs[idx])
	}
	return copied
}

// testMintAssets tests that we're able to mint assets, retrieve their proofs
// and that we're able to import the proofs into a new node.
func testMintAssets(t *harnessTest) {
	rpcSimpleAssets := mintAssetsConfirmBatch(t, t.tapd, simpleAssets)
	rpcIssuableAssets := mintAssetsConfirmBatch(t, t.tapd, issuableAssets)

	// Now that all our assets have been issued, we'll use the balance
	// calls to ensure that we're able to retrieve the proper balance for
	// them all.
	assertAssetBalances(t, rpcSimpleAssets, rpcIssuableAssets)

	// Check that we can retrieve the group keys for the issuable assets.
	assertGroups(t, issuableAssets)

	// Make sure the proof files for the freshly minted assets can be
	// retrieved and are fully valid.
	var allAssets []*taprpc.Asset
	allAssets = append(allAssets, rpcSimpleAssets...)
	allAssets = append(allAssets, rpcIssuableAssets...)
	for _, mintedAsset := range allAssets {
		assertAssetProofs(t.t, t.tapd, mintedAsset)
	}

	// Let's now create a new node and import all assets into that new node.
	charlie := t.lndHarness.NewNode("charlie", lndDefaultArgs)
	secondTapd := setupTapdHarness(
		t.t, t, charlie, t.universeServer,
	)
	defer shutdownAndAssert(t, charlie, secondTapd)

	// We import the assets into a node that doesn't have the keys to spend
	// them, so we don't expect them to show up with script_key_is_local set
	// to true in the list of assets.
	transferAssetProofs(t, t.tapd, secondTapd, allAssets, false)
}

// mintAssetsConfirmBatch mints all given assets in the same batch, confirms the
// batch and verifies all asset proofs of the minted assets.
func mintAssetsConfirmBatch(t *harnessTest, tapd *tapdHarness,
	assetRequests []*mintrpc.MintAssetRequest) []*taprpc.Asset {

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// Mint all the assets in the same batch.
	for _, assetRequest := range assetRequests {
		assetResp, err := tapd.MintAsset(ctxt, assetRequest)
		require.NoError(t.t, err)
		require.NotEmpty(t.t, assetResp.BatchKey)
	}

	// Instruct the daemon to finalize the batch.
	batchResp, err := tapd.FinalizeBatch(
		ctxt, &mintrpc.FinalizeBatchRequest{},
	)
	require.NoError(t.t, err)
	require.NotEmpty(t.t, batchResp.BatchKey)

	hashes, err := waitForNTxsInMempool(
		t.lndHarness.Miner.Client, 1, defaultWaitTimeout,
	)
	require.NoError(t.t, err)

	// Make sure the assets were all minted within the same anchor but don't
	// yet have a block hash associated with them.
	for _, assetRequest := range assetRequests {
		metaHash := (&proof.MetaReveal{
			Data: assetRequest.Asset.AssetMeta.Data,
		}).MetaHash()
		assertAssetState(
			t, tapd, assetRequest.Asset.Name,
			metaHash[:],
			assetAmountCheck(assetRequest.Asset.Amount),
			assetTypeCheck(assetRequest.Asset.AssetType),
			assetAnchorCheck(*hashes[0], zeroHash),
			assetScriptKeyIsLocalCheck(true),
		)
	}

	// Mine a block to confirm the assets.
	block := mineBlocks(t, t.lndHarness, 1, 1)[0]
	blockHash := block.BlockHash()

	// The rest of the anchor information should now be populated as well.
	// We also check that the anchor outpoint of all assets is the same,
	// since they were all minted in the same batch.
	var (
		firstOutpoint string
		assetList     []*taprpc.Asset
	)
	for _, assetRequest := range assetRequests {
		metaHash := (&proof.MetaReveal{
			Data: assetRequest.Asset.AssetMeta.Data,
		}).MetaHash()
		mintedAsset := assertAssetState(
			t, tapd, assetRequest.Asset.Name, metaHash[:],
			assetAnchorCheck(*hashes[0], blockHash),
			assetScriptKeyIsLocalCheck(true),
			func(a *taprpc.Asset) error {
				anchor := a.ChainAnchor

				if anchor.AnchorOutpoint == "" {
					return fmt.Errorf("missing anchor " +
						"outpoint")
				}

				if firstOutpoint == "" {
					firstOutpoint = anchor.AnchorOutpoint

					return nil
				}

				if anchor.AnchorOutpoint != firstOutpoint {
					return fmt.Errorf("unexpected anchor "+
						"outpoint, got %v wanted %v",
						anchor.AnchorOutpoint,
						firstOutpoint)
				}

				return nil
			},
		)

		assetList = append(assetList, mintedAsset)
	}

	return assetList
}

// transferAssetProofs locates and exports the proof files for all given assets
// from the source node and imports them into the destination node.
func transferAssetProofs(t *harnessTest, src, dst *tapdHarness,
	assets []*taprpc.Asset, shouldShowUpAsLocal bool) {

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// TODO(roasbeef): modify import call, can't work as is
	//  * proof file only contains the tweaked script key
	//  * from that we don't know the internal key
	//  * we can import the proof but it's useless as is, but lets this
	//  itest work

	for _, existingAsset := range assets {
		gen := existingAsset.AssetGenesis
		proofFile := assertAssetProofs(t.t, src, existingAsset)
		_, err := dst.ImportProof(ctxt, &taprpc.ImportProofRequest{
			ProofFile:    proofFile,
			GenesisPoint: gen.GenesisPoint,
		})
		require.NoError(t.t, err)

		anchorTxHash, err := chainhash.NewHashFromStr(
			existingAsset.ChainAnchor.AnchorTxid,
		)
		require.NoError(t.t, err)
		anchorBlockHash, err := chainhash.NewHash(
			existingAsset.ChainAnchor.AnchorBlockHash,
		)
		require.NoError(t.t, err)

		assertAssetState(
			t, dst, gen.Name, gen.MetaHash,
			assetAmountCheck(existingAsset.Amount),
			assetTypeCheck(existingAsset.AssetType),
			assetAnchorCheck(*anchorTxHash, *anchorBlockHash),
			assetScriptKeyIsLocalCheck(shouldShowUpAsLocal),
		)
	}
}

func assertAssetBalances(t *harnessTest,
	simpleAssets, issuableAssets []*taprpc.Asset) {

	t.t.Helper()

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// First, we'll ensure that we're able to get the balances of all the
	// assets grouped by their asset IDs.
	balanceReq := &taprpc.ListBalancesRequest_AssetId{
		AssetId: true,
	}
	assetIDBalances, err := t.tapd.ListBalances(
		ctxt, &taprpc.ListBalancesRequest{
			GroupBy: balanceReq,
		},
	)
	require.NoError(t.t, err)

	var allAssets []*taprpc.Asset
	allAssets = append(allAssets, simpleAssets...)
	allAssets = append(allAssets, issuableAssets...)

	require.Equal(t.t, len(allAssets), len(assetIDBalances.AssetBalances))

	for _, balance := range assetIDBalances.AssetBalances {
		for _, rpcAsset := range allAssets {
			if balance.AssetGenesis.Name == rpcAsset.AssetGenesis.Name {
				require.Equal(
					t.t, balance.Balance, rpcAsset.Amount,
				)
				require.Equal(
					t.t,
					balance.AssetGenesis,
					rpcAsset.AssetGenesis,
				)
			}
		}
	}

	// We'll also ensure that we're able to get the balance by key group
	// for all the assets that have one specified.
	groupBalanceReq := &taprpc.ListBalancesRequest_GroupKey{
		GroupKey: true,
	}
	assetGroupBalances, err := t.tapd.ListBalances(
		ctxt, &taprpc.ListBalancesRequest{
			GroupBy: groupBalanceReq,
		},
	)
	require.NoError(t.t, err)

	require.Equal(
		t.t, len(issuableAssets),
		len(assetGroupBalances.AssetGroupBalances),
	)

	for _, balance := range assetGroupBalances.AssetBalances {
		for _, rpcAsset := range issuableAssets {
			if balance.AssetGenesis.Name == rpcAsset.AssetGenesis.Name {
				require.Equal(
					t.t, balance.Balance, rpcAsset.Amount,
				)
				require.Equal(
					t.t,
					balance.AssetGenesis,
					rpcAsset.AssetGenesis,
				)
			}
		}
	}
}

func assertGroups(t *harnessTest, issuableAssets []*mintrpc.MintAssetRequest) {
	t.t.Helper()

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// We should be able to fetch two groups of one asset each.
	assetGroups, err := t.tapd.ListGroups(
		ctxt, &taprpc.ListGroupsRequest{},
	)
	require.NoError(t.t, err)

	groupKeys := maps.Keys(assetGroups.Groups)
	require.Equal(t.t, 2, len(groupKeys))

	groupedAssets := assetGroups.Groups[groupKeys[0]].Assets
	require.Equal(t.t, 1, len(groupedAssets))
	require.Equal(t.t, 1, len(assetGroups.Groups[groupKeys[1]].Assets))

	groupedAssets = append(
		groupedAssets, assetGroups.Groups[groupKeys[1]].Assets[0],
	)

	// Sort the listed assets to match the order of issuableAssets.
	sort.Slice(groupedAssets, func(i, j int) bool {
		return groupedAssets[i].Amount > groupedAssets[j].Amount
	})

	equalityCheck := func(a *mintrpc.MintAsset,
		b *taprpc.AssetHumanReadable) {

		metaHash := (&proof.MetaReveal{
			Data: a.AssetMeta.Data,
		}).MetaHash()

		require.Equal(t.t, a.AssetType, b.Type)
		require.Equal(t.t, a.Name, b.Tag)

		require.Equal(t.t, metaHash[:], b.MetaHash)
		require.Equal(t.t, a.Amount, b.Amount)
	}

	equalityCheck(issuableAssets[0].Asset, groupedAssets[0])
	equalityCheck(issuableAssets[1].Asset, groupedAssets[1])
}

// testMintAssetNameCollisionError tests that no error is produced when
// attempting to mint an asset whose name collides with an existing minted asset
// or an asset from a cancelled minting batch. An error should be produced
// when asset names collide within the same minting batch.
func testMintAssetNameCollisionError(t *harnessTest) {
	// Asset name which will be common between minted asset and colliding
	// asset.
	commonAssetName := "test-asset-name"

	// Define and mint a single asset.
	assetMint := mintrpc.MintAssetRequest{
		Asset: &mintrpc.MintAsset{
			AssetType: taprpc.AssetType_NORMAL,
			Name:      commonAssetName,
			AssetMeta: &taprpc.AssetMeta{
				Data: []byte("metadata-1"),
			},
			Amount: 5000,
		},
	}
	rpcSimpleAssets := mintAssetsConfirmBatch(
		t, t.tapd, []*mintrpc.MintAssetRequest{&assetMint},
	)

	// Ensure minted asset with requested name was successfully minted.
	mintedAssetName := rpcSimpleAssets[0].AssetGenesis.Name
	require.Equal(t.t, commonAssetName, mintedAssetName)

	// Attempt to mint another asset whose name should collide with the
	// existing minted asset. No other fields should collide.
	assetCollide := mintrpc.MintAssetRequest{
		Asset: &mintrpc.MintAsset{
			AssetType: taprpc.AssetType_COLLECTIBLE,
			Name:      commonAssetName,
			AssetMeta: &taprpc.AssetMeta{
				Data: []byte("metadata-2"),
			},
			Amount: 1,
		},
	}

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	equalityCheck := func(a, b *mintrpc.MintAsset) {
		require.Equal(t.t, a.AssetType, b.AssetType)
		require.Equal(t.t, a.Name, b.Name)
		require.Equal(t.t, a.AssetMeta.Data, b.AssetMeta.Data)
		require.Equal(t.t, a.Amount, b.Amount)
		require.Equal(t.t, a.GroupKey, b.GroupKey)
	}

	// If we attempt to add both assets to the same batch, the second mint
	// call should fail.
	collideBatchKey, err := t.tapd.MintAsset(ctxt, &assetCollide)
	require.NoError(t.t, err)
	require.NotNil(t.t, collideBatchKey.BatchKey)

	_, batchNameErr := t.tapd.MintAsset(ctxt, &assetMint)
	require.ErrorContains(t.t, batchNameErr, "already in batch")

	// If we cancel the batch, we should still be able to fetch it from the
	// daemon, and be able to refer to it by the batch key.
	rpcBatches, err := t.tapd.ListBatches(
		ctxt, &mintrpc.ListBatchRequest{},
	)
	require.NoError(t.t, err)

	allBatches := rpcBatches.Batches
	require.Len(t.t, allBatches, 2)

	isCollidingBatch := func(batch *mintrpc.MintingBatch) bool {
		if len(batch.Assets) == 0 {
			return false
		}

		return batch.Assets[0].AssetType == taprpc.AssetType_COLLECTIBLE
	}
	batchCollide, err := chanutils.First(allBatches, isCollidingBatch)
	require.NoError(t.t, err)

	require.Len(t.t, batchCollide.Assets, 1)
	equalityCheck(assetCollide.Asset, batchCollide.Assets[0])

	cancelBatchKey, err := t.tapd.CancelBatch(
		ctxt, &mintrpc.CancelBatchRequest{},
	)
	require.NoError(t.t, err)
	require.Equal(t.t, cancelBatchKey.BatchKey, collideBatchKey.BatchKey)

	// The only change in the returned batch after cancellation should be
	// the batch state.
	cancelBatch, err := t.tapd.ListBatches(
		ctxt, &mintrpc.ListBatchRequest{
			Filter: &mintrpc.ListBatchRequest_BatchKey{
				BatchKey: collideBatchKey.BatchKey,
			},
		})
	require.NoError(t.t, err)

	require.Len(t.t, cancelBatch.Batches, 1)
	cancelBatchCollide := cancelBatch.Batches[0]
	require.Len(t.t, cancelBatchCollide.Assets, 1)
	equalityCheck(batchCollide.Assets[0], cancelBatchCollide.Assets[0])
	cancelBatchState := cancelBatchCollide.State
	require.Equal(
		t.t, cancelBatchState,
		mintrpc.BatchState_BATCH_STATE_SEEDLING_CANCELLED,
	)

	// Minting the asset with the name collision should work, even though
	// it is also part of a cancelled batch.
	rpcCollideAsset := mintAssetsConfirmBatch(
		t, t.tapd, []*mintrpc.MintAssetRequest{&assetCollide},
	)

	collideAssetName := rpcCollideAsset[0].AssetGenesis.Name
	require.Equal(t.t, commonAssetName, collideAssetName)
}
