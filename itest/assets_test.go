package itest

import (
	"context"
	"fmt"
	"sort"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/lightninglabs/taro/tarogarden"
	"github.com/lightninglabs/taro/tarorpc"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"
	"google.golang.org/protobuf/proto"
)

var (
	zeroHash chainhash.Hash

	simpleAssets = []*tarorpc.MintAssetRequest{
		{
			AssetType: tarorpc.AssetType_NORMAL,
			Name:      "itestbuxx",
			MetaData:  []byte("some metadata for the itest assets"),
			Amount:    5000,
		},
		{
			AssetType: tarorpc.AssetType_COLLECTIBLE,
			Name:      "itestbuxx-collectible",
			MetaData:  []byte("some metadata for the itest assets"),
			Amount:    1,
		},
	}
	issuableAssets = []*tarorpc.MintAssetRequest{
		{
			AssetType:      tarorpc.AssetType_NORMAL,
			Name:           "itestbuxx-money-printer-brrr",
			MetaData:       []byte("some metadata"),
			Amount:         5000,
			EnableEmission: true,
		},
		{
			AssetType:      tarorpc.AssetType_COLLECTIBLE,
			Name:           "itestbuxx-collectible-brrr",
			MetaData:       []byte("some metadata"),
			Amount:         1,
			EnableEmission: true,
		},
	}
)

// copyRequest is a helper function to copy a request so that we can modify it.
func copyRequest(req *tarorpc.MintAssetRequest) *tarorpc.MintAssetRequest {
	return proto.Clone(req).(*tarorpc.MintAssetRequest)
}

// copyRequests is a helper function to copy a slice of requests so that we can
// modify them.
func copyRequests(reqs []*tarorpc.MintAssetRequest) []*tarorpc.MintAssetRequest {
	copied := make([]*tarorpc.MintAssetRequest, len(reqs))
	for idx := range reqs {
		copied[idx] = copyRequest(reqs[idx])
	}
	return copied
}

func mintAssets(t *harnessTest) {
	rpcSimpleAssets := mintAssetsConfirmBatch(t, t.tarod, simpleAssets)
	rpcIssuableAssets := mintAssetsConfirmBatch(t, t.tarod, issuableAssets)

	// Now that all our assets have been issued, we'll use the balance
	// calls to ensure that we're able to retrieve the proper balance for
	// them all.
	assertAssetBalances(t, rpcSimpleAssets, rpcIssuableAssets)

	// Check that we can retrieve the group keys for the issuable assets.
	assertGroups(t, issuableAssets)

	// Make sure the proof files for the freshly minted assets can be
	// retrieved and are fully valid.
	var allAssets []*tarorpc.Asset
	allAssets = append(allAssets, rpcSimpleAssets...)
	allAssets = append(allAssets, rpcIssuableAssets...)
	for _, mintedAsset := range allAssets {
		assertAssetProofs(t.t, t.tarod, mintedAsset)
	}

	// Let's now create a new node and import all assets into that new node.
	charlie := t.lndHarness.NewNode(t.t, "charlie", lndDefaultArgs)
	secondTarod := setupTarodHarness(
		t.t, t, t.lndHarness.BackendCfg, charlie, t.universeServer,
	)
	defer shutdownAndAssert(t, charlie, secondTarod)

	transferAssetProofs(t, t.tarod, secondTarod, allAssets)
}

// mintAssetsConfirmBatch mints all given assets in the same batch, confirms the
// batch and verifies all asset proofs of the minted assets.
func mintAssetsConfirmBatch(t *harnessTest, tarod *tarodHarness,
	assetRequests []*tarorpc.MintAssetRequest) []*tarorpc.Asset {

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// Mint all the assets in the same batch.
	for idx, assetRequest := range assetRequests {
		// Trigger a new batch with the last asset. The name SkipBatch
		// is a bit misleading in this context. It basically means:
		// Don't allow adding more assets to the batch, ship it now.
		if idx == len(assetRequests)-1 {
			assetRequest.SkipBatch = true
		}

		assetResp, err := tarod.MintAsset(ctxt, assetRequest)
		require.NoError(t.t, err)
		require.NotEmpty(t.t, assetResp.BatchKey)
	}

	hashes, err := waitForNTxsInMempool(
		t.lndHarness.Miner.Client, 1, defaultWaitTimeout,
	)
	require.NoError(t.t, err)

	// Make sure the assets were all minted within the same anchor but don't
	// yet have a block hash associated with them.
	for _, assetRequest := range assetRequests {
		assertAssetState(
			t, tarod, assetRequest.Name, assetRequest.MetaData,
			assetAmountCheck(assetRequest.Amount),
			assetTypeCheck(assetRequest.AssetType),
			assetAnchorCheck(*hashes[0], zeroHash),
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
		assetList     []*tarorpc.Asset
	)
	for _, assetRequest := range assetRequests {
		mintedAsset := assertAssetState(
			t, tarod, assetRequest.Name, assetRequest.MetaData,
			assetAnchorCheck(*hashes[0], blockHash),
			func(a *tarorpc.Asset) error {
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
func transferAssetProofs(t *harnessTest, src, dst *tarodHarness,
	assets []*tarorpc.Asset) {

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
		_, err := dst.ImportProof(ctxt, &tarorpc.ImportProofRequest{
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
			t, dst, gen.Name, gen.Meta,
			assetAmountCheck(existingAsset.Amount),
			assetTypeCheck(existingAsset.AssetType),
			assetAnchorCheck(*anchorTxHash, *anchorBlockHash),
		)
	}
}

func assertAssetBalances(t *harnessTest,
	simpleAssets, issuableAssets []*tarorpc.Asset) {

	t.t.Helper()

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// First, we'll ensure that we're able to get the balances of all the
	// assets grouped by their asset IDs.
	balanceReq := &tarorpc.ListBalancesRequest_AssetId{
		AssetId: true,
	}
	assetIDBalances, err := t.tarod.ListBalances(
		ctxt, &tarorpc.ListBalancesRequest{
			GroupBy: balanceReq,
		},
	)
	require.NoError(t.t, err)

	var allAssets []*tarorpc.Asset
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
					balance.AssetGenesis.GenesisBootstrapInfo,
					rpcAsset.AssetGenesis.GenesisBootstrapInfo,
				)
			}
		}
	}

	// We'll also ensure that we're able to get the balance by key group
	// for all the assets that have one specified.
	groupBalanceReq := &tarorpc.ListBalancesRequest_GroupKey{
		GroupKey: true,
	}
	assetGroupBalances, err := t.tarod.ListBalances(
		ctxt, &tarorpc.ListBalancesRequest{
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
					balance.AssetGenesis.GenesisBootstrapInfo,
					rpcAsset.AssetGenesis.GenesisBootstrapInfo,
				)
			}
		}
	}
}

func assertGroups(t *harnessTest, issuableAssets []*tarorpc.MintAssetRequest) {
	t.t.Helper()

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// We should be able to fetch two groups of one asset each.
	assetGroups, err := t.tarod.ListGroups(
		ctxt, &tarorpc.ListGroupsRequest{},
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

	equalityCheck := func(a *tarorpc.MintAssetRequest,
		b *tarorpc.AssetHumanReadable) {

		require.Equal(t.t, a.AssetType, b.Type)
		require.Equal(t.t, a.Name, b.Tag)
		require.Equal(t.t, a.MetaData, b.MetaData)
		require.Equal(t.t, a.Amount, int64(b.Amount))
	}

	equalityCheck(issuableAssets[0], groupedAssets[0])
	equalityCheck(issuableAssets[1], groupedAssets[1])
}

// testMintAssetNameCollisionError tests that an error is produced when
// attempting to mint an asset whose name collides with an existing minted asset.
func testMintAssetNameCollisionError(t *harnessTest) {
	// Asset name which will be common between minted asset and colliding
	// asset.
	commonAssetName := "test-asset-name"

	// Define and mint a single asset.
	assetMint := tarorpc.MintAssetRequest{
		AssetType: tarorpc.AssetType_NORMAL,
		Name:      commonAssetName,
		MetaData:  []byte("metadata-1"),
		Amount:    5000,
	}
	rpcSimpleAssets := mintAssetsConfirmBatch(
		t, t.tarod, []*tarorpc.MintAssetRequest{&assetMint},
	)

	// Ensure minted asset with requested name was successfully minted.
	mintedAssetName := rpcSimpleAssets[0].AssetGenesis.Name
	require.Equal(
		t.t, mintedAssetName, commonAssetName,
	)

	// Attempt to mint another asset whose name should collide with the
	// existing minted asset. No other fields should collide.
	assetCollide := tarorpc.MintAssetRequest{
		AssetType: tarorpc.AssetType_COLLECTIBLE,
		Name:      commonAssetName,
		MetaData:  []byte("metadata-2"),
		Amount:    1,
	}

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	_, actualErr := t.tarod.MintAsset(ctxt, &assetCollide)

	// Ensure error includes correct error type.
	// Note that `errors.Is` won't work with the error returned by
	// `t.tarod.MintAsset`.
	expectedErr := tarogarden.ErrDuplicateSeedlingName
	require.ErrorContains(t.t, actualErr, expectedErr.Error())
}
