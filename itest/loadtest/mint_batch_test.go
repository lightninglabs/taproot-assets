package loadtest

import (
	"context"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/rpcclient"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/itest"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	unirpc "github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/stretchr/testify/require"
)

//go:embed testdata/8k-metadata.hex
var imageMetadataHex []byte

// mintTest checks that we are able to mint a batch of assets and that other
// members in the federation see the universe updated accordingly.
func mintTest(t *testing.T, ctx context.Context, cfg *Config) {
	// Start by initializing all our client connections.
	alice, bob, bitcoinClient := initClients(t, ctx, cfg)

	imageMetadataBytes, err := hex.DecodeString(
		strings.Trim(string(imageMetadataHex), "\n"),
	)
	require.NoError(t, err)

	var (
		minterTimeout  = cfg.TestTimeout
		batchSize      = cfg.BatchSize
		batchReqs      = make([]*mintrpc.MintAssetRequest, batchSize)
		baseName       = fmt.Sprintf("jpeg-%d", rand.Int31())
		metaPrefixSize = binary.MaxVarintLen16
		metadataPrefix = make([]byte, metaPrefixSize)
		aliceHost      = fmt.Sprintf(
			"%s:%d", alice.cfg.Host, alice.cfg.Port,
		)
	)

	// Before we mint a new group, let's first find out how many there
	// already are.
	initialGroups := itest.NumGroups(t, alice)

	// Each asset in the batch will share a name and metadata preimage, that
	// will be updated based on the asset's index in the batch.
	collectibleRequestTemplate := mintrpc.MintAssetRequest{
		Asset: &mintrpc.MintAsset{
			AssetType: taprpc.AssetType_COLLECTIBLE,
			Name:      baseName,
			AssetMeta: &taprpc.AssetMeta{
				Data: imageMetadataBytes,
				Type: 0,
			},
			Amount:          1,
			NewGroupedAsset: false,
		},
	}

	// Update the asset name and metadata to match an index.
	incrementMintAsset := func(asset *mintrpc.MintAsset, idx int) {
		asset.Name = fmt.Sprintf("%s-%d", asset.Name, idx)
		binary.PutUvarint(metadataPrefix, uint64(idx))
		copy(asset.AssetMeta.Data[0:metaPrefixSize], metadataPrefix)
	}

	// Use the first asset of the batch as the asset group anchor.
	collectibleAnchorReq := itest.CopyRequest(&collectibleRequestTemplate)
	incrementMintAsset(collectibleAnchorReq.Asset, 0)
	collectibleAnchorReq.Asset.NewGroupedAsset = true
	batchReqs[0] = collectibleAnchorReq

	// Generate the rest of the batch, with each asset referencing the group
	// anchor we created above.
	for i := 1; i < batchSize; i++ {
		groupedAsset := itest.CopyRequest(&collectibleRequestTemplate)
		incrementMintAsset(groupedAsset.Asset, i)
		groupedAsset.Asset.GroupAnchor = collectibleAnchorReq.Asset.Name
		groupedAsset.Asset.GroupedAsset = true
		groupedAsset.Asset.NewGroupedAsset = false
		batchReqs[i] = groupedAsset
	}

	// Submit the batch for minting. Use an extended timeout for the TX
	// appearing in the mempool, so we can observe the minter hitting its
	// own shorter default timeout.
	itest.LogfTimestamped(t, "beginning minting of batch of %d assets",
		batchSize)

	mintBatch := itest.MintAssetsConfirmBatch(
		t, bitcoinClient, alice, batchReqs,
		itest.WithMintingTimeout(minterTimeout),
	)

	itest.LogfTimestamped(t, "finished batch mint of %d assets", batchSize)

	// We can re-derive the group key to verify that the correct asset was
	// used as the group anchor.
	collectibleAnchor := itest.VerifyGroupAnchor(
		t, mintBatch, collectibleAnchorReq.Asset.Name,
	)
	collectGroupKey := collectibleAnchor.AssetGroup.TweakedGroupKey
	collectGroupKeyStr := hex.EncodeToString(collectGroupKey[:])

	// We should have one group, with the specified number of assets and an
	// equivalent balance, since the group is made of collectibles.
	groupCount := initialGroups + 1
	groupBalance := batchSize

	itest.AssertNumGroups(t, alice, groupCount)
	itest.AssertGroupSizes(
		t, alice, []string{collectGroupKeyStr},
		[]int{batchSize},
	)
	itest.AssertBalanceByGroup(
		t, alice, collectGroupKeyStr, uint64(groupBalance),
	)

	// The universe tree should reflect the same properties about the batch;
	// there should be one root with a group key and balance matching what
	// we asserted previously.
	uniRoots, err := alice.AssetRoots(ctx, &unirpc.AssetRootRequest{})
	require.NoError(t, err)
	issuanceRoots := fn.FilterMap(
		uniRoots.UniverseRoots, func(root *unirpc.UniverseRoot) bool {
			return root.Id.ProofType == unirpc.ProofType_PROOF_TYPE_ISSUANCE
		},
	)
	require.Len(t, issuanceRoots, groupCount)

	itest.AssertUniverseRoot(t, alice, groupBalance, nil, collectGroupKey)

	// The universe tree should also have a leaf for each asset minted.
	// TODO(jhb): Resolve issue of 33-byte group key handling.
	collectUniID := unirpc.ID{
		Id: &unirpc.ID_GroupKey{
			GroupKey: collectGroupKey[1:],
		},
		ProofType: unirpc.ProofType_PROOF_TYPE_ISSUANCE,
	}
	uniLeaves, err := alice.AssetLeaves(ctx, &collectUniID)
	require.NoError(t, err)
	require.Len(t, uniLeaves.Leaves, batchSize)

	// The universe tree should also have a key for each asset, with all
	// outpoints matching the chain anchor of the group anchor.
	mintOutpoint := collectibleAnchor.ChainAnchor.AnchorOutpoint
	uniKeys, err := alice.AssetLeafKeys(
		ctx, &unirpc.AssetLeafKeysRequest{
			Id: &collectUniID,
		},
	)
	require.NoError(t, err)
	require.Len(t, uniKeys.AssetKeys, batchSize)

	correctOp := fn.All(uniKeys.AssetKeys, func(key *unirpc.AssetKey) bool {
		return key.GetOpStr() == mintOutpoint
	})
	require.True(t, correctOp)

	itest.SyncUniverses(ctx, t, bob, alice, aliceHost, cfg.TestTimeout)
}

// mintTestV2 checks that we can mint a batch of assets. It is a more
// performant version of the existing mintTest, as it uses less assertions and
// RPC calls.
func mintTestV2(t *testing.T, ctx context.Context, cfg *Config) {
	// Start by initializing all our client connections.
	alice, bob, bitcoinClient := initClients(t, ctx, cfg)

	// We query the assets of each node once on this step. Every function
	// that needs to take a node's assets into account will be passed these
	// values instead of calling the RPC again. This is done to minimize
	// collateral RPC impact of the loadtest.
	resAlice, err := alice.ListAssets(ctx, &taprpc.ListAssetRequest{})
	require.NoError(t, err)

	resBob, err := bob.ListAssets(ctx, &taprpc.ListAssetRequest{})
	require.NoError(t, err)

	assetsAlice := resAlice.Assets
	assetsBob := resBob.Assets

	totalAssets := make([]*taprpc.Asset, len(assetsAlice)+len(assetsBob))
	copy(totalAssets, assetsAlice)
	copy(totalAssets[len(assetsAlice):], assetsBob)

	// Alice serves as the minter.
	//
	// TODO(george): Currently we use only 1 fixed minter, but this could
	// change in the future to emulate a more realistic environment where
	// multiple nodes continuously mint assets into their own groups.
	minter := alice

	// First we make sure group initialization is completed. We check if
	// there's any more groups left
	existingGroups := getTotalAssetGroups(totalAssets)
	groupKeys := make(map[string][]byte, 0)

	for _, v := range existingGroups {
		tweakedKey, err := hex.DecodeString(v)
		require.NoError(t, err)

		groupKeys[v] = tweakedKey
	}

	var remainingGroups int
	if cfg.TotalNumGroups > len(existingGroups) {
		remainingGroups = cfg.TotalNumGroups - len(existingGroups)
	}

	t.Logf("Existing groups=%v, minting %v new groups",
		len(existingGroups), remainingGroups)
	for range remainingGroups {
		mintNewGroup(t, ctx, bitcoinClient, minter, cfg)
	}

	// If there aren't any existing groups we skip the rest of the steps, we
	// will mint into those groups in another run.
	if len(existingGroups) == 0 {
		return
	}

	groupIndex := rand.Intn(len(existingGroups))
	groupKey := groupKeys[existingGroups[groupIndex]]

	mintIntoGroup(t, ctx, bitcoinClient, minter, groupKey, cfg)
}

// mintNewGroup mints an asset that creates a new group.
func mintNewGroup(t *testing.T, ctx context.Context, miner *rpcclient.Client,
	minter *rpcClient, cfg *Config) []*taprpc.Asset {

	mintAmt := rand.Uint64() % uint64(cfg.MintSupplyMax)
	if mintAmt < uint64(cfg.MintSupplyMin) {
		mintAmt = uint64(cfg.MintSupplyMin)
	}

	assetRequests := []*mintrpc.MintAssetRequest{{
		Asset: &mintrpc.MintAsset{
			AssetType: taprpc.AssetType_NORMAL,
			Name: fmt.Sprintf(
				"tapcoin-%d", time.Now().UnixNano(),
			),
			AssetMeta: &taprpc.AssetMeta{
				Data: []byte("{}"),
				Type: taprpc.AssetMetaType_META_TYPE_JSON,
			},
			Amount:          mintAmt,
			NewGroupedAsset: true,
			DecimalDisplay:  4,
		},
	}}

	return finishMint(t, ctx, miner, minter, assetRequests)
}

// mintIntoGroup mints as many assets as the batch size and puts them in the
// existing group that is provided by the corresponding argument.
func mintIntoGroup(t *testing.T, ctx context.Context, miner *rpcclient.Client,
	minter *rpcClient, tweakedKey []byte, cfg *Config) []*taprpc.Asset {

	mintAmt := rand.Uint64() % uint64(cfg.MintSupplyMax)
	if mintAmt < uint64(cfg.MintSupplyMin) {
		mintAmt = uint64(cfg.MintSupplyMin)
	}

	var assetRequests []*mintrpc.MintAssetRequest

	t.Logf("Minting %v assets into group %x", cfg.BatchSize, tweakedKey)

	for range cfg.BatchSize {
		ts := time.Now().UnixNano()

		// nolint:lll
		req := &mintrpc.MintAssetRequest{
			Asset: &mintrpc.MintAsset{
				AssetType: taprpc.AssetType_NORMAL,
				Name:      fmt.Sprintf("tapcoin-%d", ts),
				AssetMeta: &taprpc.AssetMeta{
					Data: []byte("{}"),
					Type: taprpc.AssetMetaType_META_TYPE_JSON,
				},
				Amount:         mintAmt,
				GroupedAsset:   true,
				GroupKey:       tweakedKey,
				DecimalDisplay: 4,
			},
		}

		assetRequests = append(assetRequests, req)
	}

	return finishMint(t, ctx, miner, minter, assetRequests)
}

// finishMint accepts a list of asset requests and performs the necessary RPC
// calls to create and finalize a minting batch.
func finishMint(t *testing.T, ctx context.Context, miner *rpcclient.Client,
	minter *rpcClient,
	assetRequests []*mintrpc.MintAssetRequest) []*taprpc.Asset {

	ctxc, streamCancel := context.WithCancel(ctx)
	stream, err := minter.SubscribeMintEvents(
		ctxc, &mintrpc.SubscribeMintEventsRequest{},
	)
	require.NoError(t, err)
	sub := &itest.EventSubscription[*mintrpc.MintEvent]{
		ClientEventStream: stream,
		Cancel:            streamCancel,
	}

	itest.BuildMintingBatch(t, minter, assetRequests)

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, wait.DefaultTimeout)
	defer cancel()

	finalizeReq := &mintrpc.FinalizeBatchRequest{}

	// Instruct the daemon to finalize the batch.
	batchResp, err := minter.FinalizeBatch(ctxt, finalizeReq)
	require.NoError(t, err)
	require.NotEmpty(t, batchResp.Batch)
	require.Len(t, batchResp.Batch.Assets, len(assetRequests))
	require.Equal(
		t, mintrpc.BatchState_BATCH_STATE_BROADCAST,
		batchResp.Batch.State,
	)

	itest.WaitForBatchState(
		t, ctxt, minter, wait.DefaultTimeout,
		batchResp.Batch.BatchKey,
		mintrpc.BatchState_BATCH_STATE_BROADCAST,
	)
	hashes, err := itest.WaitForNTxsInMempool(
		miner, 1, wait.DefaultTimeout,
	)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(hashes), 1)

	return itest.ConfirmBatch(
		t, miner, minter, assetRequests, sub, *hashes[0],
		batchResp.Batch.BatchKey,
	)
}

// getTotalAssetGroups returns the total number of asset groups found in the
// passed array of assets.
func getTotalAssetGroups(assets []*taprpc.Asset) []string {
	groups := fn.NewSet[string]()

	for _, v := range assets {
		groupKeyStr := fmt.Sprintf("%x", v.AssetGroup.TweakedGroupKey)
		groups.Add(groupKeyStr)
	}

	return groups.ToSlice()
}
