package itest

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"strconv"
	"testing"
	"time"

	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	unirpc "github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	"github.com/stretchr/testify/require"
)

const (
	// testPageSize is the page size to use when fetching data from the
	// universe rpc. We use a small page size to test pagination.
	testPageSize = 42

	// testPageSizeSmall is the page size to use when fetching data from the
	// universe rpc. We use a small page size to test pagination.
	testPageSizeSmall = 10

	// testGroupSize is the size of the asset group we mint in the
	// testUniversePaginationSimple test.
	testGroupSize = 79
)

func testUniversePaginationSimple(t *harnessTest) {
	mintSize := 50
	timeout := defaultWaitTimeout

	// If we create a second tapd instance and sync the universe state,
	// the synced tree should match the source tree.
	bob := setupTapdHarness(
		t.t, t, t.lndHarness.Bob, t.universeServer,
	)
	defer func() {
		require.NoError(t.t, bob.stop(!*noDelete))
	}()

	mintBatches := func(reqs []*mintrpc.MintAssetRequest) []*taprpc.Asset {
		return MintAssetsConfirmBatch(
			t.t, t.lndHarness.Miner().Client, t.tapd, reqs,
			WithMintingTimeout(timeout),
		)
	}

	imageMetadataBytes := GetImageMetadataBytes(t.t, ImageMetadataFileName)

	mintBatchAssetsTest(
		t.t, t.tapd, bob, t.tapd.rpcHost(), mintSize, mintBatches,
		imageMetadataBytes, timeout,
	)
}

// mintBatchAssetsTest mints many assets
func mintBatchAssetsTest(
	t *testing.T, alice, bob TapdClient, aliceHost string, mintSize int,
	mintAssets func([]*mintrpc.MintAssetRequest) []*taprpc.Asset,
	imageMetadataBytes []byte, minterTimeout time.Duration) {

	var (
		batchReqs      = make([]*mintrpc.MintAssetRequest, 0)
		baseName       = "jpeg"
		metaPrefixSize = binary.MaxVarintLen16
		metadataPrefix = make([]byte, metaPrefixSize)
		mintBatches    = make(map[int][]*taprpc.Asset)
	)

	// Each asset in the batch will share a name and metdata preimage, that
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
	incrementMintAsset := func(asset *mintrpc.MintAsset, ind int) {
		asset.Name += strconv.Itoa(ind)
		binary.PutUvarint(metadataPrefix, uint64(ind))
		copy(asset.AssetMeta.Data[0:metaPrefixSize], metadataPrefix)
	}

	// Use the first asset of the batch as the asset group anchor.
	collectibleAnchorReq := CopyRequest(&collectibleRequestTemplate)
	incrementMintAsset(collectibleAnchorReq.Asset, 0)
	collectibleAnchorReq.Asset.NewGroupedAsset = true
	batchReqs = append(batchReqs, collectibleAnchorReq)

	groupSize := testGroupSize

	// Generate the rest of the batch, with each asset referencing the group
	// anchor we created above.
	for i := 1; i < mintSize; i++ {
		groupedAsset := CopyRequest(&collectibleRequestTemplate)

		// If group size was reached mint, confirm and rotate the group
		// anchor.
		if i%groupSize == 0 || i == mintSize-1 {
			mintBatch := mintAssets(batchReqs)
			mintBatches[i] = mintBatch

			batchReqs = make([]*mintrpc.MintAssetRequest, 0)

			incrementMintAsset(groupedAsset.Asset, i)
			collectibleAnchorReq = CopyRequest(groupedAsset)
			groupedAsset.Asset.NewGroupedAsset = true
		} else {
			groupedAsset.Asset.GroupAnchor =
				collectibleAnchorReq.Asset.Name
			groupedAsset.Asset.GroupedAsset = true
			groupedAsset.Asset.NewGroupedAsset = false

			incrementMintAsset(groupedAsset.Asset, i)
		}

		batchReqs = append(batchReqs, groupedAsset)
	}

	// Since batch size is not a multiple of group size, we should have one
	// last group with all the leftovers.
	groupCount := mintSize/groupSize + 1

	AssertNumGroups(t, alice, groupCount)

	for _, mintBatch := range mintBatches {
		anchorAsset := taprpc.Asset{
			AssetGenesis: mintBatch[0].AssetGenesis,
			AssetGroup:   mintBatch[0].AssetGroup,
		}

		// We can re-derive the group key to verify that the correct
		// asset was used as the group anchor.
		collectibleAnchor := VerifyGroupAnchor(
			t, mintBatch, anchorAsset.AssetGenesis.Name,
		)
		collectGroupKey := anchorAsset.AssetGroup.TweakedGroupKey
		collectGroupKeyStr := hex.EncodeToString(collectGroupKey[:])

		AssertGroupSizes(
			t, alice, []string{collectGroupKeyStr},
			[]int{len(mintBatch)},
		)
		AssertBalanceByGroup(
			t, alice, collectGroupKeyStr, uint64(len(mintBatch)),
		)

		// The universe tree should also have a leaf for each asset
		// minted.
		// TODO(jhb): Resolve issue of 33-byte group key handling.
		collectUniID := unirpc.ID{
			Id: &unirpc.ID_GroupKey{
				GroupKey: collectGroupKey[1:],
			},
			ProofType: unirpc.ProofType_PROOF_TYPE_ISSUANCE,
		}

		AssertUniverseRoot(
			t, alice, len(mintBatch), nil, collectGroupKey,
		)

		ctx := context.Background()
		uniLeaves, err := alice.AssetLeaves(ctx, &collectUniID)
		require.NoError(t, err)
		require.Len(t, uniLeaves.Leaves, len(mintBatch))

		// The universe tree should also have a key for each asset, with
		// all outpoints matching the chain anchor of the group anchor.
		mintOutpoint := collectibleAnchor.ChainAnchor.AnchorOutpoint

		leafKeys, err := fetchAllLeafKeys(alice, &collectUniID)
		require.NoError(t, err)

		require.Len(t, leafKeys, len(mintBatch))

		correctOp := fn.All(leafKeys, func(key *unirpc.AssetKey) bool {
			return key.GetOpStr() == mintOutpoint
		})
		require.True(t, correctOp)
	}

	// The universe tree should reflect the same properties about the batch;
	// there should be one root with a group key and balance matching what
	// we asserted previously.
	ctx := context.Background()
	uniRoots, err := assetRoots(ctx, alice, testPageSizeSmall)
	require.NoError(t, err)
	require.Len(t, uniRoots.UniverseRoots, groupCount)

	_, err = bob.AddFederationServer(
		ctx, &unirpc.AddFederationServerRequest{
			Servers: []*unirpc.UniverseFederationServer{
				{
					Host: aliceHost,
				},
			},
		},
	)
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		return AssertUniverseStateEqual(t, alice, bob)
	}, minterTimeout, 200*time.Millisecond)
}

// fetchAllLeafKeys fetches all leaf keys for a given universe ID.
func fetchAllLeafKeys(alice TapdClient, id *unirpc.ID) ([]*unirpc.AssetKey,
	error) {

	keys := make([]*unirpc.AssetKey, 0)
	offset := int32(0)

	for {
		resp, err := alice.AssetLeafKeys(
			context.Background(), &unirpc.AssetLeafKeysRequest{
				Id:     id,
				Offset: offset,
				Limit:  testPageSize,
			},
		)
		if err != nil {
			return nil, err
		}

		if len(resp.AssetKeys) == 0 {
			break
		}

		keys = append(keys, resp.AssetKeys...)
		offset += testPageSize
	}

	return keys, nil
}
