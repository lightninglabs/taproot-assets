package itest

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	unirpc "github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	"github.com/stretchr/testify/require"
)

const (
	// testDataFileName is the name of the directory with the test data.
	testDataFileName = "testdata"
)

var (
	// Raw data of Cryptopunk 0 saved as a PNG.
	ImageMetadataFileName = filepath.Join(
		testDataFileName, "8k-metadata.hex",
	)
)

func testMintBatch100StressTest(t *harnessTest) {
	mintBatchStressTest(t, 100, defaultWaitTimeout)
}

func testMintBatch1kStressTest(t *harnessTest) {
	mintBatchStressTest(t, 1000, defaultWaitTimeout*20)
}

func testMintBatch10kStressTest(t *harnessTest) {
	mintBatchStressTest(t, 10000, defaultWaitTimeout*200)
}

func mintBatchStressTest(t *harnessTest, batchSize int,
	minterTimeout time.Duration) {

	// Read base metadata.
	imageMetadataHex, err := os.ReadFile(ImageMetadataFileName)
	require.NoError(t.t, err)

	imageMetadataBytes, err := hex.DecodeString(
		strings.Trim(string(imageMetadataHex), "\n"),
	)
	require.NoError(t.t, err)

	var (
		batchReqs      = make([]*mintrpc.MintAssetRequest, batchSize)
		baseName       = "jpeg"
		metaPrefixSize = binary.MaxVarintLen16
		metadataPrefix = make([]byte, metaPrefixSize)
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
			Amount: 1,
		},
		EnableEmission: false,
	}

	// Update the asset name and metadata to match an index.
	incrementMintAsset := func(asset *mintrpc.MintAsset, ind int) {
		asset.Name = asset.Name + strconv.Itoa(ind)
		binary.PutUvarint(metadataPrefix, uint64(ind))
		copy(asset.AssetMeta.Data[0:metaPrefixSize], metadataPrefix)
	}

	// Use the first asset of the batch as the asset group anchor.
	collectibleAnchorReq := copyRequest(&collectibleRequestTemplate)
	incrementMintAsset(collectibleAnchorReq.Asset, 0)
	collectibleAnchorReq.EnableEmission = true
	batchReqs[0] = collectibleAnchorReq

	// Generate the rest of the batch, with each asset referencing the group
	// anchor we created above.
	for i := 1; i < batchSize; i++ {
		groupedAsset := copyRequest(&collectibleRequestTemplate)
		incrementMintAsset(groupedAsset.Asset, i)
		groupedAsset.Asset.GroupAnchor = collectibleAnchorReq.Asset.Name
		batchReqs[i] = groupedAsset
	}

	// Submit the batch for minting. Use an extended timeout for the TX
	// appearing in the mempool, so we can observe the minter hitting its
	// own shorter default timeout.
	t.LogfTimestamped("beginning minting of batch of %d assets", batchSize)
	mintBatch := mintAssetsConfirmBatch(
		t, t.tapd, batchReqs, withMintingTimeout(minterTimeout),
	)
	t.LogfTimestamped("finished batch mint of %d assets", batchSize)

	// We can re-derive the group key to verify that the correct asset was
	// used as the group anchor.
	collectibleAnchor := verifyGroupAnchor(
		t.t, mintBatch, collectibleAnchorReq.Asset.Name,
	)
	collectGroupKey := collectibleAnchor.AssetGroup.TweakedGroupKey
	collectGroupKeyStr := hex.EncodeToString(collectGroupKey[:])

	// We should have one group, with the specified number of assets and an
	// equivalent balance, since the group is made of collectibles.
	groupCount := 1
	groupBalance := batchSize
	assertNumGroups(t.t, t.tapd, groupCount)
	assertGroupSizes(
		t.t, t.tapd, []string{collectGroupKeyStr}, []int{batchSize},
	)
	assertBalanceByGroup(
		t.t, t.tapd, collectGroupKeyStr, uint64(groupBalance),
	)

	// The universe tree should reflect the same properties about the batch;
	// there should be one root with a group key and balance matching what
	// we asserted previously.
	ctx := context.Background()
	uniRoots, err := t.tapd.AssetRoots(ctx, &unirpc.AssetRootRequest{})
	require.NoError(t.t, err)
	require.Len(t.t, uniRoots.UniverseRoots, groupCount)

	err = assertUniverseRoot(
		t.t, t.tapd, groupBalance, nil, collectGroupKey,
	)
	require.NoError(t.t, err)

	// The universe tree should also have a leaf for each asset minted.
	// TODO(jhb): Resolve issue of 33-byte group key handling.
	collectUniID := unirpc.ID{
		Id: &unirpc.ID_GroupKey{
			GroupKey: collectGroupKey[1:],
		},
	}
	uniLeaves, err := t.tapd.AssetLeaves(ctx, &collectUniID)
	require.NoError(t.t, err)
	require.Len(t.t, uniLeaves.Leaves, batchSize)

	// The universe tree should also have a key for each asset, with all
	// outpoints matching the chain anchor of the group anchor.
	mintOutpoint := collectibleAnchor.ChainAnchor.AnchorOutpoint
	uniKeys, err := t.tapd.AssetLeafKeys(ctx, &collectUniID)
	require.NoError(t.t, err)
	require.Len(t.t, uniKeys.AssetKeys, batchSize)

	correctOp := fn.All(uniKeys.AssetKeys, func(key *unirpc.AssetKey) bool {
		return key.GetOpStr() == mintOutpoint
	})
	require.True(t.t, correctOp)

	// If we create a second tapd instance and sync the universe state,
	// the synced tree should match the source tree.
	bob := setupTapdHarness(
		t.t, t, t.lndHarness.Bob, nil,
	)
	defer func() {
		require.NoError(t.t, bob.stop(!*noDelete))
	}()

	_, err = bob.AddFederationServer(
		ctx, &unirpc.AddFederationServerRequest{
			Servers: []*unirpc.UniverseFederationServer{
				{
					Host: t.tapd.rpcHost(),
				},
			},
		},
	)
	require.NoError(t.t, err)

	require.Eventually(t.t, func() bool {
		return assertUniverseStateEqual(t.t, t.tapd, bob)
	}, minterTimeout, time.Second)
}
