package itest

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lightninglabs/taproot-assets/cmd/commands"
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
	batchSize := 100
	timeout := defaultWaitTimeout

	testMintBatchNStressTest(t, batchSize, timeout)
}

func testMintBatch1kStressTest(t *harnessTest) {
	batchSize := 1_000
	timeout := defaultWaitTimeout * 20

	testMintBatchNStressTest(t, batchSize, timeout)
}

func testMintBatch10kStressTest(t *harnessTest) {
	batchSize := 10_000
	timeout := defaultWaitTimeout * 200

	testMintBatchNStressTest(t, batchSize, timeout)
}

func testMintBatchNStressTest(t *harnessTest, batchSize int,
	timeout time.Duration) {

	// If we create a second tapd instance and sync the universe state,
	// the synced tree should match the source tree.
	lndBob := t.lndHarness.NewNodeWithCoins("Bob", nil)
	bob := setupTapdHarness(t.t, t, lndBob, t.universeServer)
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

	mintBatchStressTest(
		t.t, t.tapd, bob, t.tapd.rpcHost(), batchSize, mintBatches,
		imageMetadataBytes, timeout,
	)
}

// GetImageMetadataBytes returns the image metadata bytes from the given file.
func GetImageMetadataBytes(t *testing.T, fileName string) []byte {
	// Read base metadata.
	imageMetadataHex, err := os.ReadFile(fileName)
	require.NoError(t, err)

	imageMetadataBytes, err := hex.DecodeString(
		strings.Trim(string(imageMetadataHex), "\n"),
	)
	require.NoError(t, err)

	return imageMetadataBytes
}

func mintBatchStressTest(
	t *testing.T, alice, bob commands.RpcClientsBundle, aliceHost string,
	batchSize int,
	mintAssets func([]*mintrpc.MintAssetRequest) []*taprpc.Asset,
	imageMetadataBytes []byte, minterTimeout time.Duration) {

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
	collectibleAnchorReq.Asset.NewGroupedAsset = false
	collectibleAnchorReq.Asset.GroupedAsset = true
	batchReqs[0] = collectibleAnchorReq

	// Generate the rest of the batch, with each asset referencing the group
	// anchor we created above.
	for i := 1; i < batchSize; i++ {
		groupedAsset := CopyRequest(&collectibleRequestTemplate)
		incrementMintAsset(groupedAsset.Asset, i)
		groupedAsset.Asset.GroupAnchor = collectibleAnchorReq.Asset.Name
		batchReqs[i] = groupedAsset
	}

	// Submit the batch for minting. Use an extended timeout for the TX
	// appearing in the mempool, so we can observe the minter hitting its
	// own shorter default timeout.
	LogfTimestamped(t, "beginning minting of batch of %d assets",
		batchSize)

	mintBatch := mintAssets(batchReqs)

	LogfTimestamped(t, "finished batch mint of %d assets", batchSize)

	// We can re-derive the group key to verify that the correct asset was
	// used as the group anchor.
	collectibleAnchor := VerifyGroupAnchor(
		t, mintBatch, collectibleAnchorReq.Asset.Name,
	)
	collectGroupKey := collectibleAnchor.AssetGroup.TweakedGroupKey
	collectGroupKeyStr := hex.EncodeToString(collectGroupKey[:])

	// We should have one group, with the specified number of assets and an
	// equivalent balance, since the group is made of collectibles.
	groupCount := 1
	groupBalance := batchSize

	AssertNumGroups(t, alice, groupCount)
	AssertGroupSizes(
		t, alice, []string{collectGroupKeyStr},
		[]int{batchSize},
	)
	AssertBalanceByGroup(
		t, alice, collectGroupKeyStr, uint64(groupBalance),
	)

	// The universe tree should reflect the same properties about the batch;
	// there should be one root with a group key and balance matching what
	// we asserted previously.
	ctx := context.Background()
	uniRoots, err := alice.AssetRoots(
		ctx, &unirpc.AssetRootRequest{},
	)
	require.NoError(t, err)
	require.Len(t, uniRoots.UniverseRoots, groupCount)

	AssertUniverseRoot(t, alice, groupBalance, nil, collectGroupKey)

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

	leafKeys, err := fetchAllLeafKeys(alice, &collectUniID)
	require.NoError(t, err)

	require.Len(t, leafKeys, batchSize)

	correctOp := fn.All(leafKeys, func(key *unirpc.AssetKey) bool {
		return key.GetOpStr() == mintOutpoint
	})
	require.True(t, correctOp)

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
		return AssertUniverseStateEqual(
			t, alice, bob,
		)
	}, minterTimeout, time.Second)
}
