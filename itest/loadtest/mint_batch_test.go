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
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/stretchr/testify/require"
)

//go:embed testdata/8k-metadata.hex
var imageMetadataHex []byte

// execMintBatchStressTest checks that we are able to mint a batch of assets
// and that other memebers in the federation see the universe updated
// accordingly.
func execMintBatchStressTest(t *testing.T, ctx context.Context, cfg *Config) {
	// Create tapd clients.
	alice, aliceCleanUp := getTapClient(t, ctx, cfg.Alice.Tapd)
	defer aliceCleanUp()

	_, err := alice.GetInfo(ctx, &taprpc.GetInfoRequest{})
	require.NoError(t, err)

	bob, bobCleanUp := getTapClient(t, ctx, cfg.Bob.Tapd)
	defer bobCleanUp()

	_, err = bob.GetInfo(ctx, &taprpc.GetInfoRequest{})
	require.NoError(t, err)

	// Create bitcoin client.
	bitcoinClient := getBitcoinConn(t, cfg.Bitcoin)

	itest.MineBlocks(t, bitcoinClient, 1, 0)

	// If we fail from this point onward, we might have created a
	// transaction that isn't mined yet. To make sure we can run the test
	// again, we'll make sure to clean up the mempool by mining a block.
	t.Cleanup(func() {
		itest.MineBlocks(t, bitcoinClient, 1, 0)
	})

	imageMetadataBytes, err := hex.DecodeString(
		strings.Trim(string(imageMetadataHex), "\n"),
	)
	require.NoError(t, err)

	aliceHost := fmt.Sprintf("%s:%d", cfg.Alice.Tapd.Host,
		cfg.Alice.Tapd.Port)

	minterTimeout := 10 * time.Minute
	mintBatchStressTest(
		t, ctx, bitcoinClient, alice, bob, aliceHost, cfg.BatchSize,
		imageMetadataBytes, minterTimeout,
	)
}

func mintBatchStressTest(t *testing.T, ctx context.Context,
	bitcoinClient *rpcclient.Client, alice, bob itest.TapdClient,
	aliceHost string, batchSize int, imageMetadataBytes []byte,
	minterTimeout time.Duration) {

	var (
		batchReqs      = make([]*mintrpc.MintAssetRequest, batchSize)
		baseName       = fmt.Sprintf("jpeg-%d", rand.Int31())
		metaPrefixSize = binary.MaxVarintLen16
		metadataPrefix = make([]byte, metaPrefixSize)
	)

	// Before we mint a new group, let's first find out how many there
	// already are.
	initialGroups := itest.NumGroups(t, alice)

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
	incrementMintAsset := func(asset *mintrpc.MintAsset, idx int) {
		asset.Name = fmt.Sprintf("%s-%d", asset.Name, idx)
		binary.PutUvarint(metadataPrefix, uint64(idx))
		copy(asset.AssetMeta.Data[0:metaPrefixSize], metadataPrefix)
	}

	// Use the first asset of the batch as the asset group anchor.
	collectibleAnchorReq := itest.CopyRequest(&collectibleRequestTemplate)
	incrementMintAsset(collectibleAnchorReq.Asset, 0)
	collectibleAnchorReq.EnableEmission = true
	batchReqs[0] = collectibleAnchorReq

	// Generate the rest of the batch, with each asset referencing the group
	// anchor we created above.
	for i := 1; i < batchSize; i++ {
		groupedAsset := itest.CopyRequest(&collectibleRequestTemplate)
		incrementMintAsset(groupedAsset.Asset, i)
		groupedAsset.Asset.GroupAnchor = collectibleAnchorReq.Asset.Name
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
	require.Len(t, uniRoots.UniverseRoots, groupCount)

	itest.AssertUniverseRoot(t, alice, groupBalance, nil, collectGroupKey)

	// The universe tree should also have a leaf for each asset minted.
	// TODO(jhb): Resolve issue of 33-byte group key handling.
	collectUniID := unirpc.ID{
		Id: &unirpc.ID_GroupKey{
			GroupKey: collectGroupKey[1:],
		},
	}
	uniLeaves, err := alice.AssetLeaves(ctx, &collectUniID)
	require.NoError(t, err)
	require.Len(t, uniLeaves.Leaves, batchSize)

	// The universe tree should also have a key for each asset, with all
	// outpoints matching the chain anchor of the group anchor.
	mintOutpoint := collectibleAnchor.ChainAnchor.AnchorOutpoint
	uniKeys, err := alice.AssetLeafKeys(ctx, &collectUniID)
	require.NoError(t, err)
	require.Len(t, uniKeys.AssetKeys, batchSize)

	correctOp := fn.All(uniKeys.AssetKeys, func(key *unirpc.AssetKey) bool {
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
	if err != nil {
		// Only fail the test for other errors than duplicate universe
		// errors, as we might have already added the server in a
		// previous run.
		require.ErrorContains(
			t, err, universe.ErrDuplicateUniverse.Error(),
		)

		// If we've already added the server in a previous run, we'll
		// just need to kick off a sync (as that would otherwise be done
		// by adding the server request already).
		_, err := bob.SyncUniverse(ctx, &unirpc.SyncRequest{
			UniverseHost: aliceHost,
			SyncMode:     unirpc.UniverseSyncMode_SYNC_ISSUANCE_ONLY,
		})
		require.NoError(t, err)
	}

	require.Eventually(t, func() bool {
		return itest.AssertUniverseStateEqual(
			t, alice, bob,
		)
	}, minterTimeout, time.Second)
}
