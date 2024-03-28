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

	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/itest"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	unirpc "github.com/lightninglabs/taproot-assets/taprpc/universerpc"
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
