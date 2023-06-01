package itest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/taprpc"
	unirpc "github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"
	"google.golang.org/protobuf/proto"
)

// testUniverseSync tests that we're able to properly sync the universe state
// between two nodes.
func testUniverseSync(t *harnessTest) {
	// First, we'll create out usual set of simple and also issuable
	// assets.
	rpcSimpleAssets := mintAssetsConfirmBatch(t, t.tapd, simpleAssets)
	rpcIssuableAssets := mintAssetsConfirmBatch(t, t.tapd, issuableAssets)

	// With those assets created, we'll now create a new node that we'll
	// use to exercise the Universe sync.
	bob := setupTapdHarness(
		t.t, t, t.lndHarness.Bob, nil,
	)
	defer func() {
		require.NoError(t.t, bob.stop(true))
	}()

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// Before we start, we'll fetch the complete set of Universe roots from
	// our primary node.
	universeRoots, err := t.tapd.AssetRoots(
		ctxt, &unirpc.AssetRootRequest{},
	)
	require.NoError(t.t, err)

	// Now we have an initial benchmark, so we'll kick off the universe
	// sync with Bob syncing off the primary harness node that created the
	// assets.
	ctxt, cancel = context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()
	syncDiff, err := bob.SyncUniverse(ctxt, &unirpc.SyncRequest{
		UniverseHost: t.tapd.rpcHost(),
		SyncMode:     unirpc.UniverseSyncMode_SYNC_ISSUANCE_ONLY,
	})
	require.NoError(t.t, err)

	// Bob's universe diff should contain an entry for each of the assets
	// we created above.
	totalAssets := len(rpcSimpleAssets) + len(rpcIssuableAssets)
	require.Len(t.t, syncDiff.SyncedUniverses, totalAssets)

	// Each item in the diff should match the set of universe roots we got
	// from the source node above.
	for _, uniDiff := range syncDiff.SyncedUniverses {
		// The old root should be blank, as we're syncing this asset
		// for the first time.
		require.True(t.t, uniDiff.OldAssetRoot.MssmtRoot == nil)

		// A single new leaf should be present.
		require.Len(t.t, uniDiff.NewAssetLeaves, 1)

		// The new root should match the root we got from the primary
		// node above.
		newRoot := uniDiff.NewAssetRoot
		require.NotNil(t.t, newRoot)

		uniKey := func() string {
			switch {
			case newRoot.Id.GetAssetId() != nil:
				return hex.EncodeToString(
					newRoot.Id.GetAssetId(),
				)

			case newRoot.Id.GetGroupKey() != nil:
				groupKey, err := schnorr.ParsePubKey(
					newRoot.Id.GetGroupKey(),
				)
				require.NoError(t.t, err)

				h := sha256.Sum256(
					schnorr.SerializePubKey(groupKey),
				)

				return hex.EncodeToString(h[:])
			default:
				t.Fatalf("unknown universe asset id type")
				return ""
			}
		}()

		srcRoot, ok := universeRoots.UniverseRoots[uniKey]
		require.True(t.t, ok)
		assertUniverseRootEqual(t.t, srcRoot, newRoot)
	}

	// Now we'll fetch the Universe roots from Bob. These should match the
	// same roots that we got from the main universe node earlier.
	universeRootsBob, err := bob.AssetRoots(
		ctxt, &unirpc.AssetRootRequest{},
	)
	require.NoError(t.t, err)
	assertUniverseRootsEqual(t.t, universeRoots, universeRootsBob)

	// Finally, we'll ensure that the universe keys and leaves matches for
	// both parties.
	uniRoots := maps.Values(universeRoots.UniverseRoots)
	uniIDs := fn.Map(uniRoots, func(root *unirpc.UniverseRoot) *unirpc.ID {
		return root.Id
	},
	)
	assertUniverseKeysEqual(t.t, uniIDs, t.tapd, bob)
	assertUniverseLeavesEqual(t.t, uniIDs, t.tapd, bob)
}

// testUniverseREST tests that we're able to properly query the universe state
// via the REST interface.
func testUniverseREST(t *harnessTest) {
	// Mint a few assets that we then want to inspect in the universe.
	rpcSimpleAssets := mintAssetsConfirmBatch(t, t.tapd, simpleAssets)
	rpcIssuableAssets := mintAssetsConfirmBatch(t, t.tapd, issuableAssets)

	urlPrefix := fmt.Sprintf("https://%s/v1/taproot-assets/universe",
		t.tapd.clientCfg.RpcConf.RawRESTListeners[0])

	// First of all, get all roots and make sure our assets are contained
	// in the returned list.
	roots, err := getJSON[*unirpc.AssetRootResponse](
		fmt.Sprintf("%s/roots", urlPrefix),
	)
	require.NoError(t.t, err)

	// Simple assets are keyed by their asset ID.
	for _, simpleAsset := range rpcSimpleAssets {
		assetID := hex.EncodeToString(simpleAsset.AssetGenesis.AssetId)
		require.Contains(t.t, roots.UniverseRoots, assetID)

		require.Equal(
			t.t, simpleAsset.AssetGenesis.Name,
			roots.UniverseRoots[assetID].AssetName,
		)

		// Query the specific root to make sure we get the same result.
		assetRoot, err := getJSON[*unirpc.QueryRootResponse](
			fmt.Sprintf("%s/roots/asset-id/%s", urlPrefix, assetID),
		)
		require.NoError(t.t, err)
		require.Equal(
			t.t, roots.UniverseRoots[assetID], assetRoot.AssetRoot,
		)
	}

	// Re-issuable assets are keyed by their group keys.
	for _, issuableAsset := range rpcIssuableAssets {
		// The group key is the full 33-byte public key, but the
		// response instead will use the schnorr serialized public key.
		// universe commits to the hash of the Schnorr serialized
		// public key.
		groupKey := issuableAsset.AssetGroup.TweakedGroupKey
		groupKeyHash := sha256.Sum256(groupKey[1:])
		groupKeyID := hex.EncodeToString(groupKeyHash[:])
		require.Contains(t.t, roots.UniverseRoots, groupKeyID)

		// Query the specific root to make sure we get the same result.
		// Rather than use the hash above, the API exposes the
		// serialized schorr key instead as the URI param.
		queryGroupKey := hex.EncodeToString(groupKey[1:])
		queryURI := fmt.Sprintf(
			"%s/roots/group-key/%s", urlPrefix, queryGroupKey,
		)
		assetRoot, err := getJSON[*unirpc.QueryRootResponse](queryURI)
		require.NoError(t.t, err)

		require.Equal(
			t.t, roots.UniverseRoots[groupKeyID],
			assetRoot.AssetRoot,
		)
	}
}

// getJSON retrieves the body of a given URL, ignoring any TLS certificate the
// server might present.
func getJSON[T proto.Message](url string) (T, error) {
	var jsonType T
	jsonResp := jsonType.ProtoReflect().New().Interface()

	resp, err := client.Get(url)
	if err != nil {
		return jsonType, err
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return jsonType, err
	}

	err = taprpc.RESTJsonUnmarshalOpts.Unmarshal(body, jsonResp)
	if err != nil {
		return jsonType, fmt.Errorf("failed to unmarshal %s: %v", body,
			err)
	}

	return jsonResp.(T), nil
}

func testUniverseFederation(t *harnessTest) {
	// We'll kick off the test by making a new node, without hooking it up to
	// any existing Universe server.
	bob := setupTapdHarness(
		t.t, t, t.lndHarness.Bob, nil,
	)
	defer func() {
		require.NoError(t.t, bob.stop(true))
	}()

	ctx := context.Background()

	// Now that Bob is active, we'll make a set of assets with the main node.
	firstAsset := mintAssetsConfirmBatch(t, t.tapd, simpleAssets[:1])

	// We'll now add the main node, as a member of Bob's Universe
	// federation. We expect that their state is synchronized shortly after
	// the call returns.
	_, err := bob.AddFederationServer(
		ctx, &unirpc.AddFederationServerRequest{
			Servers: []*unirpc.UniverseFederationServer{
				{
					Host: t.tapd.rpcHost(),
				},
			},
		},
	)
	require.NoError(t.t, err)

	// If we fetch the set of federation nodes, then the main node should
	// be shown as being a part of that set.
	fedNodes, err := bob.ListFederationServers(
		ctx, &unirpc.ListFederationServersRequest{},
	)
	require.NoError(t.t, err)
	require.Equal(t.t, 1, len(fedNodes.Servers))
	require.Equal(t.t, t.tapd.rpcHost(), fedNodes.Servers[0].Host)

	// At this point, both nodes should have the same Universe roots.
	assertUniverseStateEqual(t.t, bob, t.tapd)

	// Bob's Universe stats should show that he now has a single asset. We
	// should also be able to query for stats specifically for the asset.
	assertUniverseStats(t.t, bob, 1, 0, 1)

	// We'll now make a new asset with Bob, and ensure that the state is
	// properly pushed to the main node which is a part of the federation.
	newAsset := mintAssetsConfirmBatch(t, bob, simpleAssets[1:])

	// Bob should have a new asset in its local Universe tree.
	assetID := newAsset[0].AssetGenesis.AssetId
	waitErr := wait.NoError(func() error {
		_, err := bob.QueryAssetRoots(ctx, &unirpc.AssetRootQuery{
			Id: &unirpc.ID{
				Id: &unirpc.ID_AssetId{
					AssetId: assetID,
				},
			},
		})
		return err
	}, defaultTimeout)
	require.NoError(t.t, waitErr)

	// At this point, both nodes should have the same Universe roots as Bob
	// should have optimistically pushed the update to its federation
	// members.
	assertUniverseStateEqual(t.t, bob, t.tapd)

	// Bob's stats should also now show that there're two total asset as
	// well as two proofs.
	assertUniverseStats(t.t, bob, 2, 0, 2)

	// We should be able to find both the new assets in the set of universe
	// stats for an asset.
	assertUniverseAssetStats(
		t.t, bob, [][]byte{
			firstAsset[0].AssetGenesis.AssetId,
			newAsset[0].AssetGenesis.AssetId,
		},
	)

	// Next, we'll try to delete the main node from the federation.
	_, err = bob.DeleteFederationServer(
		ctx, &unirpc.DeleteFederationServerRequest{
			Servers: []*unirpc.UniverseFederationServer{
				{
					Host: t.tapd.rpcHost(),
				},
			},
		},
	)
	require.NoError(t.t, err)

	// If we fetch the set of federation nodes, then the main node should
	// no longer be present.
	fedNodes, err = bob.ListFederationServers(
		ctx, &unirpc.ListFederationServersRequest{},
	)
	require.NoError(t.t, err)
	require.Equal(t.t, 0, len(fedNodes.Servers))
}
