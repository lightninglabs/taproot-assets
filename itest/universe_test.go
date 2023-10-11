package itest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	tap "github.com/lightninglabs/taproot-assets"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	unirpc "github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"
	"google.golang.org/protobuf/proto"
)

// testUniverseSync tests that we're able to properly sync the universe state
// between two nodes.
func testUniverseSync(t *harnessTest) {
	miner := t.lndHarness.Miner.Client
	// First, we'll create out usual set of simple and also issuable
	// assets.
	rpcSimpleAssets := MintAssetsConfirmBatch(
		t.t, miner, t.tapd, simpleAssets,
	)
	rpcIssuableAssets := MintAssetsConfirmBatch(
		t.t, miner, t.tapd, issuableAssets,
	)

	// With those assets created, we'll now create a new node that we'll
	// use to exercise the Universe sync.
	bob := setupTapdHarness(
		t.t, t, t.lndHarness.Bob, nil,
	)
	defer func() {
		require.NoError(t.t, bob.stop(!*noDelete))
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
		require.True(t.t, AssertUniverseRootEqual(srcRoot, newRoot))
	}

	// Now we'll fetch the Universe roots from Bob. These should match the
	// same roots that we got from the main universe node earlier.
	universeRootsBob, err := bob.AssetRoots(
		ctxt, &unirpc.AssetRootRequest{},
	)
	require.NoError(t.t, err)
	require.True(
		t.t, AssertUniverseRootsEqual(universeRoots, universeRootsBob),
	)

	// Finally, we'll ensure that the universe keys and leaves matches for
	// both parties.
	uniRoots := maps.Values(universeRoots.UniverseRoots)
	uniIDs := fn.Map(uniRoots, func(root *unirpc.UniverseRoot) *unirpc.ID {
		return root.Id
	},
	)
	AssertUniverseKeysEqual(t.t, uniIDs, t.tapd, bob)
	AssertUniverseLeavesEqual(t.t, uniIDs, t.tapd, bob)

	// We should also be able to fetch an asset from Bob's Universe, and
	// query for that asset with the compressed script key.
	firstAssetID := rpcSimpleAssets[0].AssetGenesis.AssetId
	firstScriptKey := hex.EncodeToString(rpcSimpleAssets[0].ScriptKey)
	firstOutpoint, err := tap.UnmarshalOutpoint(
		rpcSimpleAssets[0].ChainAnchor.AnchorOutpoint,
	)
	require.NoError(t.t, err)
	require.Len(t.t, firstScriptKey, btcec.PubKeyBytesLenCompressed*2)

	firstAssetProofQuery := unirpc.UniverseKey{
		Id: &unirpc.ID{
			Id: &unirpc.ID_AssetId{
				AssetId: firstAssetID,
			},
		},
		LeafKey: &unirpc.AssetKey{
			Outpoint: &unirpc.AssetKey_Op{
				Op: &unirpc.Outpoint{
					HashStr: firstOutpoint.Hash.String(),
					Index:   int32(firstOutpoint.Index),
				},
			},
			ScriptKey: &unirpc.AssetKey_ScriptKeyStr{
				ScriptKeyStr: firstScriptKey,
			},
		},
	}

	// The asset fetched from the universe should match the asset minted
	// on the main node, ignoring the zero prev witness from minting.
	firstAssetUniProof, err := bob.QueryProof(ctxt, &firstAssetProofQuery)
	require.NoError(t.t, err)

	// Verify the multiverse inclusion proof for the first asset.
	firstAssetUniMssmtRoot := unmarshalMerkleSumNode(
		firstAssetUniProof.UniverseRoot.MssmtRoot,
	)

	multiverseRoot := unmarshalMerkleSumNode(
		firstAssetUniProof.MultiverseRoot,
	)

	var compressedProof mssmt.CompressedProof
	err = compressedProof.Decode(
		bytes.NewReader(firstAssetUniProof.MultiverseInclusionProof),
	)
	require.NoError(t.t, err)

	multiverseInclusionProof, err := compressedProof.Decompress()
	require.NoError(t.t, err)

	assetIdFixedSize := fn.ToArray[[32]byte](firstAssetID)

	firstAssetAmount := rpcSimpleAssets[0].Amount
	nodeHash := firstAssetUniMssmtRoot.NodeHash()
	leaf := mssmt.NewLeafNode(
		nodeHash[:], firstAssetAmount,
	)

	verifyProofResult := mssmt.VerifyMerkleProof(
		assetIdFixedSize, leaf, multiverseInclusionProof,
		multiverseRoot,
	)
	require.True(t.t, verifyProofResult)

	firstAssetFromUni := firstAssetUniProof.AssetLeaf.Asset
	firstAssetFromUni.PrevWitnesses = nil
	AssertAsset(t.t, rpcSimpleAssets[0], firstAssetFromUni)

	// Now we'll delete a universe root on Bob's node, and then re-sync it.
	_, err = bob.DeleteAssetRoot(ctxt, &unirpc.DeleteRootQuery{
		Id: &unirpc.ID{
			Id: &unirpc.ID_AssetId{
				AssetId: firstAssetID,
			},
		},
	})
	require.NoError(t.t, err)

	universeRootsBob, err = bob.AssetRoots(
		ctxt, &unirpc.AssetRootRequest{},
	)
	require.NoError(t.t, err)

	// Bob should be missing one universe root from the total, which is
	// exactly the root we deleted.
	require.Len(t.t, universeRootsBob.UniverseRoots, totalAssets-1)
	firstAssetUniID := hex.EncodeToString(firstAssetID)
	_, ok := universeRootsBob.UniverseRoots[firstAssetUniID]
	require.False(t.t, ok)

	syncDiff, err = bob.SyncUniverse(ctxt, &unirpc.SyncRequest{
		UniverseHost: t.tapd.rpcHost(),
		SyncMode:     unirpc.UniverseSyncMode_SYNC_ISSUANCE_ONLY,
	})
	require.NoError(t.t, err)

	// The diff from resyncing Bob to the main universe node should be
	// for one universe with one asset.
	require.Len(t.t, syncDiff.SyncedUniverses, 1)
	resyncedUniverse := syncDiff.SyncedUniverses[0]
	require.True(t.t, resyncedUniverse.OldAssetRoot.MssmtRoot == nil)
	require.Len(t.t, resyncedUniverse.NewAssetLeaves, 1)

	// After re-sync, both universes should match again.
	universeRootsBob, err = bob.AssetRoots(
		ctxt, &unirpc.AssetRootRequest{},
	)
	require.NoError(t.t, err)
	require.True(
		t.t, AssertUniverseRootsEqual(universeRoots, universeRootsBob),
	)
}

// unmarshalMerkleSumNode un-marshals a protobuf MerkleSumNode.
func unmarshalMerkleSumNode(root *unirpc.MerkleSumNode) mssmt.Node {
	var nodeHash mssmt.NodeHash
	copy(nodeHash[:], root.RootHash)

	return mssmt.NewComputedBranch(nodeHash, uint64(root.RootSum))
}

// testUniverseREST tests that we're able to properly query the universe state
// via the REST interface.
func testUniverseREST(t *harnessTest) {
	miner := t.lndHarness.Miner.Client
	// Mint a few assets that we then want to inspect in the universe.
	rpcSimpleAssets := MintAssetsConfirmBatch(
		t.t, miner, t.tapd, simpleAssets,
	)
	rpcIssuableAssets := MintAssetsConfirmBatch(
		t.t, miner, t.tapd, issuableAssets,
	)

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
		require.True(t.t, AssertUniverseRootEqual(
			roots.UniverseRoots[assetID], assetRoot.AssetRoot,
		))
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

		require.True(t.t, AssertUniverseRootEqual(
			roots.UniverseRoots[groupKeyID],
			assetRoot.AssetRoot,
		))
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
		require.NoError(t.t, bob.stop(!*noDelete))
	}()

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	miner := t.lndHarness.Miner.Client

	// Now that Bob is active, we'll make a set of assets with the main node.
	firstAsset := MintAssetsConfirmBatch(t.t, miner, t.tapd, simpleAssets[:1])
	require.Len(t.t, firstAsset, 1)

	// Make sure we can't add ourselves to the universe.
	_, err := t.tapd.AddFederationServer(
		ctxt, &unirpc.AddFederationServerRequest{
			Servers: []*unirpc.UniverseFederationServer{{
				Host: t.tapd.rpcHost(),
			}},
		},
	)
	require.ErrorContains(t.t, err, "cannot add ourselves")

	// Make sure we can't add an invalid server to the universe.
	_, err = t.tapd.AddFederationServer(
		ctxt, &unirpc.AddFederationServerRequest{
			Servers: []*unirpc.UniverseFederationServer{{
				Host: "foobar this is not even a valid address",
			}},
		},
	)
	require.ErrorContains(t.t, err, "no such host")

	// We'll now add the main node, as a member of Bob's Universe
	// federation. We expect that their state is synchronized shortly after
	// the call returns.
	_, err = bob.AddFederationServer(
		ctxt, &unirpc.AddFederationServerRequest{
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
		ctxt, &unirpc.ListFederationServersRequest{},
	)
	require.NoError(t.t, err)
	require.Equal(t.t, 1, len(fedNodes.Servers))
	require.Equal(t.t, t.tapd.rpcHost(), fedNodes.Servers[0].Host)

	// At this point, both nodes should have the same Universe roots.
	require.Eventually(t.t, func() bool {
		return AssertUniverseStateEqual(t.t, bob, t.tapd)
	}, defaultWaitTimeout, wait.PollInterval)

	// Bob's Universe stats should show that he now has a single asset. We
	// should also be able to query for stats specifically for the asset.
	AssertUniverseStats(t.t, bob, 1, 0, 1, 0)

	// Test the content of the universe info call.
	info, err := bob.Info(ctxt, &unirpc.InfoRequest{})
	require.NoError(t.t, err)
	require.EqualValues(t.t, 1, info.NumAssets)

	// We'll now make two new assets with Bob, and ensure that the state is
	// properly pushed to the main node which is a part of the federation.
	newAssets := MintAssetsConfirmBatch(
		t.t, miner, bob, []*mintrpc.MintAssetRequest{
			simpleAssets[1], issuableAssets[0],
		},
	)

	// Bob should have two new assets in its local Universe tree.
	for _, newAsset := range newAssets {
		assetID := newAsset.AssetGenesis.AssetId
		uniID := &unirpc.ID{
			Id: &unirpc.ID_AssetId{
				AssetId: assetID,
			},
		}

		if newAsset.AssetGroup != nil {
			groupKey := newAsset.AssetGroup.TweakedGroupKey
			uniID = &unirpc.ID{
				Id: &unirpc.ID_GroupKey{
					GroupKey: groupKey,
				},
			}
		}

		waitErr := wait.NoError(func() error {
			_, err := bob.QueryAssetRoots(
				ctxt, &unirpc.AssetRootQuery{
					Id: uniID,
				},
			)
			return err
		}, defaultTimeout)
		require.NoError(t.t, waitErr)
	}

	// At this point, both nodes should have the same Universe roots as Bob
	// should have optimistically pushed the update to its federation
	// members.
	AssertUniverseStateEqual(t.t, bob, t.tapd)

	// Bob's stats should also now show that there're three total asset as
	// well as three proofs.
	AssertUniverseStats(t.t, bob, 3, 0, 3, 1)

	// We should be able to find both the new assets in the set of universe
	// stats for an asset.
	AssertUniverseAssetStats(t.t, bob, []*taprpc.Asset{
		firstAsset[0], newAssets[0], newAssets[1],
	})

	// Next, we'll try to delete the main node from the federation.
	_, err = bob.DeleteFederationServer(
		ctxt, &unirpc.DeleteFederationServerRequest{
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
		ctxt, &unirpc.ListFederationServersRequest{},
	)
	require.NoError(t.t, err)
	require.Equal(t.t, 0, len(fedNodes.Servers))
}
