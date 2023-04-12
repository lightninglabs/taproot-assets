package itest

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	unirpc "github.com/lightninglabs/taro/tarorpc/universerpc"
	"github.com/stretchr/testify/require"
)

func testUniverseREST(t *harnessTest) {
	// Mint a few assets that we then want to inspect in the universe.
	rpcSimpleAssets := mintAssetsConfirmBatch(t, t.tarod, simpleAssets)
	rpcIssuableAssets := mintAssetsConfirmBatch(t, t.tarod, issuableAssets)

	urlPrefix := fmt.Sprintf("https://%s/v1/taro/universe",
		t.tarod.clientCfg.RpcConf.RawRESTListeners[0])

	// First of all, get all roots and make sure our assets are contained
	// in the returned list.
	roots, err := getJSON[unirpc.AssetRootResponse](
		fmt.Sprintf("%s/roots", urlPrefix),
	)
	require.NoError(t.t, err)

	// Simple assets are keyed by their asset ID.
	for _, simpleAsset := range rpcSimpleAssets {
		assetID := hex.EncodeToString(simpleAsset.AssetGenesis.AssetId)
		require.Contains(t.t, roots.UniverseRoots, assetID)

		// Query the specific root to make sure we get the same result.
		assetRoot, err := getJSON[unirpc.QueryRootResponse](
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
		assetRoot, err := getJSON[unirpc.QueryRootResponse](queryURI)
		require.NoError(t.t, err)

		require.Equal(
			t.t, roots.UniverseRoots[groupKeyID],
			assetRoot.AssetRoot,
		)
	}
}

// getJSON retrieves the body of a given URL, ignoring any TLS certificate the
// server might present.
func getJSON[T any](url string) (*T, error) {
	jsonResp := new(T)

	resp, err := client.Get(url)
	if err != nil {
		return jsonResp, err
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return jsonResp, err
	}

	if err = jsonMarshaler.Unmarshal(body, jsonResp); err != nil {
		return jsonResp, fmt.Errorf("failed to unmarshal %s: %v", body,
			err)
	}

	return jsonResp, nil
}
