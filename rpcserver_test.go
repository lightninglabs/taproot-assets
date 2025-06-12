package taprootassets

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/stretchr/testify/require"
)

// mockAddrBook is a mock implementation of the address.Book interface.
type mockAddrBook struct {
	address.Book // Embed to satisfy most methods if not overridden

	FetchAssetMetaForAssetFunc func(ctx context.Context, id asset.ID) (*proof.MetaReveal, error)
	FetchAssetMetaByHashFunc   func(ctx context.Context, hash [proof.MetaHashLen]byte) (*proof.MetaReveal, error)
	// Add other methods if FetchAssetMeta indirectly calls them.
}

func (m *mockAddrBook) FetchAssetMetaForAsset(ctx context.Context, id asset.ID) (*proof.MetaReveal, error) {
	if m.FetchAssetMetaForAssetFunc != nil {
		return m.FetchAssetMetaForAssetFunc(ctx, id)
	}
	return nil, fmt.Errorf("mockAddrBook.FetchAssetMetaForAssetFunc not implemented")
}

func (m *mockAddrBook) FetchAssetMetaByHash(ctx context.Context, hash [proof.MetaHashLen]byte) (*proof.MetaReveal, error) {
	if m.FetchAssetMetaByHashFunc != nil {
		return m.FetchAssetMetaByHashFunc(ctx, hash)
	}
	return nil, fmt.Errorf("mockAddrBook.FetchAssetMetaByHashFunc not implemented")
}

// mockAssetStore is a mock implementation of the tapdb.AssetStore interface.
type mockAssetStore struct {
	tapdb.AssetStore // Embed to satisfy most methods if not overridden

	FetchAllAssetsFunc func(context.Context, bool, bool, *tapdb.AssetQueryFilters) ([]*asset.ChainAsset, error)
	// Add other methods if FetchAssetMeta indirectly calls them.
}

func (m *mockAssetStore) FetchAllAssets(ctx context.Context, includeSpent, includeLeased bool,
	filters *tapdb.AssetQueryFilters) ([]*asset.ChainAsset, error) {
	if m.FetchAllAssetsFunc != nil {
		return m.FetchAllAssetsFunc(ctx, includeSpent, includeLeased, filters)
	}
	return nil, fmt.Errorf("mockAssetStore.FetchAllAssetsFunc not implemented")
}

func newTestRpcServer(t *testing.T, mockBook address.Book, mockStore tapdb.AssetStore) *rpcServer {
	// We use a minimal config here. If other parts of Config are accessed by
	// FetchAssetMeta or its callees (like ChainParams for address encoding,
	// or KeyRing for local key checks in MarshalChainAsset), they might need
	// to be initialized. For now, AddrBook and AssetStore are the direct ones.
	cfg := &Config{
		AddrBook:   mockBook,
		AssetStore: mockStore,
		// ChainParams: &chaincfg.MainNetParams, // Example if needed
	}
	return &rpcServer{cfg: cfg}
}

func makeMetaReveal(t *testing.T, name string, decDisplay uint32) *proof.MetaReveal {
	metaJSON := map[string]interface{}{
		"name": name,
	}
	// Only add decimal_display if it's non-zero to simulate cases where it might be absent
	if decDisplay > 0 {
		metaJSON["decimal_display"] = decDisplay
	}
	metaBytes, err := json.Marshal(metaJSON)
	require.NoError(t, err)

	// The DecDisplayOption() method on MetaReveal tries TLV first, then JSON.
	// To make it simpler for mocking, we can directly set the Data to JSON.
	// Alternatively, one could construct the TLV bytes if testing that path specifically.
	return &proof.MetaReveal{
		Data: metaBytes,
		Type: proof.MetaJson,
	}
}

func TestFetchAssetMeta(t *testing.T) {
	ctx := context.Background()

	// Common assets and keys for tests
	assetID1Bytes, _ := hex.DecodeString("0101010101010101010101010101010101010101010101010101010101010101")
	var assetID1 asset.ID
	copy(assetID1[:], assetID1Bytes)

	assetID2Bytes, _ := hex.DecodeString("0202020202020202020202020202020202020202020202020202020202020202")
	var assetID2 asset.ID
	copy(assetID2[:], assetID2Bytes)

	groupKeyBytes, _ := hex.DecodeString("030000000000000000000000000000000000000000000000000000000000000001")
	groupKey, _ := btcec.ParsePubKey(groupKeyBytes)

	meta1 := makeMetaReveal(t, "Asset One", 2)
	meta2 := makeMetaReveal(t, "Asset Two in Group", 2) // Same decimal display for group
	meta3 := makeMetaReveal(t, "Asset Three in Group", 2) // Same decimal display for group

	var meta1Hash [proof.MetaHashLen]byte
	copy(meta1Hash[:], meta1.MetaHash())


	t.Run("Fetch by Group Key - Success", func(t *testing.T) {
		mockBook := &mockAddrBook{}
		mockStore := &mockAssetStore{}

		chainAsset2 := &asset.ChainAsset{
			Asset: asset.Asset{
				Version:  asset.V0,
				Genesis:  asset.Genesis{ID: assetID2, MetaHash: meta2.MetaHash()},
				GroupKey: &asset.GroupKey{GroupPubKey: *groupKey},
				// Other fields as needed by MarshalChainAsset
				ScriptKey: asset.ScriptKey{PubKey: &btcec.PublicKey{}},
			},
		}
		chainAsset3 := &asset.ChainAsset{
			Asset: asset.Asset{
				Version:  asset.V0,
				Genesis:  asset.Genesis{ID: assetID1, MetaHash: meta3.MetaHash()}, // Note: using assetID1 for variety
				GroupKey: &asset.GroupKey{GroupPubKey: *groupKey},
				// Other fields as needed by MarshalChainAsset
				ScriptKey: asset.ScriptKey{PubKey: &btcec.PublicKey{}},
			},
		}

		mockStore.FetchAllAssetsFunc = func(_ context.Context, _, _ bool, filters *tapdb.AssetQueryFilters) ([]*asset.ChainAsset, error) {
			require.NotNil(t, filters)
			require.NotNil(t, filters.AssetSpecifier)
			require.True(t, filters.AssetSpecifier.HasGroupPubKey())
			require.True(t, filters.AssetSpecifier.UnwrapGroupKeyToPtr().IsEqual(groupKey))
			return []*asset.ChainAsset{chainAsset2, chainAsset3}, nil
		}

		mockBook.FetchAssetMetaForAssetFunc = func(_ context.Context, id asset.ID) (*proof.MetaReveal, error) {
			if id == assetID2 {
				return meta2, nil
			}
			if id == assetID1 { // Corresponds to chainAsset3's Genesis ID
				return meta3, nil
			}
			return nil, fmt.Errorf("unexpected asset ID: %x", id)
		}

		server := newTestRpcServer(t, mockBook, mockStore)
		req := &taprpc.FetchAssetMetaRequest{
			Asset: &taprpc.FetchAssetMetaRequest_GroupKeyStr{GroupKeyStr: hex.EncodeToString(groupKeyBytes)},
		}

		resp, err := server.FetchAssetMeta(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Len(t, resp.AssetMetas, 2)
		require.Equal(t, int32(2), resp.DecimalDisplay)

		// Check individual metas (order might vary depending on fetchRpcAssets)
		foundMeta2 := false
		foundMeta3 := false
		for _, rpcMeta := range resp.AssetMetas {
			if bytes.Equal(rpcMeta.MetaHash, meta2.MetaHash()) {
				foundMeta2 = true
				require.Equal(t, meta2.Data, rpcMeta.Data)
			}
			if bytes.Equal(rpcMeta.MetaHash, meta3.MetaHash()) {
				foundMeta3 = true
				require.Equal(t, meta3.Data, rpcMeta.Data)
			}
		}
		require.True(t, foundMeta2, "meta2 not found in response")
		require.True(t, foundMeta3, "meta3 not found in response")
	})

	t.Run("Fetch by Group Key - Group Not Found", func(t *testing.T) {
		mockBook := &mockAddrBook{} // Not used in this path
		mockStore := &mockAssetStore{}
		mockStore.FetchAllAssetsFunc = func(_ context.Context, _, _ bool, filters *tapdb.AssetQueryFilters) ([]*asset.ChainAsset, error) {
			return []*asset.ChainAsset{}, nil // No assets for this group
		}

		server := newTestRpcServer(t, mockBook, mockStore)
		req := &taprpc.FetchAssetMetaRequest{
			Asset: &taprpc.FetchAssetMetaRequest_GroupKeyStr{GroupKeyStr: hex.EncodeToString(groupKeyBytes)},
		}

		resp, err := server.FetchAssetMeta(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Empty(t, resp.AssetMetas)
		require.Equal(t, int32(0), resp.DecimalDisplay)
	})

	t.Run("Fetch by Asset ID - DecimalDisplay populated", func(t *testing.T) {
		mockBook := &mockAddrBook{}
		mockStore := &mockAssetStore{} // Not directly used by FetchAssetMetaForAsset path

		mockBook.FetchAssetMetaForAssetFunc = func(_ context.Context, id asset.ID) (*proof.MetaReveal, error) {
			require.Equal(t, assetID1, id)
			return meta1, nil
		}

		server := newTestRpcServer(t, mockBook, mockStore)
		req := &taprpc.FetchAssetMetaRequest{
			Asset: &taprpc.FetchAssetMetaRequest_AssetIdStr{AssetIdStr: hex.EncodeToString(assetID1Bytes)},
		}

		resp, err := server.FetchAssetMeta(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Len(t, resp.AssetMetas, 1)
		require.Equal(t, meta1.Data, resp.AssetMetas[0].Data)
		require.Equal(t, meta1.MetaHash(), resp.AssetMetas[0].MetaHash)
		require.Equal(t, int32(2), resp.DecimalDisplay)
	})

	t.Run("Fetch by Meta Hash - DecimalDisplay populated", func(t *testing.T) {
		mockBook := &mockAddrBook{}
		mockStore := &mockAssetStore{} // Not directly used by FetchAssetMetaByHash path

		mockBook.FetchAssetMetaByHashFunc = func(_ context.Context, hash [proof.MetaHashLen]byte) (*proof.MetaReveal, error) {
			require.Equal(t, meta1Hash, hash)
			return meta1, nil
		}

		server := newTestRpcServer(t, mockBook, mockStore)
		req := &taprpc.FetchAssetMetaRequest{
			Asset: &taprpc.FetchAssetMetaRequest_MetaHashStr{MetaHashStr: hex.EncodeToString(meta1Hash[:])},
		}

		resp, err := server.FetchAssetMeta(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Len(t, resp.AssetMetas, 1)
		require.Equal(t, meta1.Data, resp.AssetMetas[0].Data)
		require.Equal(t, meta1.MetaHash(), resp.AssetMetas[0].MetaHash)
		require.Equal(t, int32(2), resp.DecimalDisplay)
	})

	// Test cases for raw byte inputs
	t.Run("Fetch by Group Key (Raw Bytes) - Success", func(t *testing.T) {
		mockBook := &mockAddrBook{}
		mockStore := &mockAssetStore{}

		chainAsset2 := &asset.ChainAsset{
			Asset: asset.Asset{
				Version:  asset.V0,
				Genesis:  asset.Genesis{ID: assetID2, MetaHash: meta2.MetaHash()},
				GroupKey: &asset.GroupKey{GroupPubKey: *groupKey},
				ScriptKey: asset.ScriptKey{PubKey: &btcec.PublicKey{}},
			},
		}
		chainAsset3 := &asset.ChainAsset{
			Asset: asset.Asset{
				Version:  asset.V0,
				Genesis:  asset.Genesis{ID: assetID1, MetaHash: meta3.MetaHash()},
				GroupKey: &asset.GroupKey{GroupPubKey: *groupKey},
				ScriptKey: asset.ScriptKey{PubKey: &btcec.PublicKey{}},
			},
		}

		mockStore.FetchAllAssetsFunc = func(_ context.Context, _, _ bool, filters *tapdb.AssetQueryFilters) ([]*asset.ChainAsset, error) {
			require.NotNil(t, filters)
			require.NotNil(t, filters.AssetSpecifier)
			require.True(t, filters.AssetSpecifier.HasGroupPubKey())
			require.True(t, filters.AssetSpecifier.UnwrapGroupKeyToPtr().IsEqual(groupKey))
			return []*asset.ChainAsset{chainAsset2, chainAsset3}, nil
		}

		mockBook.FetchAssetMetaForAssetFunc = func(_ context.Context, id asset.ID) (*proof.MetaReveal, error) {
			if id == assetID2 {
				return meta2, nil
			}
			if id == assetID1 {
				return meta3, nil
			}
			return nil, fmt.Errorf("unexpected asset ID: %x", id)
		}

		server := newTestRpcServer(t, mockBook, mockStore)
		req := &taprpc.FetchAssetMetaRequest{
			Asset: &taprpc.FetchAssetMetaRequest_GroupKey{GroupKey: groupKeyBytes},
		}

		resp, err := server.FetchAssetMeta(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Len(t, resp.AssetMetas, 2)
		require.Equal(t, int32(2), resp.DecimalDisplay)
	})

	t.Run("Fetch by Asset ID (Raw Bytes) - DecimalDisplay populated", func(t *testing.T) {
		mockBook := &mockAddrBook{}
		mockStore := &mockAssetStore{}

		mockBook.FetchAssetMetaForAssetFunc = func(_ context.Context, id asset.ID) (*proof.MetaReveal, error) {
			require.Equal(t, assetID1, id)
			return meta1, nil
		}

		server := newTestRpcServer(t, mockBook, mockStore)
		req := &taprpc.FetchAssetMetaRequest{
			Asset: &taprpc.FetchAssetMetaRequest_AssetId{AssetId: assetID1Bytes},
		}

		resp, err := server.FetchAssetMeta(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Len(t, resp.AssetMetas, 1)
		require.Equal(t, meta1.Data, resp.AssetMetas[0].Data)
		require.Equal(t, meta1.MetaHash(), resp.AssetMetas[0].MetaHash)
		require.Equal(t, int32(2), resp.DecimalDisplay)
	})

	t.Run("Fetch by Meta Hash (Raw Bytes) - DecimalDisplay populated", func(t *testing.T) {
		mockBook := &mockAddrBook{}
		mockStore := &mockAssetStore{}

		mockBook.FetchAssetMetaByHashFunc = func(_ context.Context, hash [proof.MetaHashLen]byte) (*proof.MetaReveal, error) {
			require.Equal(t, meta1Hash, hash)
			return meta1, nil
		}

		server := newTestRpcServer(t, mockBook, mockStore)
		req := &taprpc.FetchAssetMetaRequest{
			Asset: &taprpc.FetchAssetMetaRequest_MetaHash{MetaHash: meta1Hash[:]},
		}

		resp, err := server.FetchAssetMeta(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Len(t, resp.AssetMetas, 1)
		require.Equal(t, meta1.Data, resp.AssetMetas[0].Data)
		require.Equal(t, meta1.MetaHash(), resp.AssetMetas[0].MetaHash)
		require.Equal(t, int32(2), resp.DecimalDisplay)
	})
}

// TODO: Add tests for invalid inputs (bad hex strings, wrong lengths) if not covered by main RPC error handling.
// These are implicitly tested by the main function's initial parsing, but dedicated unit tests for those
// specific error paths in FetchAssetMeta could be added if desired.
// The current tests focus on the logic after successful parsing of the request's oneof field.
