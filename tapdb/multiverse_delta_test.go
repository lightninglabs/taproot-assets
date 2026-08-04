package tapdb

import (
	"context"
	"testing"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/stretchr/testify/require"
)

// deltaUniverse pairs a universe identifier with the asset genesis all
// of its leaves share. The identifier is derived from the genesis
// (matching production, where a non-group universe ID is the genesis
// asset ID), so the id recovered from the delta rows agrees with the
// one used at insert time.
type deltaUniverse struct {
	id  universe.Identifier
	gen asset.Genesis
}

// newDeltaUniverse creates a universe descriptor of the given proof
// type, optionally group-keyed.
func newDeltaUniverse(t *testing.T, proofType universe.ProofType,
	withGroup bool) deltaUniverse {

	assetGen := asset.RandGenesis(t, asset.Normal)
	id := universe.Identifier{
		AssetID:   assetGen.ID(),
		ProofType: proofType,
	}
	if withGroup {
		id.GroupKey = test.RandPubKey(t)
	}

	return deltaUniverse{id: id, gen: assetGen}
}

// insertDeltaLeaf inserts a single random minting leaf into the given
// universe and returns the key and leaf that were inserted.
func insertDeltaLeaf(t *testing.T, ctx context.Context,
	store *MultiverseStore, u deltaUniverse) (universe.LeafKey,
	universe.Leaf) {

	key := randLeafKey(t)
	leaf := randMintingLeaf(t, u.gen, u.id.GroupKey)

	_, err := store.UpsertProofLeaf(ctx, u.id, key, &leaf, nil)
	require.NoError(t, err)

	return key, leaf
}

// TestMultiverseFetchLeavesSince tests that the insertion-ordered leaf
// delta query returns exactly the leaves inserted after a given
// sequence number, in insertion order, across universes.
func TestMultiverseFetchLeavesSince(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, _ := newTestMultiverse(t)

	// Create three universes: a plain issuance universe, a group-keyed
	// issuance universe, and a transfer universe.
	universes := []deltaUniverse{
		newDeltaUniverse(t, universe.ProofTypeIssuance, false),
		newDeltaUniverse(t, universe.ProofTypeIssuance, true),
		newDeltaUniverse(t, universe.ProofTypeTransfer, false),
	}

	// Insert three leaves per universe, interleaved, so insertion order
	// crosses universe boundaries.
	type inserted struct {
		id   universe.Identifier
		key  universe.LeafKey
		leaf universe.Leaf
	}
	var all []inserted
	for i := 0; i < 3; i++ {
		for _, u := range universes {
			key, leaf := insertDeltaLeaf(t, ctx, store, u)
			all = append(all, inserted{
				id: u.id, key: key, leaf: leaf,
			})
		}
	}

	// Fetching since zero should return every leaf, in insertion order.
	items, maxSeq, err := store.FetchLeavesSince(ctx, 0, 0)
	require.NoError(t, err)
	require.Len(t, items, len(all))

	for i, item := range items {
		require.Equal(t, all[i].id.Key(), item.ID.Key())
		require.Equal(
			t, all[i].key.UniverseKey(), item.Key.UniverseKey(),
		)
		require.Equal(
			t, []byte(all[i].leaf.RawProof),
			[]byte(item.Leaf.RawProof),
		)

		// Sequence numbers must be strictly increasing.
		if i > 0 {
			require.Greater(t, item.Seq, items[i-1].Seq)
		}
	}
	require.Equal(t, items[len(items)-1].Seq, maxSeq)

	// Fetching since a mid-point sequence returns exactly the suffix.
	midSeq := items[4].Seq
	suffix, suffixMax, err := store.FetchLeavesSince(ctx, midSeq, 0)
	require.NoError(t, err)
	require.Len(t, suffix, len(all)-5)
	require.Equal(t, items[5].Seq, suffix[0].Seq)
	require.Equal(t, maxSeq, suffixMax)

	// A limited fetch returns only the first leaves of the range.
	limited, limitedMax, err := store.FetchLeavesSince(ctx, 0, 4)
	require.NoError(t, err)
	require.Len(t, limited, 4)
	require.Equal(t, items[3].Seq, limitedMax)

	// Fetching from the high-water mark returns nothing and reports the
	// same sequence back.
	empty, emptyMax, err := store.FetchLeavesSince(ctx, maxSeq, 0)
	require.NoError(t, err)
	require.Empty(t, empty)
	require.Equal(t, maxSeq, emptyMax)

	// Re-upserting an existing leaf must not produce a new sequence
	// number: re-org style rewrites are invisible to the delta, which is
	// why root comparison stays authoritative.
	_, err = store.UpsertProofLeaf(
		ctx, all[0].id, all[0].key, &all[0].leaf, nil,
	)
	require.NoError(t, err)

	empty, emptyMax, err = store.FetchLeavesSince(ctx, maxSeq, 0)
	require.NoError(t, err)
	require.Empty(t, empty)
	require.Equal(t, maxSeq, emptyMax)
}
