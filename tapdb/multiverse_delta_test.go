package tapdb

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/universe"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
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

// TestMultiverseLeafJournalTailReport tests that an empty delta page
// reports the committed journal tail, allowing a caller whose cursor
// lies beyond the journal to detect the rewind.
func TestMultiverseLeafJournalTailReport(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, _ := newTestMultiverse(t)

	// On a store with no journal at all, any cursor reports tail
	// zero.
	items, maxSeq, err := store.FetchLeavesSince(ctx, 100, 0)
	require.NoError(t, err)
	require.Empty(t, items)
	require.Zero(t, maxSeq)

	// Insert a couple of leaves and locate the true tail.
	u := newDeltaUniverse(t, universe.ProofTypeIssuance, false)
	insertDeltaLeaf(t, ctx, store, u)
	insertDeltaLeaf(t, ctx, store, u)

	items, tail, err := store.FetchLeavesSince(ctx, 0, 0)
	require.NoError(t, err)
	require.Len(t, items, 2)

	// A cursor beyond the tail comes back empty with the tail itself
	// reported, strictly below the cursor.
	items, maxSeq, err = store.FetchLeavesSince(ctx, tail+50, 0)
	require.NoError(t, err)
	require.Empty(t, items)
	require.Equal(t, tail, maxSeq)
}

// TestMultiverseLeafJournalReupsertGap tests that a batch mixing an
// already-journaled leaf with a new one hands the new leaf a fresh seq
// while the re-upserted leaf keeps its original one, and that the
// resulting reserved-range gap does not disturb paging.
func TestMultiverseLeafJournalReupsertGap(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, _ := newTestMultiverse(t)

	u := newDeltaUniverse(t, universe.ProofTypeTransfer, false)
	key0, leaf0 := insertDeltaLeaf(t, ctx, store, u)

	items, seq0, err := store.FetchLeavesSince(ctx, 0, 0)
	require.NoError(t, err)
	require.Len(t, items, 1)

	// Batch: re-upsert the existing leaf together with a new one.
	key1 := randLeafKey(t)
	leaf1 := randMintingLeaf(t, u.gen, u.id.GroupKey)
	err = store.UpsertProofLeafBatch(ctx, []*universe.Item{
		{ID: u.id, Key: key0, Leaf: &leaf0},
		{ID: u.id, Key: key1, Leaf: &leaf1},
	})
	require.NoError(t, err)

	// Only the new leaf appears after the old tail, with a strictly
	// larger seq.
	items, maxSeq, err := store.FetchLeavesSince(ctx, seq0, 0)
	require.NoError(t, err)
	require.Len(t, items, 1)
	require.Equal(
		t, []byte(leaf1.RawProof), []byte(items[0].Leaf.RawProof),
	)
	require.Greater(t, items[0].Seq, seq0)
	require.Equal(t, items[0].Seq, maxSeq)

	// The caught-up cursor still reads as caught up despite any gap
	// left by the re-upsert's reserved seq.
	items, tail, err := store.FetchLeavesSince(ctx, maxSeq, 0)
	require.NoError(t, err)
	require.Empty(t, items)
	require.Equal(t, maxSeq, tail)
}

// TestMultiverseLeafJournalCommitOrder tests that journal seq order
// equals commit order under concurrent writers: a transaction that has
// journaled but not yet committed excludes later writers from
// journaling ahead of it, so a delta reader can never observe a seq
// while a lower unserved seq is still uncommitted.
func TestMultiverseLeafJournalCommitOrder(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, _ := newTestMultiverse(t)

	uniA := newDeltaUniverse(t, universe.ProofTypeIssuance, false)
	uniB := newDeltaUniverse(t, universe.ProofTypeTransfer, false)

	keyA := randLeafKey(t)
	leafA := randMintingLeaf(t, uniA.gen, uniA.id.GroupKey)

	// Writer A: insert and journal a leaf, then hold the transaction
	// open until released. The signal fires at most once even if the
	// executor retries the closure.
	var (
		journaledOnce sync.Once
		journaled     = make(chan struct{})
		release       = make(chan struct{})
		aDone         = make(chan error, 1)
	)
	go func() {
		var writeTx BaseMultiverseOptions
		aDone <- store.db.ExecTx(
			ctx, &writeTx,
			func(dbTx BaseMultiverseStore) error {
				_, _, leafID, err := universeUpsertProofLeaf(
					ctx, dbTx, uniA.id.String(),
					uniA.id.ProofType, uniA.id.GroupKey,
					keyA, &leafA, nil,
					lfn.None[uint32](),
				)
				if err != nil {
					return err
				}

				err = journalUniverseLeaves(
					ctx, dbTx, []int64{leafID},
				)
				if err != nil {
					return err
				}

				journaledOnce.Do(func() {
					close(journaled)
				})
				<-release

				return nil
			},
		)
	}()

	<-journaled

	// Writer B: a full single-leaf upsert through the public path. It
	// must not be able to commit ahead of A.
	bDone := make(chan error, 1)
	go func() {
		keyB := randLeafKey(t)
		leafB := randMintingLeaf(t, uniB.gen, uniB.id.GroupKey)
		_, err := store.UpsertProofLeaf(
			ctx, uniB.id, keyB, &leafB, nil,
		)
		bDone <- err
	}()

	// While A holds the journal tail, B stays blocked and a delta
	// reader sees an empty, tail-zero journal: nothing is committed
	// yet, so nothing may be served.
	select {
	case err := <-bDone:
		t.Fatalf("writer B committed ahead of held writer A: %v", err)
	case <-time.After(300 * time.Millisecond):
	}

	items, maxSeq, err := store.FetchLeavesSince(ctx, 0, 0)
	require.NoError(t, err)
	require.Empty(t, items)
	require.Zero(t, maxSeq)

	// Release A; both writers must now complete, and the delta must
	// serve A's leaf strictly before B's.
	close(release)
	require.NoError(t, <-aDone)
	require.NoError(t, <-bDone)

	items, _, err = store.FetchLeavesSince(ctx, 0, 0)
	require.NoError(t, err)
	require.Len(t, items, 2)
	require.Equal(t, uniA.id.Key(), items[0].ID.Key())
	require.Equal(t, uniB.id.Key(), items[1].ID.Key())
	require.Greater(t, items[1].Seq, items[0].Seq)
}
