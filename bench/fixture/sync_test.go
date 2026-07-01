package fixture

import (
	"context"
	"math/rand"
	"testing"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/stretchr/testify/require"
)

// TestSyncFixture_EndToEnd exercises the sync fixture end to end: it
// seeds the remote with a mix of issuance and transfer roots, seeds
// half the leaves into the local side, then drives one SyncUniverse
// call. Passing means the local + remote wiring, the seeded random
// proofs, and the direct-write registrar all agree.
func TestSyncFixture_EndToEnd(t *testing.T) {
	t.Parallel()

	f := NewSyncFixture(t, SyncFixtureOpts{})
	f.Seed(t, SeedSpec{
		Issuance:     RootSweep{Roots: 3, Leaves: 5},
		Transfer:     RootSweep{Roots: 2, Leaves: 5},
		LocalOverlap: NewFraction(0.4),
	})

	ctx := context.Background()

	_, err := f.Syncer.SyncUniverse(
		ctx, universe.ServerAddr{}, universe.SyncFull,
		GlobalSyncConfig(),
	)
	require.NoError(t, err)

	// One batch call per root (5 roots, all diverge).
	require.EqualValues(t, 5, f.Metrics.UpsertBatches.Load())

	// With the content-based diff in place, only the new leaves cross
	// over: 5 roots x (5 remote - 2 local overlap) = 15.
	require.EqualValues(t, 15, f.Metrics.LeavesInserted.Load())

	// No DB retries or dep-missing errors should surface at this scale.
	require.Zero(t, f.Metrics.DBRetryErrors.Load())
	require.Zero(t, f.Metrics.DependencyMissing.Load())
}

// TestSyncFixture_FullOverlap covers the degenerate case where local
// already has every leaf remote has. The syncer should observe no
// leaves to insert — a direct check that seeding is symmetric across
// the two sides for the overlapping prefix.
func TestSyncFixture_FullOverlap(t *testing.T) {
	t.Parallel()

	f := NewSyncFixture(t, SyncFixtureOpts{})
	f.Seed(t, SeedSpec{
		Issuance:     RootSweep{Roots: 2, Leaves: 3},
		LocalOverlap: NewFraction(1),
	})

	ctx := context.Background()
	_, err := f.Syncer.SyncUniverse(
		ctx, universe.ServerAddr{}, universe.SyncFull,
		GlobalSyncConfig(),
	)
	require.NoError(t, err)

	// With full overlap, roots are identical and the syncer's early
	// exit at syncer.go:302 fires per root — no writes should occur.
	require.Zero(t, f.Metrics.UpsertBatches.Load())
	require.Zero(t, f.Metrics.LeavesInserted.Load())
}

// TestSyncFixture_StaleContentAtSharedKeys covers the re-org shape:
// remote and local hold leaves at the same (outpoint, script_key) but
// with different content. The syncer's LeafEntry diff carries each
// leaf's canonical H(value || sum) node hash, so a shared key with
// disagreeing content surfaces as a normal diff entry and its
// remote-side leaf gets fetched. Regression for the
// TestTaprootAssetsDaemon/tranche07/re-org_mint itest.
func TestSyncFixture_StaleContentAtSharedKeys(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	f := NewSyncFixture(t, SyncFixtureOpts{})

	// Both sides share a single universe with two shared leaf keys but
	// distinct leaf contents. randMintingLeafFor allocates a fresh
	// proof each time, so remote.Amt and local.Amt differ with
	// overwhelming probability — sufficient to force different SMT
	// leaf hashes at the same key.
	assetGen := asset.RandGenesis(t, asset.Normal)
	id := universe.Identifier{
		AssetID:   assetGen.ID(),
		ProofType: universe.ProofTypeIssuance,
	}

	const numLeaves = 2
	keys := make([]universe.LeafKey, numLeaves)
	remoteItems := make([]*universe.Item, numLeaves)
	localItems := make([]*universe.Item, numLeaves)
	for i := 0; i < numLeaves; i++ {
		keys[i] = randLeafKey(t)
		remoteItems[i] = &universe.Item{
			ID:   id,
			Key:  keys[i],
			Leaf: randMintingLeafFor(t, assetGen),
		}

		// Local leaf shares the key but carries a different Amt (and
		// therefore a different SMT leaf hash) than the remote leaf.
		staleLeaf := randMintingLeafFor(t, assetGen)
		for staleLeaf.Amt == remoteItems[i].Leaf.Amt {
			staleLeaf.Amt = uint64(rand.Int31()) //nolint:gosec
		}
		localItems[i] = &universe.Item{
			ID:   id,
			Key:  keys[i],
			Leaf: staleLeaf,
		}
	}

	require.NoError(t, f.Remote.Multiverse.UpsertProofLeafBatch(
		ctx, remoteItems,
	))
	require.NoError(t, f.Local.Multiverse.UpsertProofLeafBatch(
		ctx, localItems,
	))

	_, err := f.Syncer.SyncUniverse(
		ctx, universe.ServerAddr{}, universe.SyncFull,
		GlobalSyncConfig(),
	)
	require.NoError(t, err)

	// Every shared key showed up in the diff (differing content
	// hashes) and its remote-side leaf was fetched and reinserted.
	require.EqualValues(t, numLeaves, f.Metrics.LeavesInserted.Load())

	// And the underlying content actually got overwritten — post-sync,
	// local's leaf Amt values match remote's.
	for i, key := range keys {
		proofs, err := f.Local.Multiverse.FetchProofLeaf(
			ctx, id, key,
		)
		require.NoError(t, err)
		require.Len(t, proofs, 1)
		require.Equal(t, remoteItems[i].Leaf.Amt, proofs[0].Leaf.Amt)
	}
}

// TestSyncFixture_RemoteBehindPeer covers the peer-is-behind shape:
// remote's leaf-key set is a strict subset of local's, so the two
// roots diverge but the LeafEntry diff finds no remote-only or
// content-differing entries. No leaves must be fetched or upserted;
// the syncer must not busy-loop refetching every remote leaf on
// each pass. Regression against the empty-diff-refetch pathology
// this branch's LeafEntry work replaces.
func TestSyncFixture_RemoteBehindPeer(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	f := NewSyncFixture(t, SyncFixtureOpts{})

	assetGen := asset.RandGenesis(t, asset.Normal)
	id := universe.Identifier{
		AssetID:   assetGen.ID(),
		ProofType: universe.ProofTypeIssuance,
	}

	// Build 5 shared leaves — same key and same leaf on both sides.
	const numShared = 5
	shared := make([]*universe.Item, numShared)
	for i := 0; i < numShared; i++ {
		shared[i] = &universe.Item{
			ID:   id,
			Key:  randLeafKey(t),
			Leaf: randMintingLeafFor(t, assetGen),
		}
	}

	// Local additionally holds 3 leaves the remote does not — this
	// is what makes the roots diverge while keeping remote's keyset
	// a strict subset of local's.
	const numExtra = 3
	extras := make([]*universe.Item, numExtra)
	for i := 0; i < numExtra; i++ {
		extras[i] = &universe.Item{
			ID:   id,
			Key:  randLeafKey(t),
			Leaf: randMintingLeafFor(t, assetGen),
		}
	}

	require.NoError(t, f.Remote.Multiverse.UpsertProofLeafBatch(
		ctx, shared,
	))
	require.NoError(t, f.Local.Multiverse.UpsertProofLeafBatch(
		ctx, append(shared, extras...),
	))

	_, err := f.Syncer.SyncUniverse(
		ctx, universe.ServerAddr{}, universe.SyncFull,
		GlobalSyncConfig(),
	)
	require.NoError(t, err)

	// No leaves crossed over: shared entries match by content and
	// local-only entries have no remote counterpart to fetch.
	require.Zero(t, f.Metrics.LeavesInserted.Load())
	require.Zero(t, f.Metrics.UpsertBatches.Load())
}

// TestNewFraction_PanicOutOfRange guards the Fraction invariant.
func TestNewFraction_PanicOutOfRange(t *testing.T) {
	t.Parallel()

	require.Panics(t, func() { NewFraction(-0.01) })
	require.Panics(t, func() { NewFraction(1.01) })

	// Boundary values are valid.
	require.NotPanics(t, func() { NewFraction(0) })
	require.NotPanics(t, func() { NewFraction(1) })
}
