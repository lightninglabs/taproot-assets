package fixture

import (
	"context"
	"testing"

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

	// The syncer over-fetches under the pointer-identity SetDiff bug
	// this PR is fixing (issue #2026): 5 leaves per root fetched even
	// though local already had 2 per root, so 25 leaves cross the
	// wire instead of the correct 15. Phase 1 tightens this to 15.
	require.EqualValues(t, 25, f.Metrics.LeavesInserted.Load())

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

// TestNewFraction_PanicOutOfRange guards the Fraction invariant.
func TestNewFraction_PanicOutOfRange(t *testing.T) {
	t.Parallel()

	require.Panics(t, func() { NewFraction(-0.01) })
	require.Panics(t, func() { NewFraction(1.01) })

	// Boundary values are valid.
	require.NotPanics(t, func() { NewFraction(0) })
	require.NotPanics(t, func() { NewFraction(1) })
}
