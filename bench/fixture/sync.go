package fixture

import (
	"context"
	"database/sql"
	"fmt"
	"math/rand"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	crand "crypto/rand"

	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightningnetwork/lnd/clock"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/stretchr/testify/require"
)

// SyncMetrics accumulates registrar-observable events across a run of
// SyncFixture. Every counter is written atomically because the syncer's
// fan-out invokes the registrar from multiple goroutines.
type SyncMetrics struct {
	// UpsertBatches counts calls into UpsertProofLeafBatch.
	UpsertBatches atomic.Int64

	// LeavesInserted counts the total number of leaves passed through
	// the registrar (single + batch, summed).
	LeavesInserted atomic.Int64

	// DBRetryErrors counts insertions that failed because the DB
	// transaction retry budget was exhausted — the "db tx retries
	// exceeded" symptom from issue #2026.
	DBRetryErrors atomic.Int64

	// DependencyMissing counts insertions that failed because a
	// referenced prior proof was not present locally. Only surfaces when
	// the registrar routes through the Archive verifier; the direct-
	// write registrar in this fixture will keep it at zero.
	DependencyMissing atomic.Int64
}

// Report emits the current counters to a bench via b.ReportMetric so
// each shows up as its own column in benchstat output.
func (m *SyncMetrics) Report(b *testing.B) {
	b.Helper()

	b.ReportMetric(
		float64(m.UpsertBatches.Load()), "upsert_batches",
	)
	b.ReportMetric(
		float64(m.LeavesInserted.Load()), "leaves_inserted",
	)
	b.ReportMetric(
		float64(m.DBRetryErrors.Load()), "db_retry_errs",
	)
	b.ReportMetric(
		float64(m.DependencyMissing.Load()), "dep_missing",
	)
}

// Fraction is a bounded float in [0, 1]. Construct via NewFraction to
// enforce the invariant. The zero value is 0 (valid).
type Fraction float64

// NewFraction returns f as a Fraction, panicking if f is outside
// [0, 1]. Bench setup failing loudly is preferable to a silently
// clamped value drifting the workload away from what the caller
// intended.
func NewFraction(f float64) Fraction {
	if f < 0 || f > 1 {
		panic(fmt.Sprintf("fixture: fraction %v out of [0, 1]", f))
	}
	return Fraction(f)
}

// RootSweep is a compact description of "N universes, each with M
// leaves." Used by SeedSpec to describe issuance- and transfer-typed
// roots separately.
type RootSweep struct {
	Roots  int
	Leaves int
}

// SeedSpec describes the shape of a seeded corpus. Issuance and
// Transfer are separate fields (rather than a flat list tagged by
// proof type) so a caller cannot accidentally interleave the two.
type SeedSpec struct {
	// Issuance describes the issuance-typed universes to create.
	Issuance RootSweep

	// Transfer describes the transfer-typed universes to create.
	Transfer RootSweep

	// LocalOverlap is the fraction of each remote root's leaves that
	// also get inserted into the local universe before sync. Zero means
	// the local side starts empty; one means the two sides are already
	// identical (and sync should be a no-op).
	LocalOverlap Fraction
}

// universePair is one side of the sync fixture. Each side has its own
// SQLite DB, multiverse store, and archive. The archive is what the
// syncer talks to as a DiffEngine.
type universePair struct {
	DB         *tapdb.SqliteStore
	Multiverse *tapdb.MultiverseStore
	Archive    *universe.Archive
}

// newUniversePair spins up a fresh SQLite-backed universe suitable for
// use as the local or remote side of a sync benchmark. Verifiers are
// mock (permissive) because the seed corpus is random and would not
// survive real chain-backed verification.
func newUniversePair(tb testing.TB, clk clock.Clock) *universePair {
	tb.Helper()

	db := tapdb.NewTestDB(tb)

	multiverseDB := tapdb.NewTransactionExecutor(
		db.BaseDB, func(tx *sql.Tx) tapdb.BaseMultiverseStore {
			return db.WithTx(tx)
		},
	)
	mv, err := tapdb.NewMultiverseStore(
		multiverseDB, tapdb.DefaultMultiverseStoreConfig(),
	)
	require.NoError(tb, err)

	uniDB := tapdb.NewTransactionExecutor(
		db.BaseDB, func(tx *sql.Tx) tapdb.BaseUniverseStore {
			return db.WithTx(tx)
		},
	)
	newBaseTree := func(id universe.Identifier) universe.StorageBackend {
		return tapdb.NewBaseUniverseTree(uniDB, id)
	}

	uniStatsDB := tapdb.NewTransactionExecutor(
		db.BaseDB, func(tx *sql.Tx) tapdb.UniverseStatsStore {
			return db.WithTx(tx)
		},
	)
	stats := tapdb.NewUniverseStats(uniStatsDB, clk)

	archive := universe.NewArchive(universe.ArchiveConfig{
		NewBaseTree:          newBaseTree,
		HeaderVerifier:       proof.MockHeaderVerifier,
		MerkleVerifier:       proof.DefaultMerkleVerifier,
		GroupVerifier:        proof.MockGroupVerifier,
		ChainLookupGenerator: proof.MockChainLookup,
		Multiverse:           mv,
		UniverseStats:        stats,
		IgnoreChecker:        lfn.None[proof.IgnoreChecker](),
	})

	return &universePair{
		DB:         db,
		Multiverse: mv,
		Archive:    archive,
	}
}

// directRegistrar is a BatchRegistrar that writes directly into the
// multiverse store, bypassing the Archive's per-proof verification
// pipeline. Two reasons:
//
//  1. Seed corpora are random proofs that would not survive real
//     proof.Verify; keeping verification off the write path lets us
//     bench the sync-side and DB-side work in isolation.
//  2. The DB transaction contention we care about happens inside
//     MultiverseStore.UpsertProofLeafBatch. Routing writes through the
//     archive would layer verifier work on top without changing the
//     contention pattern under measurement.
type directRegistrar struct {
	multiverse *tapdb.MultiverseStore
	metrics    *SyncMetrics
}

var _ universe.BatchRegistrar = (*directRegistrar)(nil)

func (r *directRegistrar) UpsertProofLeaf(ctx context.Context,
	id universe.Identifier, key universe.LeafKey,
	leaf *universe.Leaf) (*universe.Proof, error) {

	r.metrics.LeavesInserted.Add(1)
	p, err := r.multiverse.UpsertProofLeaf(ctx, id, key, leaf, nil)
	r.classify(err)
	return p, err
}

func (r *directRegistrar) UpsertProofLeafBatch(ctx context.Context,
	items []*universe.Item) error {

	r.metrics.UpsertBatches.Add(1)
	r.metrics.LeavesInserted.Add(int64(len(items)))
	err := r.multiverse.UpsertProofLeafBatch(ctx, items)
	r.classify(err)
	return err
}

func (r *directRegistrar) Close() error { return nil }

// classify categorises an insertion error into the per-symptom
// counters the bench reports. The upstream errors are string-wrapped
// via fmt.Errorf with no sentinel, so substring matching is what we
// have to work with.
func (r *directRegistrar) classify(err error) {
	if err == nil {
		return
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "db tx retries exceeded"):
		r.metrics.DBRetryErrors.Add(1)
	case strings.Contains(msg, "no universe proof found"):
		r.metrics.DependencyMissing.Add(1)
	}
}

// SyncFixtureOpts configures a SyncFixture. Zero fields fall back to
// the production defaults (batch=50, root-concurrency=2).
type SyncFixtureOpts struct {
	// SyncBatchSize is the leaf batch size passed to SimpleSyncer.
	SyncBatchSize int

	// SyncRootConcurrency caps the syncer's per-root fan-out.
	SyncRootConcurrency int
}

func (o SyncFixtureOpts) withDefaults() SyncFixtureOpts {
	if o.SyncBatchSize == 0 {
		o.SyncBatchSize = 50
	}
	if o.SyncRootConcurrency == 0 {
		o.SyncRootConcurrency = 2
	}
	return o
}

// SyncFixture pairs two in-process universes (local, remote) with a
// SimpleSyncer wired to treat one side as remote. Use it from a bench
// to drive SyncUniverse end-to-end without any network I/O.
type SyncFixture struct {
	Local   *universePair
	Remote  *universePair
	Syncer  *universe.SimpleSyncer
	Metrics *SyncMetrics
}

// NewSyncFixture constructs an unseeded SyncFixture. Call Seed to
// populate the two sides before running SyncUniverse.
func NewSyncFixture(tb testing.TB, opts SyncFixtureOpts) *SyncFixture {
	tb.Helper()

	opts = opts.withDefaults()

	// A fixed clock keeps timing-dependent paths deterministic across
	// bench runs.
	clk := clock.NewTestClock(time.Unix(1_700_000_000, 0))

	local := newUniversePair(tb, clk)
	remote := newUniversePair(tb, clk)

	metrics := &SyncMetrics{}

	syncer := universe.NewSimpleSyncer(universe.SimpleSyncCfg{
		LocalDiffEngine: local.Archive,
		LocalRegistrar: &directRegistrar{
			multiverse: local.Multiverse,
			metrics:    metrics,
		},
		NewRemoteDiffEngine: func(
			_ universe.ServerAddr) (universe.DiffEngine, error) {

			return remote.Archive, nil
		},
		SyncBatchSize:       opts.SyncBatchSize,
		SyncRootConcurrency: opts.SyncRootConcurrency,
	})

	return &SyncFixture{
		Local:   local,
		Remote:  remote,
		Syncer:  syncer,
		Metrics: metrics,
	}
}

// GlobalSyncConfig returns a SyncConfigs value that enables global
// insert for both proof types, matching the mainnet default a fresh
// tapd would use.
func GlobalSyncConfig() universe.SyncConfigs {
	return universe.SyncConfigs{
		GlobalSyncConfigs: []*universe.FedGlobalSyncConfig{
			{
				ProofType:       universe.ProofTypeIssuance,
				AllowSyncInsert: true,
				AllowSyncExport: true,
			},
			{
				ProofType:       universe.ProofTypeTransfer,
				AllowSyncInsert: true,
				AllowSyncExport: true,
			},
		},
	}
}

// Seed populates the fixture according to spec. Every remote root and
// leaf is inserted into the Remote side; a leading LocalOverlap
// fraction of each root's leaves is additionally inserted into the
// Local side, so the syncer sees a partial-overlap workload.
func (f *SyncFixture) Seed(tb testing.TB, spec SeedSpec) {
	tb.Helper()

	ctx := context.Background()

	seedType(tb, ctx, f, universe.ProofTypeIssuance, spec.Issuance,
		spec.LocalOverlap)
	seedType(tb, ctx, f, universe.ProofTypeTransfer, spec.Transfer,
		spec.LocalOverlap)
}

// seedType is the per-proof-type worker used by Seed.
func seedType(tb testing.TB, ctx context.Context, f *SyncFixture,
	pt universe.ProofType, sweep RootSweep, overlap Fraction) {

	tb.Helper()

	if sweep.Roots == 0 || sweep.Leaves == 0 {
		return
	}

	localCount := int(float64(sweep.Leaves) * float64(overlap))

	for r := 0; r < sweep.Roots; r++ {
		// All leaves under one root share a single asset genesis; the
		// universe identifier is derived from that same genesis so
		// insert-time and query-time namespaces agree. Deriving id
		// from the genesis (rather than choosing a random AssetID
		// independently) is what makes id.String() at read-time match
		// the namespace under which leaves were actually stored.
		assetGen := asset.RandGenesis(tb, asset.Normal)
		id := universe.Identifier{
			AssetID:   assetGen.ID(),
			ProofType: pt,
		}

		remoteItems := make([]*universe.Item, sweep.Leaves)
		for i := 0; i < sweep.Leaves; i++ {
			key := randLeafKey(tb)
			leaf := randMintingLeafFor(tb, assetGen)
			remoteItems[i] = &universe.Item{
				ID:   id,
				Key:  key,
				Leaf: leaf,
			}
		}

		err := f.Remote.Multiverse.UpsertProofLeafBatch(
			ctx, remoteItems,
		)
		require.NoError(tb, err)

		if localCount == 0 {
			continue
		}

		err = f.Local.Multiverse.UpsertProofLeafBatch(
			ctx, remoteItems[:localCount],
		)
		require.NoError(tb, err)
	}
}

// randLeafKey returns a random universe leaf key. Each call allocates
// a fresh *asset.ScriptKey, which is exactly the shape that reveals
// the pointer-identity diff bug when the returned keys are diffed via
// fn.SetDiff.
func randLeafKey(tb testing.TB) universe.LeafKey {
	tb.Helper()

	return universe.BaseLeafKey{
		OutPoint:  test.RandOp(tb),
		ScriptKey: fn.Ptr(asset.NewScriptKey(test.RandPubKey(tb))),
	}
}

// randMintingLeafFor returns a random universe leaf carrying a
// serialized proof. Every leaf under one universe root must share the
// same asset genesis, otherwise the multiverse's per-namespace bookkeeping
// would treat each leaf as belonging to a distinct universe.
func randMintingLeafFor(tb testing.TB,
	assetGen asset.Genesis) *universe.Leaf {

	tb.Helper()

	p := randProof(tb)
	p.Asset.Genesis = assetGen
	p.GenesisReveal = &assetGen

	leaf := &universe.Leaf{
		GenesisWithGroup: universe.GenesisWithGroup{
			Genesis: assetGen,
		},
		Asset: &p.Asset,
		Amt:   uint64(rand.Int31()), //nolint:gosec
	}

	proofBytes, err := p.Bytes()
	require.NoError(tb, err)
	leaf.RawProof = proofBytes

	return leaf
}

// randProof builds a minimal but structurally valid proof.Proof
// suitable for round-tripping through Bytes/Decode. The fields are
// random; the fixture uses mock verifiers so semantic validity is not
// required.
func randProof(tb testing.TB) *proof.Proof {
	tb.Helper()

	proofAsset := *asset.RandAsset(tb, asset.Normal)

	var witnessData [32]byte
	_, err := crand.Read(witnessData[:])
	require.NoError(tb, err)

	var pkScript [32]byte
	_, err = crand.Read(pkScript[:])
	require.NoError(tb, err)

	return &proof.Proof{
		PrevOut: wire.OutPoint{},
		BlockHeader: wire.BlockHeader{
			Timestamp: time.Unix(rand.Int63(), 0), //nolint:gosec
		},
		AnchorTx: wire.MsgTx{
			Version: 2,
			TxIn: []*wire.TxIn{{
				Witness: [][]byte{witnessData[:]},
			}},
			TxOut: []*wire.TxOut{{
				PkScript: pkScript[:],
				Value:    1000,
			}},
		},
		Asset: proofAsset,
		InclusionProof: proof.TaprootProof{
			InternalKey: test.RandPubKey(tb),
		},
		AltLeaves: asset.ToAltLeaves(asset.RandAltLeaves(tb, true)),
	}
}
