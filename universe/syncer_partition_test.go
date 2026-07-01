package universe

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestPartitionByProofType_ExampleSplit is a compact example that
// documents the shape of partitionByProofType alongside the property
// tests in this file.
func TestPartitionByProofType_ExampleSplit(t *testing.T) {
	t.Parallel()

	roots := []Root{
		{ID: Identifier{ProofType: ProofTypeIssuance}},
		{ID: Identifier{ProofType: ProofTypeTransfer}},
		{ID: Identifier{ProofType: ProofTypeIssuance}},
		{ID: Identifier{ProofType: ProofTypeIssuance}},
		{ID: Identifier{ProofType: ProofTypeTransfer}},
		{ID: Identifier{ProofType: ProofTypeBurn}},
	}

	sorted := partitionByProofType(roots)
	require.Len(t, sorted.Issuance, 3)
	require.Len(t, sorted.Transfer, 2)
	require.Len(t, sorted.Other, 1)
}

// syncOrderRecorder is a minimal DiffEngine used to observe the order
// in which the syncer processes roots by proof type. RootNode is the
// first call syncRoot makes per root, so recording it there gives an
// accurate ordering trace.
//
// UniverseLeafKeys is stubbed to return an empty slice on both sides,
// which sends every root through the "no keys to fetch" fast path in
// syncRoot without touching the archive or the registrar.
type syncOrderRecorder struct {
	roots []Root
	mu    sync.Mutex
	order []ProofType
}

func (r *syncOrderRecorder) RootNode(_ context.Context,
	id Identifier) (Root, error) {

	r.mu.Lock()
	r.order = append(r.order, id.ProofType)
	r.mu.Unlock()

	// A short sleep after recording widens the window in which a
	// collapsed single-pool refactor would interleave transfer with
	// issuance. Without it the goroutine could return before any
	// racing goroutine had a chance to start recording, letting a
	// bad refactor pass by accident.
	time.Sleep(time.Millisecond)

	return Root{}, ErrNoUniverseRoot
}

func (r *syncOrderRecorder) RootNodes(_ context.Context,
	_ RootNodesQuery) ([]Root, error) {

	return r.roots, nil
}

func (r *syncOrderRecorder) UniverseLeafKeys(_ context.Context,
	_ UniverseLeafKeysQuery) ([]LeafKey, error) {

	return nil, nil
}

func (r *syncOrderRecorder) FetchProofLeaf(_ context.Context,
	_ Identifier, _ LeafKey) ([]*Proof, error) {

	return nil, nil
}

func (r *syncOrderRecorder) Close() error { return nil }

// noopRegistrar satisfies BatchRegistrar without doing anything. The
// ordering test never reaches the registrar because the diff comes up
// empty per root, but SimpleSyncCfg requires the field to be set.
type noopRegistrar struct{}

func (noopRegistrar) UpsertProofLeaf(_ context.Context, _ Identifier,
	_ LeafKey, _ *Leaf) (*Proof, error) {

	return nil, nil
}

func (noopRegistrar) UpsertProofLeafBatch(_ context.Context,
	_ []*Item) error {

	return nil
}

func (noopRegistrar) Close() error { return nil }

// TestExecuteSync_IssuanceBeforeTransfer is the direct regression for
// the ordering piece of issue #2026: with a mix of issuance and
// transfer roots on the remote, every issuance-typed root must reach
// syncRoot before any transfer-typed root does. The property is
// observed via a call log threaded through the LocalDiffEngine.
//
// SyncRootConcurrency is set well above the input size so that within
// a phase all roots race in parallel — the only reason issuance can
// still finish before transfer is the sequential invocation of the
// two syncRoots calls in executeSync. A refactor that collapsed the
// two calls into one bounded worker pool would fail this test even if
// partitionByProofType still returned roots in the right buckets.
func TestExecuteSync_IssuanceBeforeTransfer(t *testing.T) {
	t.Parallel()

	// Interleave issuance and transfer to catch any accidental
	// reliance on insertion order.
	var roots []Root
	for i := 0; i < 6; i++ {
		var id Identifier
		copy(id.AssetID[:], []byte{byte(i)})

		if i%2 == 0 {
			id.ProofType = ProofTypeIssuance
		} else {
			id.ProofType = ProofTypeTransfer
		}
		roots = append(roots, Root{ID: id})
	}

	local := &syncOrderRecorder{}
	remote := &syncOrderRecorder{roots: roots}

	syncer := NewSimpleSyncer(SimpleSyncCfg{
		LocalDiffEngine: local,
		LocalRegistrar:  noopRegistrar{},
		NewRemoteDiffEngine: func(_ ServerAddr) (DiffEngine, error) {
			return remote, nil
		},
		SyncBatchSize:       50,
		SyncRootConcurrency: 8,
	})

	_, err := syncer.SyncUniverse(
		context.Background(), ServerAddr{}, SyncFull,
		SyncConfigs{
			GlobalSyncConfigs: []*FedGlobalSyncConfig{
				{
					ProofType:       ProofTypeIssuance,
					AllowSyncInsert: true,
				},
				{
					ProofType:       ProofTypeTransfer,
					AllowSyncInsert: true,
				},
			},
		},
	)
	require.NoError(t, err)

	// Every issuance call must precede every transfer call. Since
	// the ordering fix runs the two sync phases sequentially, the
	// order slice partitions cleanly at the issuance/transfer
	// boundary.
	seenTransfer := false
	for _, pt := range local.order {
		if pt == ProofTypeTransfer {
			seenTransfer = true
			continue
		}
		if seenTransfer {
			t.Fatalf("issuance root observed after transfer "+
				"root; order=%v", local.order)
		}
	}

	// Sanity: every root was actually visited.
	require.Len(t, local.order, len(roots))
}
