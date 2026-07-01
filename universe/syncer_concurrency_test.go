package universe

import (
	"context"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// concurrencyProbe is a DiffEngine that gates its RootNode call on a
// live gauge, so a test can observe how many syncRoot invocations are
// in flight at once. Each call blocks briefly to make racing
// invocations overlap in time and expose any limit violation.
type concurrencyProbe struct {
	roots []Root

	inFlight atomic.Int64
	peak     atomic.Int64
}

func (p *concurrencyProbe) RootNode(_ context.Context,
	_ Identifier) (Root, error) {

	n := p.inFlight.Add(1)
	for {
		peak := p.peak.Load()
		if n <= peak || p.peak.CompareAndSwap(peak, n) {
			break
		}
	}

	// A short sleep widens the window in which limit violations can
	// be observed. Without it a serial-looking invocation pattern
	// would only reflect the cost of the atomic ops.
	time.Sleep(2 * time.Millisecond)
	p.inFlight.Add(-1)

	return Root{}, ErrNoUniverseRoot
}

func (p *concurrencyProbe) RootNodes(_ context.Context,
	_ RootNodesQuery) ([]Root, error) {

	return p.roots, nil
}

func (p *concurrencyProbe) UniverseLeafKeys(_ context.Context,
	_ UniverseLeafKeysQuery) ([]LeafEntry, error) {

	return nil, nil
}

func (p *concurrencyProbe) FetchProofLeaf(_ context.Context,
	_ Identifier, _ LeafKey) ([]*Proof, error) {

	return nil, nil
}

func (p *concurrencyProbe) Close() error { return nil }

// TestSyncRoots_HonoursConcurrencyCap runs syncRoots with a probe
// that widens the observation window, asserts the peak observed
// concurrency never exceeds the limit, and covers a few limit values
// to catch off-by-ones.
func TestSyncRoots_HonoursConcurrencyCap(t *testing.T) {
	t.Parallel()

	for _, limit := range []int{1, 2, 4, 8} {
		limit := limit
		t.Run("limit="+strconv.Itoa(limit), func(t *testing.T) {
			t.Parallel()

			var roots []Root
			for i := 0; i < 16; i++ {
				var id Identifier
				id.ProofType = ProofTypeIssuance
				id.AssetID[0] = byte(i)
				roots = append(roots, Root{ID: id})
			}

			probe := &concurrencyProbe{roots: roots}
			remote := &syncOrderRecorder{roots: roots}

			syncer := NewSimpleSyncer(SimpleSyncCfg{
				LocalDiffEngine: probe,
				LocalRegistrar:  noopRegistrar{},
				NewRemoteDiffEngine: func(
					_ ServerAddr) (DiffEngine, error) {

					return remote, nil
				},
				SyncBatchSize:       50,
				SyncRootConcurrency: limit,
			})

			cfg := SyncConfigs{
				GlobalSyncConfigs: []*FedGlobalSyncConfig{{
					ProofType:       ProofTypeIssuance,
					AllowSyncInsert: true,
				}},
			}
			_, err := syncer.SyncUniverse(
				context.Background(), ServerAddr{},
				SyncFull, cfg,
			)
			require.NoError(t, err)

			peak := int(probe.peak.Load())
			require.LessOrEqual(t, peak, limit,
				"peak concurrency %d exceeded limit %d",
				peak, limit)
		})
	}
}

// TestNewSimpleSyncer_ClampsNonPositiveConcurrency pins that a config
// with an invalid SyncRootConcurrency (zero or negative) resolves to
// concurrency 1 rather than silently jamming with a zero-slot
// errgroup.
func TestNewSimpleSyncer_ClampsNonPositiveConcurrency(t *testing.T) {
	t.Parallel()

	for _, val := range []int{-1, 0} {
		s := NewSimpleSyncer(SimpleSyncCfg{
			LocalRegistrar:      noopRegistrar{},
			SyncBatchSize:       50,
			SyncRootConcurrency: val,
		})
		require.Equal(t, 1, s.cfg.SyncRootConcurrency,
			"input %d should clamp to 1", val)
	}
}
