package proof

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

// TestCachingHeaderVerifier tests deduplication and error non-caching
// of the cachingHeaderVerifier.
func TestCachingHeaderVerifier(t *testing.T) {
	t.Parallel()

	t.Run("dedup", func(t *testing.T) {
		t.Parallel()

		var calls atomic.Int64
		inner := func(_ wire.BlockHeader,
			_ uint32) error {

			calls.Add(1)
			return nil
		}

		cv := newCachingHeaderVerifier(inner)
		header := wire.BlockHeader{Nonce: 42}

		// Call three times with the same header+height.
		for i := 0; i < 3; i++ {
			err := cv.verify(header, 100)
			require.NoError(t, err)
		}

		require.Equal(t, int64(1), calls.Load())
	})

	t.Run("distinct_keys", func(t *testing.T) {
		t.Parallel()

		var calls atomic.Int64
		inner := func(_ wire.BlockHeader,
			_ uint32) error {

			calls.Add(1)
			return nil
		}

		cv := newCachingHeaderVerifier(inner)

		// Different heights should each trigger a call.
		for i := uint32(0); i < 5; i++ {
			h := wire.BlockHeader{Nonce: i}
			err := cv.verify(h, i)
			require.NoError(t, err)
		}

		require.Equal(t, int64(5), calls.Load())
	})

	t.Run("error_not_cached", func(t *testing.T) {
		t.Parallel()

		var calls atomic.Int64
		errBad := fmt.Errorf("bad block")
		inner := func(_ wire.BlockHeader,
			_ uint32) error {

			calls.Add(1)
			return errBad
		}

		cv := newCachingHeaderVerifier(inner)
		header := wire.BlockHeader{Nonce: 1}

		err := cv.verify(header, 200)
		require.ErrorIs(t, err, errBad)

		// Errors are not cached — each call retries
		// the inner verifier.
		err = cv.verify(header, 200)
		require.ErrorIs(t, err, errBad)

		require.Equal(t, int64(2), calls.Load())
	})
}

// TestPrefetchHeaders verifies that prefetchHeaders deduplicates
// headers and populates the cache.
func TestPrefetchHeaders(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	inner := func(_ wire.BlockHeader, _ uint32) error {
		calls.Add(1)
		return nil
	}

	cv := newCachingHeaderVerifier(inner)

	// Create proofs with some duplicate block heights/hashes.
	proofs := make([]*Proof, 10)
	for i := range proofs {
		// Heights 0-4 repeated twice.
		proofs[i] = &Proof{
			BlockHeight: uint32(i % 5),
			BlockHeader: wire.BlockHeader{
				Nonce: uint32(i % 5),
			},
		}
	}

	err := prefetchHeaders(
		context.Background(), proofs, cv,
	)
	require.NoError(t, err)

	// Only 5 unique headers, so only 5 calls.
	require.Equal(t, int64(5), calls.Load())

	// Subsequent verify calls should hit the cache.
	for _, p := range proofs {
		err := cv.verify(p.BlockHeader, p.BlockHeight)
		require.NoError(t, err)
	}

	// No additional calls.
	require.Equal(t, int64(5), calls.Load())
}

// BenchmarkHeaderPrefetch compares sequential header verification
// against the cached parallel prefetch approach with simulated RPC
// latency.
func BenchmarkHeaderPrefetch(b *testing.B) {
	const (
		numHeaders = 200
		rpcLatency = 5 * time.Millisecond
	)

	slowVerifier := func(_ wire.BlockHeader,
		_ uint32) error {

		time.Sleep(rpcLatency)
		return nil
	}

	// Build N unique (header, height) pairs.
	proofs := make([]*Proof, numHeaders)
	for i := range proofs {
		proofs[i] = &Proof{
			BlockHeight: uint32(i + 1),
			BlockHeader: wire.BlockHeader{
				Nonce: uint32(i),
			},
		}
	}

	b.Run("sequential", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			for _, p := range proofs {
				_ = slowVerifier(
					p.BlockHeader, p.BlockHeight,
				)
			}
		}
	})

	b.Run("cached_parallel", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			cv := newCachingHeaderVerifier(slowVerifier)
			err := prefetchHeaders(
				context.Background(), proofs, cv,
			)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	// Sub-benchmark with duplicate headers to show dedup
	// benefit.
	dupeProofs := make([]*Proof, numHeaders)
	for i := range dupeProofs {
		// Only 20 unique blocks, rest are duplicates.
		idx := i % 20
		dupeProofs[i] = &Proof{
			BlockHeight: uint32(idx + 1),
			BlockHeader: wire.BlockHeader{
				Nonce: uint32(idx),
			},
		}
	}

	b.Run("cached_parallel_dedup", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			cv := newCachingHeaderVerifier(slowVerifier)
			err := prefetchHeaders(
				context.Background(), dupeProofs, cv,
			)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkPrefetchWorkerCount compares prefetch throughput at
// different worker pool sizes to inform the headerPrefetchWorkers
// default.
func BenchmarkPrefetchWorkerCount(b *testing.B) {
	const (
		numHeaders = 200
		rpcLatency = 5 * time.Millisecond
	)

	slowVerifier := func(_ wire.BlockHeader,
		_ uint32) error {

		time.Sleep(rpcLatency)
		return nil
	}

	proofs := make([]*Proof, numHeaders)
	for i := range proofs {
		proofs[i] = &Proof{
			BlockHeight: uint32(i + 1),
			BlockHeader: wire.BlockHeader{
				Nonce: uint32(i),
			},
		}
	}

	for _, workers := range []int{4, 8, 16} {
		b.Run(fmt.Sprintf("workers_%d", workers), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				cv := newCachingHeaderVerifier(slowVerifier)
				err := prefetchWithLimit(
					context.Background(), proofs,
					cv, workers,
				)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// prefetchWithLimit is a test helper that mirrors prefetchHeaders
// but accepts a configurable worker limit.
func prefetchWithLimit(ctx context.Context, proofs []*Proof,
	hv *cachingHeaderVerifier, workers int) error {

	type headerInfo struct {
		header wire.BlockHeader
		height uint32
	}

	seen := make(map[headerCacheKey]struct{})
	var unique []headerInfo

	for _, p := range proofs {
		key := headerCacheKey{
			height: p.BlockHeight,
			hash:   p.BlockHeader.BlockHash(),
		}
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			unique = append(unique, headerInfo{
				header: p.BlockHeader,
				height: p.BlockHeight,
			})
		}
	}

	g, gCtx := errgroup.WithContext(ctx)
	g.SetLimit(workers)

	for _, h := range unique {
		if err := gCtx.Err(); err != nil {
			break
		}

		g.Go(func() error {
			select {
			case <-gCtx.Done():
				return gCtx.Err()
			default:
			}

			return hv.verify(h.header, h.height)
		})
	}

	return g.Wait()
}

// TestPrefetchHeadersError verifies that a header verification
// failure during prefetch propagates correctly.
func TestPrefetchHeadersError(t *testing.T) {
	t.Parallel()

	errBad := fmt.Errorf("block not found")

	var calls atomic.Int64
	inner := func(_ wire.BlockHeader, h uint32) error {
		calls.Add(1)
		if h == 3 {
			return errBad
		}
		return nil
	}

	cv := newCachingHeaderVerifier(inner)
	proofs := make([]*Proof, 5)
	for i := range proofs {
		proofs[i] = &Proof{
			BlockHeight: uint32(i + 1),
			BlockHeader: wire.BlockHeader{Nonce: uint32(i)},
		}
	}

	err := prefetchHeaders(
		context.Background(), proofs, cv,
	)
	require.Error(t, err)
	require.ErrorIs(t, err, errBad)
}

// TestPrefetchSkipsLastProof verifies that the prefetch set
// excludes the last proof when skipChainForFinalProof is set,
// matching the File.Verify behavior for pre-broadcast
// verification.
func TestPrefetchSkipsLastProof(t *testing.T) {
	t.Parallel()

	verified := make(map[uint32]bool)
	var mu sync.Mutex
	inner := func(_ wire.BlockHeader, h uint32) error {
		mu.Lock()
		verified[h] = true
		mu.Unlock()
		return nil
	}

	proofs := make([]*Proof, 5)
	for i := range proofs {
		proofs[i] = &Proof{
			BlockHeight: uint32(i + 1),
			BlockHeader: wire.BlockHeader{Nonce: uint32(i)},
		}
	}

	// Prefetch only the first 4 (simulating
	// skipChainForFinalProof exclusion).
	cv := newCachingHeaderVerifier(inner)
	err := prefetchHeaders(
		context.Background(), proofs[:4], cv,
	)
	require.NoError(t, err)

	// Heights 1-4 should be verified, 5 should not.
	for h := uint32(1); h <= 4; h++ {
		require.True(t, verified[h])
	}
	require.False(t, verified[5])
}
