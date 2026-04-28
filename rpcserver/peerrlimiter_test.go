package rpcserver

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

// mockAddr implements net.Addr for testing.
type mockAddr struct {
	addr string
}

func (m mockAddr) Network() string { return "tcp" }
func (m mockAddr) String() string  { return m.addr }

// peerCtx returns a context with gRPC peer info for the given
// IP address.
func peerCtx(ip string) context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{
		Addr: mockAddr{addr: net.JoinHostPort(ip, "12345")},
	})
}

// TestPeerRateLimiterIsolation verifies that different IPs get
// independent buckets and that exhausting one does not affect
// another.
func TestPeerRateLimiterIsolation(t *testing.T) {
	prl := NewPeerRateLimiter(rate.Limit(100), 10)
	defer prl.Stop()

	// Different IPs get different limiters.
	lA := prl.getLimiter("10.0.0.1")
	lB := prl.getLimiter("10.0.0.2")
	require.True(t, lA != lB,
		"different IPs should get different limiters")

	// Same IP reuses the same limiter.
	lA2 := prl.getLimiter("10.0.0.1")
	require.True(t, lA == lA2,
		"same IP should reuse its limiter")

	// Exhaust A's burst budget.
	for i := 0; i < 10; i++ {
		require.True(t, lA.Allow())
	}
	require.False(t, lA.Allow(), "A should be exhausted")

	// B is unaffected.
	require.True(t, lB.Allow(), "B should be unaffected")
}

// TestPeerRateLimiterWaitIsolation verifies the end-to-end Wait
// flow: peer A exhausting its budget does not block peer B.
func TestPeerRateLimiterWaitIsolation(t *testing.T) {
	// 1 QPS, burst 1 — very tight so we can observe blocking.
	prl := NewPeerRateLimiter(rate.Limit(1), 1)
	defer prl.Stop()

	ctxA := peerCtx("10.0.0.1")
	ctxB := peerCtx("10.0.0.2")

	// Peer A consumes its burst token.
	require.NoError(t, prl.Wait(ctxA))

	// Peer B succeeds immediately — tight deadline proves it
	// doesn't wait for A's token to replenish.
	ctxBTight, cancelB := context.WithTimeout(
		ctxB, 10*time.Millisecond,
	)
	defer cancelB()
	require.NoError(t, prl.Wait(ctxBTight),
		"peer B should not be blocked by peer A")

	// Peer A is rate limited — its own burst is exhausted.
	shortA, cancelA := context.WithTimeout(
		ctxA, 5*time.Millisecond,
	)
	defer cancelA()
	require.Error(t, prl.Wait(shortA),
		"peer A should be rate limited")
}

// TestPeerRateLimiterMetadataLoopback verifies that the client
// IP is extracted from gRPC metadata when the transport peer is
// loopback (i.e. the request came through the REST gateway).
func TestPeerRateLimiterMetadataLoopback(t *testing.T) {
	prl := NewPeerRateLimiter(rate.Limit(100), 10)
	defer prl.Stop()

	// Simulate a REST request: transport peer is localhost,
	// but metadata carries the real client IP.
	ctx := peer.NewContext(context.Background(), &peer.Peer{
		Addr: mockAddr{
			addr: net.JoinHostPort("127.0.0.1", "9999"),
		},
	})
	md := metadata.Pairs(ClientIPMetadataKey, "203.0.113.5")
	ctx = metadata.NewIncomingContext(ctx, md)

	require.NoError(t, prl.Wait(ctx))

	// The limiter should be keyed on the metadata IP, not
	// localhost.
	prl.mu.Lock()
	_, hasReal := prl.entries["203.0.113.5"]
	_, hasLocal := prl.entries["127.0.0.1"]
	prl.mu.Unlock()

	require.True(t, hasReal,
		"should be keyed on metadata IP")
	require.False(t, hasLocal,
		"should not be keyed on transport peer")
}

// TestPeerRateLimiterMetadataSpoofing verifies that a direct
// gRPC client (non-loopback peer) cannot spoof the client IP
// via metadata to rotate rate limit buckets.
func TestPeerRateLimiterMetadataSpoofing(t *testing.T) {
	prl := NewPeerRateLimiter(rate.Limit(100), 10)
	defer prl.Stop()

	// Direct gRPC client with a non-loopback peer sets
	// metadata trying to spoof a different IP.
	ctx := peer.NewContext(context.Background(), &peer.Peer{
		Addr: mockAddr{
			addr: net.JoinHostPort("198.51.100.7", "5555"),
		},
	})
	md := metadata.Pairs(ClientIPMetadataKey, "10.0.0.99")
	ctx = metadata.NewIncomingContext(ctx, md)

	require.NoError(t, prl.Wait(ctx))

	// Should be keyed on the real transport peer, not the
	// spoofed metadata value.
	prl.mu.Lock()
	_, hasReal := prl.entries["198.51.100.7"]
	_, hasSpoofed := prl.entries["10.0.0.99"]
	prl.mu.Unlock()

	require.True(t, hasReal,
		"should be keyed on transport peer")
	require.False(t, hasSpoofed,
		"spoofed metadata should be ignored")
}

// TestPeerRateLimiterNoPeer verifies that requests with no
// peer info fall back to a shared "unknown" bucket.
func TestPeerRateLimiterNoPeer(t *testing.T) {
	prl := NewPeerRateLimiter(rate.Limit(1), 1)
	defer prl.Stop()

	// No peer context — should use "unknown" key.
	require.NoError(t, prl.Wait(context.Background()))
}

// TestPeerRateLimiterCleanup verifies that stale entries are
// removed.
func TestPeerRateLimiterCleanup(t *testing.T) {
	prl := NewPeerRateLimiter(rate.Limit(100), 10)
	defer prl.Stop()

	ctx := peerCtx("10.0.0.99")
	require.NoError(t, prl.Wait(ctx))

	// Manually backdate the entry so it appears stale.
	prl.mu.Lock()
	entry := prl.entries["10.0.0.99"]
	entry.lastSeen = time.Now().Add(
		-peerLimiterStaleThreshold - time.Second,
	)
	prl.mu.Unlock()

	prl.cleanup()

	prl.mu.Lock()
	_, exists := prl.entries["10.0.0.99"]
	prl.mu.Unlock()

	require.False(t, exists, "stale entry should be removed")
}

// TestPeerRateLimiterEviction verifies that when the per-IP map
// is at capacity, the least-recently-seen entry is evicted to
// make room for the new IP.
func TestPeerRateLimiterEviction(t *testing.T) {
	prl := NewPeerRateLimiter(rate.Limit(100), 10)
	defer prl.Stop()

	// Fill the map to capacity. The first IP inserted will
	// have the oldest lastSeen.
	for i := 0; i < maxPeerLimiterEntries; i++ {
		ip := fmt.Sprintf("10.%d.%d.%d",
			(i>>16)&0xff, (i>>8)&0xff, i&0xff)
		prl.getLimiter(ip)
	}

	prl.mu.Lock()
	require.Equal(t, maxPeerLimiterEntries, len(prl.entries))

	// The first IP (oldest) should still be present.
	_, hasOldest := prl.entries["10.0.0.0"]
	require.True(t, hasOldest)
	prl.mu.Unlock()

	// Insert a new IP — should evict the oldest and keep
	// the map at capacity.
	l := prl.getLimiter("192.168.0.1")
	require.NotNil(t, l)

	prl.mu.Lock()
	require.Equal(t, maxPeerLimiterEntries, len(prl.entries),
		"map should not have grown")

	_, hasNew := prl.entries["192.168.0.1"]
	require.True(t, hasNew, "new IP should be present")

	_, hasOldest = prl.entries["10.0.0.0"]
	require.False(t, hasOldest,
		"oldest entry should have been evicted")
	prl.mu.Unlock()
}
