package rpcserver

import (
	"context"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

const (
	// ClientIPMetadataKey is the gRPC metadata key used to
	// propagate the original client IP from the REST gateway
	// to the gRPC server. Exported so server.go can set it
	// via grpc-gateway's WithMetadata option.
	ClientIPMetadataKey = "x-real-ip"

	// peerLimiterCleanupInterval is how often we scan for and
	// remove stale per-peer rate limiter entries.
	peerLimiterCleanupInterval = 5 * time.Minute

	// peerLimiterStaleThreshold is how long a peer entry must
	// be idle before it is eligible for removal.
	peerLimiterStaleThreshold = 10 * time.Minute

	// maxPeerLimiterEntries is the maximum number of per-IP
	// entries. When the map is at capacity, the
	// least-recently-seen entry is evicted to make room.
	maxPeerLimiterEntries = 10_000

	// globalLimiterMultiplier scales the per-IP rate to
	// produce the global aggregate rate cap. High enough
	// that normal multi-client traffic never hits it, low
	// enough to bound pathological aggregate load.
	globalLimiterMultiplier = 100
)

// peerLimiterEntry holds a rate limiter and the last time it was
// accessed.
type peerLimiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// PeerRateLimiter maintains a separate rate.Limiter per client IP
// so that one client cannot starve others. A high-rate global
// limiter caps pathological aggregate load.
type PeerRateLimiter struct {
	mu      sync.Mutex
	entries map[string]*peerLimiterEntry

	// global caps aggregate query rate across all clients.
	// Set to globalLimiterMultiplier * per-IP rate so normal
	// multi-client traffic is unaffected.
	global *rate.Limiter

	rateLimit rate.Limit
	burst     int

	quit chan struct{}
	wg   sync.WaitGroup
}

// NewPeerRateLimiter creates a new per-peer rate limiter. Each
// peer gets its own token bucket with the given rate and burst.
// A global limiter at globalLimiterMultiplier * r caps aggregate
// load as a circuit breaker.
func NewPeerRateLimiter(r rate.Limit,
	burst int) *PeerRateLimiter {

	globalRate := rate.Limit(
		float64(r) * globalLimiterMultiplier,
	)
	globalBurst := burst * globalLimiterMultiplier

	prl := &PeerRateLimiter{
		entries:   make(map[string]*peerLimiterEntry),
		global:    rate.NewLimiter(globalRate, globalBurst),
		rateLimit: r,
		burst:     burst,
		quit:      make(chan struct{}),
	}

	prl.wg.Add(1)
	go prl.cleanupLoop()

	return prl
}

// Wait blocks until the per-peer rate limiter for the caller
// (identified by IP from gRPC peer context) allows the event,
// then checks the global aggregate limiter. If the context has
// no peer info, a shared "unknown" bucket is used.
func (p *PeerRateLimiter) Wait(ctx context.Context) error {
	ip := peerIP(ctx)
	limiter := p.getLimiter(ip)

	// Per-IP limit (fairness / isolation).
	if err := limiter.Wait(ctx); err != nil {
		return err
	}

	// Global limit (aggregate circuit breaker).
	return p.global.Wait(ctx)
}

// Stop shuts down the background cleanup goroutine.
func (p *PeerRateLimiter) Stop() {
	close(p.quit)
	p.wg.Wait()
}

// getLimiter returns the rate limiter for the given IP, creating
// one if it doesn't exist yet. If the map is at capacity, the
// least-recently-seen entry is evicted to make room.
func (p *PeerRateLimiter) getLimiter(ip string) *rate.Limiter {
	p.mu.Lock()
	defer p.mu.Unlock()

	entry, ok := p.entries[ip]
	if ok {
		entry.lastSeen = time.Now()
		return entry.limiter
	}

	// Map at capacity — evict the least-recently-seen entry.
	if len(p.entries) >= maxPeerLimiterEntries {
		p.evictOldest()
	}

	entry = &peerLimiterEntry{
		limiter:  rate.NewLimiter(p.rateLimit, p.burst),
		lastSeen: time.Now(),
	}
	p.entries[ip] = entry

	return entry.limiter
}

// evictOldest removes the entry with the oldest lastSeen time.
// Must be called with p.mu held.
func (p *PeerRateLimiter) evictOldest() {
	var oldestIP string
	var oldestTime time.Time

	for ip, entry := range p.entries {
		if oldestIP == "" ||
			entry.lastSeen.Before(oldestTime) {

			oldestIP = ip
			oldestTime = entry.lastSeen
		}
	}

	if oldestIP != "" {
		delete(p.entries, oldestIP)
	}
}

// cleanupLoop periodically removes stale entries from the map.
func (p *PeerRateLimiter) cleanupLoop() {
	defer p.wg.Done()

	ticker := time.NewTicker(peerLimiterCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.cleanup()

		case <-p.quit:
			return
		}
	}
}

// cleanup removes entries that have not been seen recently.
func (p *PeerRateLimiter) cleanup() {
	p.mu.Lock()
	defer p.mu.Unlock()

	threshold := time.Now().Add(-peerLimiterStaleThreshold)
	for ip, entry := range p.entries {
		if entry.lastSeen.Before(threshold) {
			delete(p.entries, ip)
		}
	}
}

// peerIP extracts the client IP from the gRPC context. For
// requests arriving via the REST gateway (loopback transport
// peer), it uses the ClientIPMetadataKey set by the gateway.
// For direct gRPC clients, it uses the transport peer and
// ignores any metadata to prevent spoofing.
func peerIP(ctx context.Context) string {
	// Extract the transport peer first — we need it both
	// as the primary key for direct clients and to decide
	// whether to trust metadata.
	var transportIP string
	if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
		transportIP = p.Addr.String()
		if host, _, err := net.SplitHostPort(
			transportIP,
		); err == nil {
			transportIP = host
		}
	}

	// Only trust metadata when the transport peer is
	// loopback, i.e. the request came through the local
	// grpc-gateway. Direct gRPC clients could set this
	// header to arbitrary values to rotate buckets.
	if isLoopback(transportIP) {
		if md, ok := metadata.FromIncomingContext(ctx); ok {
			vals := md.Get(ClientIPMetadataKey)
			if len(vals) > 0 {
				ip := vals[0]
				if host, _, err := net.SplitHostPort(
					ip,
				); err == nil {
					ip = host
				}
				if ip != "" {
					return ip
				}
			}
		}
	}

	if transportIP != "" {
		return transportIP
	}

	return "unknown"
}

// isLoopback reports whether ip is a loopback address.
func isLoopback(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.IsLoopback()
}

// AnnotateClientIP is a grpc-gateway metadata annotator that
// extracts the client IP from the HTTP request and attaches it
// as gRPC metadata. This allows the per-IP rate limiter to
// distinguish REST clients that would otherwise all appear as
// localhost.
func AnnotateClientIP(_ context.Context,
	req *http.Request) metadata.MD {

	ip := req.RemoteAddr
	if host, _, err := net.SplitHostPort(ip); err == nil {
		ip = host
	}

	return metadata.Pairs(ClientIPMetadataKey, ip)
}
