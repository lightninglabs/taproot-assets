package rpcserver

import (
	"errors"
	"sync"

	"github.com/lightninglabs/taproot-assets/universe"
	"google.golang.org/grpc/connectivity"
)

// ErrPoolClosed is returned from Get after the pool has been closed.
// Callers should treat it as a terminal signal: the daemon is shutting
// down, no further outbound universe RPCs should be issued.
var ErrPoolClosed = errors.New("universe conn pool is closed")

// ErrServerEvicted is returned from Get when Evict ran for the same
// address concurrently with the in-flight dial. Callers should treat
// it as transient — the federation member has been removed, so this
// push is moot; the next sync round will reconcile.
var ErrServerEvicted = errors.New(
	"universe server evicted during dial",
)

// dialerFn is the signature of the function the pool uses to obtain a
// fresh connection. Production code wires ConnectUniverse; tests in
// this package wire a controlled stub via newUniverseConnPool to
// exercise the in-flight-dial race paths deterministically.
type dialerFn func(universe.ServerAddr) (*universeClientConn, error)

// UniverseConnPool holds one *universeClientConn per remote universe
// server address. Connections are created lazily on first Get and
// reused for the lifetime of the pool. A single *grpc.ClientConn is
// safe for concurrent use; HTTP/2 multiplexes RPCs onto it.
//
// The pool is the substitute for the previous per-call dial pattern in
// FederationEnvoy.pushProofToServer, which opened a fresh
// grpc.ClientConn (and ran a fresh TLS handshake) for every leaf push
// and closed it after one InsertProof. With the pool, every leaf push
// to a given server reuses the same client connection.
type UniverseConnPool struct {
	mu     sync.Mutex
	conns  map[string]*universeClientConn
	closed bool

	// evictGens counts how many times Evict has been called per
	// address. Get snapshots this counter before unlocking to dial
	// and re-checks under the post-dial lock; a mismatch means
	// Evict ran during the dial, so the freshly-dialed conn is
	// closed and the caller sees ErrServerEvicted. This keeps the
	// invariant "after Evict(X) returns, no pooled connection
	// exists for X" — without it, an in-flight Get could install a
	// stale conn that Evict's map check could not see.
	evictGens map[string]uint64

	// dial is the function used to obtain a fresh connection. Set
	// once at construction and never mutated, so the pool is safe
	// for parallel test use without coordination.
	dial dialerFn
}

// NewUniverseConnPool constructs an empty pool that dials with
// ConnectUniverse. The pool is ready to hand out connections
// immediately; nothing is dialed up-front.
func NewUniverseConnPool() *UniverseConnPool {
	return newUniverseConnPool(ConnectUniverse)
}

// newUniverseConnPool is the package-private constructor used by tests
// to inject a controlled dial implementation. The public constructor
// wires ConnectUniverse; nothing outside this package can reach the
// dial seam.
func newUniverseConnPool(dial dialerFn) *UniverseConnPool {
	return &UniverseConnPool{
		conns:     make(map[string]*universeClientConn),
		evictGens: make(map[string]uint64),
		dial:      dial,
	}
}

// Get returns the pooled *universeClientConn for the given server
// address, dialing a fresh one if the pool has none. Returned
// connections are owned by the pool — callers must NOT call Close on
// them; lifecycle is managed via Evict and the pool's own Close.
//
// Get returns ErrPoolClosed if the pool has already been closed, and
// ErrServerEvicted if Evict ran for the same address while the dial
// was in flight. If a pooled connection has entered the gRPC
// connectivity.Shutdown state (permanent failure), Get drops it and
// dials fresh. Transient failures recover internally via gRPC's
// backoff machinery, so we don't second-guess them.
func (p *UniverseConnPool) Get(
	addr universe.ServerAddr) (*universeClientConn, error) {

	key := addr.HostStr()

	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, ErrPoolClosed
	}
	if c, ok := p.conns[key]; ok {
		if c.GetState() != connectivity.Shutdown {
			p.mu.Unlock()
			return c, nil
		}
		_ = c.ClientConn.Close()
		delete(p.conns, key)
	}
	gen := p.evictGens[key]
	p.mu.Unlock()

	// Dial outside the lock: a slow handshake against one address
	// must not block pool users hitting different addresses.
	conn, err := p.dial(addr)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		_ = conn.ClientConn.Close()
		return nil, ErrPoolClosed
	}

	// If Evict ran while we were dialing, drop the new conn so the
	// "post-Evict, no entry" invariant holds. The caller can retry
	// or, more usefully, observe that the federation member is
	// gone.
	if p.evictGens[key] != gen {
		_ = conn.ClientConn.Close()
		return nil, ErrServerEvicted
	}

	// Re-check in case a concurrent Get dialed the same address
	// while we were unlocked.
	if existing, ok := p.conns[key]; ok {
		_ = conn.ClientConn.Close()
		return existing, nil
	}
	p.conns[key] = conn
	return conn, nil
}

// Evict closes and drops the pooled connection for the given address,
// if any. Safe to call for an unknown address. Evict also bumps the
// per-address generation counter so any in-flight Get for the same
// address will see the eviction post-dial and skip pooling its result.
func (p *UniverseConnPool) Evict(addr universe.ServerAddr) {
	p.mu.Lock()
	defer p.mu.Unlock()

	key := addr.HostStr()
	if c, ok := p.conns[key]; ok {
		_ = c.ClientConn.Close()
		delete(p.conns, key)
	}
	p.evictGens[key]++
}

// Close drains the pool: every pooled connection is closed and the
// pool is marked closed so subsequent Get calls return ErrPoolClosed.
// Close is idempotent — calling it twice is safe and the second call
// is a no-op.
func (p *UniverseConnPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return
	}
	p.closed = true

	for _, c := range p.conns {
		_ = c.ClientConn.Close()
	}
	p.conns = nil
}
