package rpcserver

import (
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightningnetwork/lnd/cert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

// noopUniServer is a minimal UniverseServer used only so a TLS gRPC
// listener has something to register; the tests never actually exercise
// any RPCs against it.
type noopUniServer struct {
	universerpc.UnimplementedUniverseServer
}

// startTestUniverseServer stands up an in-process TLS gRPC universe
// server on a free loopback port for one test. Returns its address;
// cleanup is registered with t.
func startTestUniverseServer(t *testing.T) universe.ServerAddr {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	certBytes, keyBytes, err := cert.GenCertPair(
		"pool test cert", nil, nil, false, time.Hour,
	)
	require.NoError(t, err)

	tlsCert, _, err := cert.LoadCertFromBytes(certBytes, keyBytes)
	require.NoError(t, err)

	tlsConf := cert.TLSConfFromCert(tlsCert)
	tlsConf.NextProtos = []string{"h2"}

	tlsLis := tls.NewListener(lis, tlsConf)
	srv := grpc.NewServer()
	universerpc.RegisterUniverseServer(srv, noopUniServer{})

	go func() { _ = srv.Serve(tlsLis) }()
	t.Cleanup(func() {
		srv.Stop()
		_ = tlsLis.Close()
	})

	return universe.NewServerAddrFromStr(lis.Addr().String())
}

// TestUniverseConnPoolGetReuses confirms repeated Get for the same
// address returns the same underlying *universeClientConn.
func TestUniverseConnPoolGetReuses(t *testing.T) {
	addr := startTestUniverseServer(t)
	pool := NewUniverseConnPool()
	defer pool.Close()

	c1, err := pool.Get(addr)
	require.NoError(t, err)

	c2, err := pool.Get(addr)
	require.NoError(t, err)

	require.Same(t, c1, c2)
}

// TestUniverseConnPoolDistinctAddrs confirms that distinct addresses
// get distinct pooled connections.
func TestUniverseConnPoolDistinctAddrs(t *testing.T) {
	a := startTestUniverseServer(t)
	b := startTestUniverseServer(t)

	pool := NewUniverseConnPool()
	defer pool.Close()

	ca, err := pool.Get(a)
	require.NoError(t, err)

	cb, err := pool.Get(b)
	require.NoError(t, err)

	require.NotSame(t, ca, cb)
}

// TestUniverseConnPoolEvictRemoves confirms that after Evict, the next
// Get for the same address dials a fresh connection.
func TestUniverseConnPoolEvictRemoves(t *testing.T) {
	addr := startTestUniverseServer(t)
	pool := NewUniverseConnPool()
	defer pool.Close()

	c1, err := pool.Get(addr)
	require.NoError(t, err)

	pool.Evict(addr)

	c2, err := pool.Get(addr)
	require.NoError(t, err)
	require.NotSame(t, c1, c2)
}

// TestUniverseConnPoolDoubleCloseSafe confirms calling Close twice is
// safe and idempotent.
func TestUniverseConnPoolDoubleCloseSafe(t *testing.T) {
	addr := startTestUniverseServer(t)
	pool := NewUniverseConnPool()

	_, err := pool.Get(addr)
	require.NoError(t, err)

	pool.Close()
	require.NotPanics(t, pool.Close)
}

// TestUniverseConnPoolGetAfterClose confirms that Get after Close
// returns ErrPoolClosed and does not leak a connection in the now-nil
// internal map.
func TestUniverseConnPoolGetAfterClose(t *testing.T) {
	addr := startTestUniverseServer(t)
	pool := NewUniverseConnPool()
	pool.Close()

	_, err := pool.Get(addr)
	require.ErrorIs(t, err, ErrPoolClosed)
}

// TestUniverseConnPoolEvictDuringDial exercises the race fix: Evict
// runs while Get is mid-dial (with no pre-existing map entry to
// remove); the post-dial generation check must detect the eviction,
// close the freshly-dialed conn, and return ErrServerEvicted to the
// caller. Without the generation counter, Get would silently install
// the conn for an address Evict was supposed to have purged.
func TestUniverseConnPoolEvictDuringDial(t *testing.T) {
	addr := startTestUniverseServer(t)

	dialReleased := make(chan struct{})
	evictRan := make(chan struct{})

	// Construct a pool with a controlled dialer that blocks until
	// the test signals release. By the time it does, Evict will
	// have bumped the generation counter — exercising the race fix.
	pool := newUniverseConnPool(func(
		a universe.ServerAddr) (*universeClientConn, error) {

		close(evictRan)
		<-dialReleased
		return ConnectUniverse(a)
	})
	defer pool.Close()

	var (
		wg      sync.WaitGroup
		getErr  error
		getConn *universeClientConn
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		getConn, getErr = pool.Get(addr)
	}()

	// Wait for Get to be in the dial step, then Evict.
	<-evictRan
	pool.Evict(addr)
	close(dialReleased)

	wg.Wait()

	require.Nil(t, getConn)
	require.True(t, errors.Is(getErr, ErrServerEvicted),
		"got %v", getErr)

	// The pool must not have an entry for the evicted address.
	// A subsequent Get should dial fresh — and now that the test
	// hook is restored on the next test, behave normally.
	require.Len(t, pool.conns, 0)
}

// TestUniverseConnPoolShutdownRedials confirms that a pooled
// connection whose underlying ClientConn has transitioned to the
// connectivity.Shutdown state (e.g. its own Close was called) gets
// dropped from the pool and the next Get dials fresh.
func TestUniverseConnPoolShutdownRedials(t *testing.T) {
	addr := startTestUniverseServer(t)
	pool := NewUniverseConnPool()
	defer pool.Close()

	c1, err := pool.Get(addr)
	require.NoError(t, err)

	// Close the underlying ClientConn directly. This transitions
	// it to connectivity.Shutdown — exactly the state Get is meant
	// to detect and replace.
	_ = c1.ClientConn.Close()

	c2, err := pool.Get(addr)
	require.NoError(t, err)
	require.NotSame(t, c1, c2)
}
