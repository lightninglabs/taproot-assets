// Package wire contains benchmarks that measure the cost of going through
// the gRPC stack — serialization, interceptors, in-process transport —
// for a representative set of RPCs. The point is to characterise the
// per-call gRPC overhead once; the per-RPC benches under bench/rpc/ skip
// the wire and call handlers directly so their numbers reflect subsystem
// cost only.
package wire

import (
	"context"
	"net"
	"testing"

	"github.com/lightninglabs/taproot-assets/bench/fixture"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

// bufSize is the size of the bufconn buffer. 1 MiB is plenty for any RPC
// payload these benches exercise.
const bufSize = 1 << 20

// newWireFixture spins up a Storage fixture, attaches its RPCServer to an
// in-memory bufconn gRPC server, and returns a client connected over that
// pipe. Cleanup is registered with tb.
func newWireFixture(tb testing.TB) (
	taprpc.TaprootAssetsClient, *fixture.Storage) {

	tb.Helper()
	f := fixture.NewStorage(tb)

	lis := bufconn.Listen(bufSize)
	srv := grpc.NewServer()
	require.NoError(tb, f.Server.RegisterWithGrpcServer(srv))

	go func() { _ = srv.Serve(lis) }()
	tb.Cleanup(srv.Stop)

	dialer := func(_ context.Context, _ string) (net.Conn, error) {
		return lis.Dial()
	}
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(tb, err)
	tb.Cleanup(func() { _ = conn.Close() })

	client := taprpc.NewTaprootAssetsClient(conn)

	// Warm the connection. grpc.NewClient is lazy — the underlying
	// transport is not established until the first RPC. With
	// -benchtime=1x the entire bench would otherwise time the connect
	// + TLS-less handshake instead of the per-call cost. We use
	// DebugLevel because it is the cheapest server-side handler that
	// the Storage fixture can serve.
	_, err = client.DebugLevel(
		context.Background(),
		&taprpc.DebugLevelRequest{Show: true},
	)
	require.NoError(tb, err)

	return client, f
}

// BenchmarkWireDebugLevel measures the gRPC overhead for a near-trivial
// handler (DebugLevel) — isolates wire + interceptor + marshal cost from
// subsystem work.
func BenchmarkWireDebugLevel(b *testing.B) {
	client, _ := newWireFixture(b)
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := client.DebugLevel(ctx, &taprpc.DebugLevelRequest{
			Show: true,
		})
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkWireListAssets measures gRPC overhead for an empty ListAssets
// (the smallest payload that still touches a db read path).
func BenchmarkWireListAssets(b *testing.B) {
	client, _ := newWireFixture(b)
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := client.ListAssets(ctx, &taprpc.ListAssetRequest{})
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkWireQueryAddrs measures gRPC overhead for an empty QueryAddrs.
func BenchmarkWireQueryAddrs(b *testing.B) {
	client, _ := newWireFixture(b)
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := client.QueryAddrs(ctx, &taprpc.QueryAddrRequest{})
		if err != nil {
			b.Fatal(err)
		}
	}
}
