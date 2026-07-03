package rpcserver

import (
	"context"
	"net"
	"testing"

	unirpc "github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

// deltaServerStub exposes only the SyncDelta method by delegating to
// the given handler function; every other universe RPC inherits the
// Unimplemented status.
type deltaServerStub struct {
	unirpc.UnimplementedUniverseServer

	syncDelta func(context.Context,
		*unirpc.SyncDeltaRequest) (*unirpc.SyncDeltaResponse, error)
}

func (s *deltaServerStub) SyncDelta(ctx context.Context,
	req *unirpc.SyncDeltaRequest) (*unirpc.SyncDeltaResponse, error) {

	return s.syncDelta(ctx, req)
}

// newDeltaClient spins up an in-process gRPC server for the given
// universe server implementation and returns an RpcUniverseDiff dialed
// into it over a bufconn.
func newDeltaClient(t *testing.T,
	srv unirpc.UniverseServer) *RpcUniverseDiff {

	t.Helper()

	lis := bufconn.Listen(1024 * 1024)
	grpcServer := grpc.NewServer()
	unirpc.RegisterUniverseServer(grpcServer, srv)

	go func() {
		_ = grpcServer.Serve(lis)
	}()
	t.Cleanup(grpcServer.Stop)

	//nolint:staticcheck
	conn, err := grpc.DialContext(
		context.Background(), "bufnet",
		grpc.WithContextDialer(func(ctx context.Context,
			_ string) (net.Conn, error) {

			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = conn.Close()
	})

	return &RpcUniverseDiff{
		conn: &universeClientConn{
			ClientConn:     conn,
			UniverseClient: unirpc.NewUniverseClient(conn),
		},
	}
}

// TestRpcUniverseDiffSyncDelta round-trips a delta page through the
// real SyncDelta handler over an in-process gRPC connection and checks
// the client-side unmarshaling, including inclusion proof validity
// against the returned roots.
func TestRpcUniverseDiffSyncDelta(t *testing.T) {
	ctx := context.Background()
	h := newSyncDeltaHarness(t)

	client := newDeltaClient(t, &deltaServerStub{
		syncDelta: h.rpc.SyncDelta,
	})

	page, err := client.SyncDelta(ctx, 0, 100)
	require.NoError(t, err)

	// The harness seeds 3 issuance universes x 4 leaves and 2 transfer
	// universes x 3 leaves, all exportable by default.
	require.Len(t, page.Items, 3*4+2*3)
	require.Len(t, page.Roots, 5)
	require.Equal(t, page.Items[len(page.Items)-1].Seq, page.LatestSeq)

	var lastSeq uint64
	for _, item := range page.Items {
		require.Greater(t, item.Seq, lastSeq)
		lastSeq = item.Seq

		root, ok := page.Roots[item.ID.Key()]
		require.True(t, ok)

		uniProof := &universe.Proof{
			LeafKey:                item.Key,
			UniverseRoot:           root.Node,
			UniverseInclusionProof: item.InclusionProof,
			Leaf:                   item.Leaf,
		}
		require.True(t, uniProof.VerifyRoot(root.Node))
	}

	// Resuming from the returned cursor yields an empty page with the
	// same cursor.
	empty, err := client.SyncDelta(ctx, page.LatestSeq, 100)
	require.NoError(t, err)
	require.Empty(t, empty.Items)
	require.Equal(t, page.LatestSeq, empty.LatestSeq)
}

// TestRpcUniverseDiffSyncDeltaUnsupported pins that a remote server
// without the SyncDelta RPC surfaces universe.ErrDeltaUnsupported, the
// signal for callers to fall back to enumeration-based sync.
func TestRpcUniverseDiffSyncDeltaUnsupported(t *testing.T) {
	client := newDeltaClient(
		t, &unirpc.UnimplementedUniverseServer{},
	)

	_, err := client.SyncDelta(context.Background(), 0, 100)
	require.ErrorIs(t, err, universe.ErrDeltaUnsupported)
}

// TestArchiveSyncDelta exercises the local (in-process) DeltaEngine
// implementation on the universe Archive, which serves pages without
// export gating.
func TestArchiveSyncDelta(t *testing.T) {
	ctx := context.Background()
	h := newSyncDeltaHarness(t)

	page, err := h.arch.SyncDelta(ctx, 0, 100)
	require.NoError(t, err)

	require.Len(t, page.Items, 3*4+2*3)
	require.Len(t, page.Roots, 5)
	require.Equal(t, page.Items[len(page.Items)-1].Seq, page.LatestSeq)

	for _, item := range page.Items {
		root, ok := page.Roots[item.ID.Key()]
		require.True(t, ok)

		uniProof := &universe.Proof{
			LeafKey:                item.Key,
			UniverseRoot:           root.Node,
			UniverseInclusionProof: item.InclusionProof,
			Leaf:                   item.Leaf,
		}
		require.True(t, uniProof.VerifyRoot(root.Node))
	}

	// Paging from the middle returns the suffix.
	mid := page.Items[8].Seq
	suffix, err := h.arch.SyncDelta(ctx, mid, 100)
	require.NoError(t, err)
	require.Len(t, suffix.Items, len(page.Items)-9)
	require.Equal(t, page.LatestSeq, suffix.LatestSeq)
}
