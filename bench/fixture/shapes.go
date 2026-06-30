package fixture

import (
	"context"
	"testing"
)

// CommandBench measures the cost of issuing a state-mutating RPC. It runs
// call once per b.N iteration with allocs reporting on. The handler is
// invoked directly (no gRPC wire) so the signal reflects subsystem cost,
// not transport.
//
// Use this shape for RPCs whose dominant cost is a chain mutation, a db
// write, or a heavy fan-out (Mint, Send, Burn, FundBatch, etc.).
func CommandBench[Req, Resp any](
	b *testing.B,
	call func(context.Context, Req) (Resp, error),
	req Req,
) {

	b.Helper()
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := call(ctx, req); err != nil {
			b.Fatal(err)
		}
	}
}

// QueryBench measures the cost of issuing a read-only RPC. Identical to
// CommandBench at the call site, but kept separate so the bench classifier
// (and future per-shape harness behaviour like cold/warm cache modes) can
// distinguish read from write paths.
//
// Use this shape for RPCs that only read state (List*, Query*, Fetch*,
// Decode*, Verify*).
func QueryBench[Req, Resp any](
	b *testing.B,
	call func(context.Context, Req) (Resp, error),
	req Req,
) {

	b.Helper()
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := call(ctx, req); err != nil {
			b.Fatal(err)
		}
	}
}
