package fixture

import (
	"context"
	"testing"

	"google.golang.org/grpc"
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

// StreamBench measures the per-event cost of a server-streaming RPC in
// steady state. It opens the stream once and times the emission and
// per-event handling of b.N events emitted by emit. The first event is
// excluded from the timing so subscription setup does not contaminate
// the signal.
//
// The collector parameter is the function that drains a single event from
// the stream (e.g. stream.Recv()). The emit callback triggers one
// publish-side event each iteration.
func StreamBench[Stream grpc.ServerStream, Event any](
	b *testing.B,
	open func(context.Context) (Stream, error),
	collect func(Stream) (Event, error),
	emit func(int) error,
) {
	b.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stream, err := open(ctx)
	if err != nil {
		b.Fatal(err)
	}

	// Drain one warmup event so subscription wiring is excluded from the
	// timed loop.
	if err := emit(-1); err != nil {
		b.Fatal(err)
	}
	if _, err := collect(stream); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if err := emit(i); err != nil {
			b.Fatal(err)
		}
		if _, err := collect(stream); err != nil {
			b.Fatal(err)
		}
	}
}
