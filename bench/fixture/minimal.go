// Package fixture provides graduated in-process tapd fixtures used by
// benchmarks under bench/. Each fixture composes the minimum set of
// subsystems required to exercise a given class of RPC handler without the
// noise of spinning up a real lnd/btcd subprocess.
package fixture

import (
	"context"
	"testing"

	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/rpcperms"
	"github.com/lightninglabs/taproot-assets/rpcserver"
	"github.com/lightninglabs/taproot-assets/tapconfig"
	"github.com/lightningnetwork/lnd/build"
	"github.com/lightningnetwork/lnd/signal"
	"github.com/stretchr/testify/require"
	"gopkg.in/macaroon.v2"
)

// noopMacaroonBaker is a MacaroonBaker that returns an empty macaroon. It
// suffices for benchmarks because all fixtures register the RPC server with
// macaroons disabled.
type noopMacaroonBaker struct{}

func (noopMacaroonBaker) BakeMacaroon(_ context.Context,
	_ rpcperms.BakeRequest) (macaroon.Macaroon, error) {

	return macaroon.Macaroon{}, nil
}

// Minimal is the smallest fixture: just config primitives, no subsystems.
// It is sufficient for handlers that only consume ChainParams, LogMgr, and
// the like — decoders, marshallers, GetInfo-shape calls.
type Minimal struct {
	Config *tapconfig.Config
	Server *rpcserver.RPCServer
}

// NewMinimal constructs a Minimal fixture and registers cleanup with the
// provided testing.TB so the server is stopped at the end of the benchmark.
func NewMinimal(tb testing.TB) *Minimal {
	tb.Helper()

	logWriter := build.NewRotatingLogWriter()
	logCfg := build.DefaultLogConfig()
	logMgr := build.NewSubLoggerManager(
		build.NewDefaultLogHandlers(logCfg, logWriter)...,
	)

	cfg := &tapconfig.Config{
		Version:           "bench",
		RuntimeID:         0,
		ChainParams:       address.RegressionNetTap,
		SignalInterceptor: signal.Interceptor{},
		MacaroonBaker:     noopMacaroonBaker{},
		LogWriter:         logWriter,
		LogMgr:            logMgr,

		// UniverseQueriesPerSecond / Burst gate handler rate limits;
		// set to a permissive value so benches are never throttled.
		UniverseQueriesPerSecond: 1_000_000,
		UniverseQueriesBurst:     1_000_000,

		RPCConfig: &tapconfig.RPCConfig{
			NoMacaroons:  true,
			MacaroonPath: "",
		},

		// DatabaseConfig is embedded as a pointer; allocate it empty
		// so upper fixtures can populate fields without nil-deref.
		DatabaseConfig: &tapconfig.DatabaseConfig{},
	}

	srv := rpcserver.NewRPCServer()
	require.NoError(tb, srv.Start(cfg))

	tb.Cleanup(func() {
		_ = srv.Stop()
	})

	return &Minimal{
		Config: cfg,
		Server: srv,
	}
}

