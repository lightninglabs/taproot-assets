package rpcserver

import (
	"github.com/btcsuite/btclog/v2"
	"github.com/lightningnetwork/lnd/build"
)

const (
	// RPCSubsystem defines the logging code for the RPC subsystem.
	RPCSubsystem = "TRPC"

	// ServerSubsystem defines the logging code for the server subsystem.
	ServerSubsystem = "TSVR"

	// DaemonSubsystem defines the logging code for the daemon subsystem.
	DaemonSubsystem = "TAPD"
)

// log is a logger that is initialized with the btclog.Disabled logger.
var (
	rpcsLog = build.NewSubLogger(RPCSubsystem, nil)
	srvrLog = build.NewSubLogger(ServerSubsystem, nil)
	tapdLog = build.NewSubLogger(DaemonSubsystem, nil)
)

// UseLogger uses a specified Logger to output package logging info.
func UseLogger(logger btclog.Logger) {
	rpcsLog = logger
}

// UseServerLogger uses a specified Logger to output server logging info.
func UseServerLogger(logger btclog.Logger) {
	srvrLog = logger
}

// UseDaemonLogger uses a specified Logger to output daemon logging info.
func UseDaemonLogger(logger btclog.Logger) {
	tapdLog = logger
}
