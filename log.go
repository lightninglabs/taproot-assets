package taprootassets

import (
	"github.com/btcsuite/btclog"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/monitoring"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/rfq"
	"github.com/lightninglabs/taproot-assets/tapdb"
	"github.com/lightninglabs/taproot-assets/tapfreighter"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightningnetwork/lnd/build"
	"github.com/lightningnetwork/lnd/signal"
)

// replaceableLogger is a thin wrapper around a logger that is used so the
// logger can be replaced easily without some black pointer magic.
type replaceableLogger struct {
	btclog.Logger
	subsystem string
}

// Loggers can not be used before the log rotator has been initialized with a
// log file. This must be performed early during application startup by
// calling InitLogRotator() on the main log writer instance in the config.
var (
	// tapPkgLoggers is a list of all Taproot Asset package level loggers
	// that are registered. They are tracked here, so they can be replaced
	// once the SetupLoggers function is called with the final root logger.
	tapPkgLoggers []*replaceableLogger

	// addTapPkgLogger is a helper function that creates a new replaceable
	// main Taproot Asset package level logger and adds it to the list of
	// loggers that are replaced again later, once the final root logger is
	// ready.
	addTapPkgLogger = func(subsystem string) *replaceableLogger {
		l := &replaceableLogger{
			Logger:    build.NewSubLogger(subsystem, nil),
			subsystem: subsystem,
		}
		tapPkgLoggers = append(tapPkgLoggers, l)
		return l
	}

	// Loggers that need to be accessible from the Taproot Asset package can
	// be placed here. Loggers that are only used in submodules can be added
	// directly by using the addSubLogger method. We declare all loggers, so
	// we never run into a nil reference if they are used early. But the
	// SetupLoggers function should always be called as soon as possible to
	// finish setting them up properly with a root logger.
	tapdLog = addTapPkgLogger("TAPD")
	srvrLog = addTapPkgLogger("SRVR")
	rpcsLog = addTapPkgLogger("RPCS")
)

// genSubLogger creates a logger for a subsystem. We provide an instance of a
// signal.Interceptor to be able to shutdown in the case of a critical error.
func genSubLogger(root *build.RotatingLogWriter,
	interceptor signal.Interceptor) func(string) btclog.Logger {

	// Create a shutdown function which will request shutdown from our
	// interceptor if it is listening.
	shutdown := func() {
		if !interceptor.Listening() {
			return
		}

		interceptor.RequestShutdown()
	}

	// Return a function which will create a sublogger from our root logger
	// without shutdown fn.
	return func(tag string) btclog.Logger {
		return root.GenSubLogger(tag, shutdown)
	}
}

// SetupLoggers initializes all package-global logger variables.
func SetupLoggers(root *build.RotatingLogWriter, interceptor signal.Interceptor) {
	genLogger := genSubLogger(root, interceptor)

	// Now that we have the proper root logger, we can replace the
	// placeholder Taproot Asset package loggers.
	for _, l := range tapPkgLoggers {
		l.Logger = build.NewSubLogger(l.subsystem, genLogger)
		SetSubLogger(root, l.subsystem, l.Logger)
	}

	// Some of the loggers declared in the main taprootassets package are
	// also used in sub packages.
	signal.UseLogger(tapdLog)

	AddSubLogger(root, tapgarden.Subsystem, interceptor, tapgarden.UseLogger)
	AddSubLogger(
		root, tapfreighter.Subsystem, interceptor, tapfreighter.UseLogger,
	)
	AddSubLogger(root, proof.Subsystem, interceptor, proof.UseLogger)
	AddSubLogger(root, tapdb.Subsystem, interceptor, tapdb.UseLogger)
	AddSubLogger(root, address.Subsystem, interceptor, address.UseLogger)
	AddSubLogger(root, tapsend.Subsystem, interceptor, tapsend.UseLogger)
	AddSubLogger(root, universe.Subsystem, interceptor, universe.UseLogger)
	AddSubLogger(
		root, commitment.Subsystem, interceptor, commitment.UseLogger,
	)
	AddSubLogger(
		root, monitoring.Subsystem, interceptor, monitoring.UseLogger,
	)
	AddSubLogger(root, rfq.Subsystem, interceptor, rfq.UseLogger)
}

// AddSubLogger is a helper method to conveniently create and register the
// logger of one or more sub systems.
func AddSubLogger(root *build.RotatingLogWriter, subsystem string,
	interceptor signal.Interceptor, useLoggers ...func(btclog.Logger)) {

	// genSubLogger will return a callback for creating a logger instance,
	// which we will give to the root logger.
	genLogger := genSubLogger(root, interceptor)

	// Create and register just a single logger to prevent them from
	// overwriting each other internally.
	logger := build.NewSubLogger(subsystem, genLogger)
	SetSubLogger(root, subsystem, logger, useLoggers...)
}

// SetSubLogger is a helper method to conveniently register the logger of a sub
// system.
func SetSubLogger(root *build.RotatingLogWriter, subsystem string,
	logger btclog.Logger, useLoggers ...func(btclog.Logger)) {

	root.RegisterSubLogger(subsystem, logger)
	for _, useLogger := range useLoggers {
		useLogger(logger)
	}
}
