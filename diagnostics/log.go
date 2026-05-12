package diagnostics

import (
	"github.com/btcsuite/btclog/v2"
)

// Subsystem defines the logging code for this subsystem.
const Subsystem = "DIAG"

// log is a logger that is initialized with no output filters.
var log = btclog.Disabled

// DisableLog disables all library log output.
func DisableLog() {
	UseLogger(btclog.Disabled)
}

// UseLogger uses a specified Logger to output package logging info.
func UseLogger(logger btclog.Logger) {
	log = logger
}
