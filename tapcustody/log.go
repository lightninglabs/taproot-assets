package tapcustody

import (
	"github.com/btcsuite/btclog/v2"
)

// Subsystem defines the logging code for this subsystem.
const Subsystem = "CSTD"

// log is a logger that is initialized with no output filters. This
// means the package will not perform any logging by default until the
// caller requests it.
var log = btclog.Disabled

// DisableLog disables all library log output.
func DisableLog() {
	UseLogger(btclog.Disabled)
}

// UseLogger uses a specified Logger to output package logging info.
func UseLogger(logger btclog.Logger) {
	log = logger
}
