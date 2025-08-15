package supplycommit

import (
	"fmt"

	"github.com/btcsuite/btclog/v2"
	"github.com/davecgh/go-spew/spew"
)

// Subsystem defines the logging code for this subsystem.
const Subsystem = "SUCO"

// log is a logger that is initialized with no output filters.  This
// means the package will not perform any logging by default until the caller
// requests it.
var log = btclog.Disabled

// DisableLog disables all library log output.  Logging output is disabled
// by default until UseLogger is called.
func DisableLog() {
	UseLogger(btclog.Disabled)
}

// limitSpewer is a spew.ConfigState that limits the depth of the output to 4
// levels, so it can safely be used for things that contain an MS-SMT tree.
var limitSpewer = &spew.ConfigState{
	Indent:   "  ",
	MaxDepth: 4,
}

// UseLogger uses a specified Logger to output package logging info.
// This should be used in preference to SetLogWriter if the caller is also
// using btclog.
func UseLogger(logger btclog.Logger) {
	log = logger
}

// NewAssetLogger creates a new prefixed logger for a specific asset. This
// logger will automatically include the asset specifier in all log messages,
// using the format "SupplyCommit(asset): message".
func NewAssetLogger(assetSpec string) btclog.Logger {
	return log.WithPrefix(fmt.Sprintf("SupplyCommit(%v): ", assetSpec))
}
