package tapreorg_test

import (
	"os"
	"testing"

	"github.com/btcsuite/btclog/v2"
	"github.com/lightninglabs/taproot-assets/tapreorg"
)

// TestMain enables trace logging when TAPREORG_DEBUG is set, for
// diagnosing ordering-dependent scenarios.
func TestMain(m *testing.M) {
	if os.Getenv("TAPREORG_DEBUG") != "" {
		handler := btclog.NewDefaultHandler(os.Stderr)
		logger := btclog.NewSLogger(handler)
		logger.SetLevel(btclog.LevelTrace)
		tapreorg.UseLogger(logger)
	}
	os.Exit(m.Run())
}
