package tapfreighter

import (
	"math/rand"
	"testing"
	"time"

	"github.com/lightningnetwork/lnd/build"
)

func TestRunChainPorter(t *testing.T) {
	t.Parallel()
}

func init() {
	rand.Seed(time.Now().Unix())

	logWriter := build.NewRotatingLogWriter()
	logger := logWriter.GenSubLogger(Subsystem, func() {})
	logWriter.RegisterSubLogger(Subsystem, logger)
	UseLogger(logger)
}
