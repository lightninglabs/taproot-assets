package tapfreighter

import (
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/btcsuite/btclog/v2"
)

func TestRunChainPorter(t *testing.T) {
	t.Parallel()
}

func init() {
	rand.Seed(time.Now().Unix())

	logger := btclog.NewSLogger(btclog.NewDefaultHandler(os.Stdout))
	UseLogger(logger.SubSystem(Subsystem))
}
