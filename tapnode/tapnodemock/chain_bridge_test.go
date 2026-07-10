package tapnodemock

import (
	"context"
	"sync"
	"testing"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
)

// TestChainBridgeBlocksRace exercises concurrent SetBlock / GetBlock
// access. Run with `go test -race` to catch any future writer that
// bypasses the SetBlock helper.
func TestChainBridgeBlocksRace(t *testing.T) {
	t.Parallel()

	const (
		writers        = 8
		readers        = 8
		opsPerWorker   = 200
		distinctHashes = 16
	)

	hashes := make([]chainhash.Hash, distinctHashes)
	for i := range hashes {
		hashes[i][0] = byte(i)
	}

	m := NewChainBridge()
	ctx := context.Background()
	block := &wire.MsgBlock{}

	var wg sync.WaitGroup
	wg.Add(writers + readers)
	for w := 0; w < writers; w++ {
		go func(seed int) {
			defer wg.Done()
			for i := 0; i < opsPerWorker; i++ {
				h := hashes[(seed+i)%distinctHashes]
				m.SetBlock(h, block)
			}
		}(w)
	}
	for r := 0; r < readers; r++ {
		go func(seed int) {
			defer wg.Done()
			for i := 0; i < opsPerWorker; i++ {
				_, _ = m.GetBlock(
					ctx, hashes[(seed+i)%distinctHashes],
				)
			}
		}(r)
	}
	wg.Wait()
}
