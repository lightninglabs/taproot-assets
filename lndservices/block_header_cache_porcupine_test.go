package lndservices

import (
	"fmt"
	"maps"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/anishathalye/porcupine"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

type cacheOperation uint8

const (
	cachePut cacheOperation = iota
	cacheGet
)

type cacheInput struct {
	op     cacheOperation
	height uint32
	header wire.BlockHeader
}

type cacheOutput struct {
	found bool
	hash  chainhash.Hash
	err   bool
}

type cacheModelState map[uint32]chainhash.Hash

// blockHeaderCacheModel describes the expected sequential behavior of the
// cache. Porcupine checks whether a concurrent execution can be arranged into
// a sequence accepted by this model while preserving real-time ordering.
//
// This demo disables settlement depth and capacity eviction in the system
// under test. The model therefore focuses on concurrent reads, writes, and
// reorg invalidation.
var blockHeaderCacheModel = porcupine.Model{
	Init: func() interface{} {
		return cacheModelState{}
	},
	Step: func(state, input, output interface{}) (bool, interface{}) {
		current := state.(cacheModelState)
		in := input.(cacheInput)
		out := output.(cacheOutput)

		next := maps.Clone(current)

		switch in.op {
		case cachePut:
			if out.err {
				return false, current
			}

			hash := in.header.BlockHash()
			existingHash, exists := current[in.height]
			if exists && existingHash != hash {
				for height := range next {
					if height >= in.height {
						delete(next, height)
					}
				}
			}

			next[in.height] = hash
			return true, next

		case cacheGet:
			expectedHash, found := current[in.height]
			valid := out.found == found
			if found {
				valid = valid && out.hash == expectedHash
			}

			return valid, next

		default:
			return false, current
		}
	},
	Equal: func(state1, state2 interface{}) bool {
		return maps.Equal(
			state1.(cacheModelState), state2.(cacheModelState),
		)
	},
	DescribeOperation: func(input, output interface{}) string {
		in := input.(cacheInput)
		out := output.(cacheOutput)

		switch in.op {
		case cachePut:
			return fmt.Sprintf(
				"Put(height=%d, hash=%s) -> error=%v",
				in.height, in.header.BlockHash(), out.err,
			)

		case cacheGet:
			return fmt.Sprintf(
				"GetByHeight(height=%d) -> found=%v, hash=%s",
				in.height, out.found, out.hash,
			)

		default:
			return "unknown operation"
		}
	},
}

func executeCacheOperation(cache *BlockHeaderCache,
	in cacheInput) cacheOutput {

	switch in.op {
	case cachePut:
		return cacheOutput{
			err: cache.Put(in.height, in.header) != nil,
		}

	case cacheGet:
		header, found := cache.GetByHeight(in.height)
		if !found {
			return cacheOutput{}
		}

		return cacheOutput{
			found: true,
			hash:  header.BlockHash(),
		}

	default:
		panic("unknown cache operation")
	}
}

func executeCacheHistory(cache *BlockHeaderCache,
	clients [][]cacheInput) []porcupine.Operation {

	var (
		clock   atomic.Int64
		wg      sync.WaitGroup
		history = make(chan porcupine.Operation)
		start   = make(chan struct{})
	)

	for clientID, operations := range clients {
		clientID := clientID
		operations := operations

		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start

			for _, input := range operations {
				call := clock.Add(1)
				output := executeCacheOperation(cache, input)
				ret := clock.Add(1)

				history <- porcupine.Operation{
					ClientId: clientID,
					Input:    input,
					Call:     call,
					Output:   output,
					Return:   ret,
				}
			}
		}()
	}

	close(start)
	go func() {
		wg.Wait()
		close(history)
	}()

	result := make([]porcupine.Operation, 0)
	for operation := range history {
		result = append(result, operation)
	}

	return result
}

// TestBlockHeaderCacheLinearizability runs independent clients against the
// real cache and asks Porcupine to verify the resulting concurrent history.
func TestBlockHeaderCacheLinearizability(t *testing.T) {
	t.Parallel()

	cache, err := NewBlockHeaderCache(BlockHeaderCacheConfig{
		MaxSize:              1_000,
		PurgePercentage:      10,
		MinSettledBlockDepth: 0,
	})
	require.NoError(t, err)

	baseTime := time.Unix(1_700_000_000, 0).UTC()
	header := func(nonce uint32) wire.BlockHeader {
		return makeHeader(
			nonce, baseTime.Add(time.Duration(nonce)*time.Second),
		)
	}
	put := func(height, nonce uint32) cacheInput {
		return cacheInput{
			op:     cachePut,
			height: height,
			header: header(nonce),
		}
	}
	get := func(height uint32) cacheInput {
		return cacheInput{
			op:     cacheGet,
			height: height,
		}
	}

	clients := [][]cacheInput{
		{
			put(100, 1), get(100), put(101, 2), get(101),
		},
		{
			get(100), put(100, 3), get(100), get(101),
		},
		{
			put(102, 4), get(102), get(101), get(100),
		},
		{
			put(103, 5), get(103), put(101, 6), get(102),
		},
	}

	history := executeCacheHistory(cache, clients)
	result := porcupine.CheckOperationsTimeout(
		blockHeaderCacheModel, history, 5*time.Second,
	)

	require.Equal(t, porcupine.Ok, result)
}
