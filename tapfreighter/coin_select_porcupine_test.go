package tapfreighter

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/anishathalye/porcupine"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

const porcupineCoinCount = 4

type coinSelectOperation uint8

const (
	coinSelectLease coinSelectOperation = iota
	coinSelectRelease
)

type coinSelectInput struct {
	op   coinSelectOperation
	coin uint32
}

type coinSelectOutput struct {
	coin   uint32
	found  bool
	failed bool
}

// coinLeaseModel describes the externally visible lease set. Selection uses
// PreferMaxAmount, so it must atomically lease the largest available coin.
var coinLeaseModel = porcupine.Model{
	Init: func() interface{} {
		return uint8(0)
	},
	Step: func(state, input, output interface{}) (bool, interface{}) {
		leased := state.(uint8)
		in := input.(coinSelectInput)
		out := output.(coinSelectOutput)

		switch in.op {
		case coinSelectLease:
			var expected uint32
			found := false
			for idx := porcupineCoinCount - 1; idx >= 0; idx-- {
				mask := uint8(1 << idx)
				if leased&mask == 0 {
					expected = uint32(idx)
					found = true
					break
				}
			}

			if out.failed || out.found != found {
				return false, leased
			}
			if !found {
				return true, leased
			}
			if out.coin != expected {
				return false, leased
			}

			return true, leased | uint8(1<<expected)

		case coinSelectRelease:
			if out.failed {
				return false, leased
			}

			return true, leased &^ uint8(1<<in.coin)

		default:
			return false, leased
		}
	},
	Equal: func(state1, state2 interface{}) bool {
		return state1.(uint8) == state2.(uint8)
	},
	DescribeOperation: func(input, output interface{}) string {
		in := input.(coinSelectInput)
		out := output.(coinSelectOutput)
		if in.op == coinSelectLease {
			return fmt.Sprintf(
				"SelectCoins() -> coin=%d, found=%v, failed=%v",
				out.coin, out.found, out.failed,
			)
		}

		return fmt.Sprintf(
			"ReleaseCoins(coin=%d) -> failed=%v", in.coin,
			out.failed,
		)
	},
}

// porcupineCoinLister is a transactional in-memory CoinLister used to expose
// the real CoinSelect list then lease sequence to concurrent callers.
type porcupineCoinLister struct {
	mu     sync.Mutex
	coins  []*AnchoredCommitment
	leased map[wire.OutPoint]struct{}
}

func (p *porcupineCoinLister) ListEligibleCoins(_ context.Context,
	constraints CommitmentConstraints) ([]*AnchoredCommitment, error) {

	p.mu.Lock()
	defer p.mu.Unlock()

	eligible := make([]*AnchoredCommitment, 0, len(p.coins))
	for _, coin := range p.coins {
		if _, ok := p.leased[coin.AnchorPoint]; ok {
			continue
		}

		eligible = append(eligible, coin)
	}

	if len(eligible) == 0 {
		return nil, ErrMatchingAssetsNotFound
	}

	return eligible, nil
}

func (p *porcupineCoinLister) LeaseCoins(_ context.Context, _ [32]byte,
	_ time.Time, outpoints ...wire.OutPoint) error {

	p.mu.Lock()
	defer p.mu.Unlock()

	for _, outpoint := range outpoints {
		if _, ok := p.leased[outpoint]; ok {
			return fmt.Errorf("coin already leased")
		}
	}
	for _, outpoint := range outpoints {
		p.leased[outpoint] = struct{}{}
	}

	return nil
}

func (p *porcupineCoinLister) ReleaseCoins(_ context.Context,
	outpoints ...wire.OutPoint) error {

	p.mu.Lock()
	defer p.mu.Unlock()

	for _, outpoint := range outpoints {
		delete(p.leased, outpoint)
	}

	return nil
}

func (*porcupineCoinLister) DeleteExpiredLeases(context.Context) error {
	return nil
}

func (*porcupineCoinLister) FetchOrphanUTXOs(
	context.Context) ([]*ZeroValueInput, error) {

	return nil, nil
}

func newPorcupineCoinSelector(t *testing.T) *CoinSelect {
	t.Helper()

	coins := make([]*AnchoredCommitment, porcupineCoinCount)
	for idx := range coins {
		coins[idx] = &AnchoredCommitment{
			AnchorPoint: wire.OutPoint{Index: uint32(idx)},
			Asset: &asset.Asset{
				Amount:    uint64(idx + 1),
				ScriptKey: asset.RandScriptKey(t),
			},
			Commitment: &commitment.TapCommitment{
				Version: commitment.TapCommitmentV1,
			},
		}
	}

	return NewCoinSelect(&porcupineCoinLister{
		coins:  coins,
		leased: make(map[wire.OutPoint]struct{}),
	})
}

func executeCoinSelect(selector *CoinSelect,
	in coinSelectInput) coinSelectOutput {

	ctx := context.Background()
	if in.op == coinSelectRelease {
		err := selector.ReleaseCoins(
			ctx, wire.OutPoint{Index: in.coin},
		)
		return coinSelectOutput{failed: err != nil}
	}

	coins, err := selector.SelectCoins(
		ctx, CommitmentConstraints{MinAmt: 1}, PreferMaxAmount,
		commitment.TapCommitmentV1,
	)
	if errors.Is(err, ErrMatchingAssetsNotFound) {
		return coinSelectOutput{}
	}
	if err != nil || len(coins) != 1 {
		return coinSelectOutput{failed: true}
	}

	return coinSelectOutput{
		coin:  coins[0].AnchorPoint.Index,
		found: true,
	}
}

func executeCoinSelectHistory(selector *CoinSelect,
	clients [][]coinSelectInput) []porcupine.Operation {

	var operationCount int
	for _, operations := range clients {
		operationCount += len(operations)
	}

	var (
		clock   atomic.Int64
		wg      sync.WaitGroup
		start   = make(chan struct{})
		history = make(chan porcupine.Operation, operationCount)
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
				output := executeCoinSelect(selector, input)
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
	wg.Wait()
	close(history)

	result := make([]porcupine.Operation, 0, operationCount)
	for operation := range history {
		result = append(result, operation)
	}

	return result
}

func checkCoinSelectLinearizability(t *testing.T, rt *rapid.T) {
	numClients := rapid.IntRange(2, 5).Draw(rt, "num_clients")
	clients := make([][]coinSelectInput, numClients)
	for clientID := range clients {
		numOperations := rapid.IntRange(1, 4).Draw(
			rt, fmt.Sprintf("client_%d_operations", clientID),
		)
		clients[clientID] = make([]coinSelectInput, numOperations)
		for operationID := range clients[clientID] {
			label := fmt.Sprintf(
				"client_%d_operation_%d", clientID, operationID,
			)
			op := rapid.IntRange(0, 1).Draw(rt, label+"_op")
			clients[clientID][operationID] = coinSelectInput{
				op: coinSelectOperation(op),
				coin: uint32(rapid.IntRange(
					0, porcupineCoinCount-1,
				).Draw(rt, label+"_coin")),
			}
		}
	}

	history := executeCoinSelectHistory(
		newPorcupineCoinSelector(t), clients,
	)
	result := porcupine.CheckOperationsTimeout(
		coinLeaseModel, history, 5*time.Second,
	)
	if result != porcupine.Ok {
		rt.Fatalf("coin lease history is not linearizable: %v", result)
	}
}

// TestCoinSelectLinearizability checks that concurrent selection and release
// calls behave like atomic operations on one shared lease set.
func TestCoinSelectLinearizability(t *testing.T) {
	t.Parallel()

	const rapidBatches = 10
	for batch := range rapidBatches {
		t.Run(fmt.Sprintf("batch_%02d", batch), func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				checkCoinSelectLinearizability(t, rt)
			})
		})
	}
}

// TestCoinLeaseModelRejectsDoubleLease is a negative control proving that the
// model rejects two successful selections of the same coin.
func TestCoinLeaseModelRejectsDoubleLease(t *testing.T) {
	t.Parallel()

	history := []porcupine.Operation{{
		ClientId: 0,
		Input:    coinSelectInput{op: coinSelectLease},
		Call:     1,
		Output:   coinSelectOutput{coin: 3, found: true}, Return: 4,
	}, {
		ClientId: 1,
		Input:    coinSelectInput{op: coinSelectLease},
		Call:     2,
		Output:   coinSelectOutput{coin: 3, found: true}, Return: 3,
	}}

	result := porcupine.CheckOperationsTimeout(
		coinLeaseModel, history, time.Second,
	)
	require.Equal(t, porcupine.Illegal, result)
}
