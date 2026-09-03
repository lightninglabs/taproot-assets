package rfq

import (
	"context"
	"fmt"
	"maps"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/anishathalye/porcupine"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightningnetwork/lnd/graph/db/models"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/stretchr/testify/require"
)

type salePolicyInput struct {
	htlcID uint64
	amount lnwire.MilliSatoshi
}

type salePolicyOutput struct {
	accepted bool
}

type salePolicyState map[uint64]lnwire.MilliSatoshi

// newSalePolicyModel describes the atomic check and track behavior of an
// asset sale policy. A replay replaces the amount for its circuit key, while
// distinct accepted HTLCs must never exceed the quote's maximum amount.
func newSalePolicyModel(maxAmount lnwire.MilliSatoshi) porcupine.Model {
	return porcupine.Model{
		Init: func() interface{} {
			return salePolicyState{}
		},
		Step: func(state, input,
			output interface{}) (bool, interface{}) {

			current := state.(salePolicyState)
			in := input.(salePolicyInput)
			out := output.(salePolicyOutput)

			var trackedAmount lnwire.MilliSatoshi
			for id, amount := range current {
				if id != in.htlcID {
					trackedAmount += amount
				}
			}

			shouldAccept := trackedAmount <= maxAmount &&
				in.amount <= maxAmount-trackedAmount
			if out.accepted != shouldAccept {
				return false, current
			}

			next := maps.Clone(current)
			if shouldAccept {
				next[in.htlcID] = in.amount
			}

			return true, next
		},
		Equal: func(state1, state2 interface{}) bool {
			return maps.Equal(
				state1.(salePolicyState),
				state2.(salePolicyState),
			)
		},
		DescribeOperation: func(input, output interface{}) string {
			in := input.(salePolicyInput)
			out := output.(salePolicyOutput)

			return fmt.Sprintf(
				"CheckHtlcCompliance(id=%d, amount_msat=%d) "+
					"-> accepted=%v", in.htlcID, in.amount,
				out.accepted,
			)
		},
	}
}

func newPorcupineSalePolicy(t *testing.T) (*AssetSalePolicy,
	lnwire.MilliSatoshi) {

	t.Helper()

	rate := rfqmsg.NewAssetRate(
		rfqmath.NewBigIntFixedPoint(100, 0),
		time.Now().Add(time.Hour),
	)
	accept := rfqmsg.BuyAccept{
		Request: rfqmsg.BuyRequest{
			AssetSpecifier: asset.NewSpecifierFromId(asset.ID{1}),
			AssetMaxAmt:    1_000,
		},
		AssetRate: rate,
	}
	policy := NewAssetSalePolicy(accept, false, nil)

	maxAssetAmount := rfqmath.NewBigIntFixedPoint(
		policy.MaxOutboundAssetAmount, 0,
	)
	maxAmount, err := rfqmath.UnitsToMilliSatoshi(
		maxAssetAmount, policy.AskAssetRate,
	)
	require.NoError(t, err)

	return policy, maxAmount
}

func checkSalePolicy(policy *AssetSalePolicy,
	in salePolicyInput) salePolicyOutput {

	htlc := lndclient.InterceptedHtlc{
		IncomingCircuitKey: models.CircuitKey{
			ChanID: lnwire.NewShortChanIDFromInt(1),
			HtlcID: in.htlcID,
		},
		OutgoingChannelID: lnwire.NewShortChanIDFromInt(
			uint64(policy.AcceptedQuoteId.Scid()),
		),
		AmountOutMsat: in.amount,
	}

	err := policy.CheckHtlcCompliance(context.Background(), htlc, nil)
	return salePolicyOutput{
		accepted: err == nil,
	}
}

// TestAssetSalePolicyLinearizability verifies that concurrently checked HTLCs
// cannot collectively exceed the quote's maximum amount.
func TestAssetSalePolicyLinearizability(t *testing.T) {
	t.Parallel()

	policy, maxAmount := newPorcupineSalePolicy(t)
	model := newSalePolicyModel(maxAmount)

	const numClients = 32

	var (
		clock   atomic.Int64
		wg      sync.WaitGroup
		history = make(chan porcupine.Operation, numClients)
		start   = make(chan struct{})
	)

	for clientID := 0; clientID < numClients; clientID++ {
		clientID := clientID
		wg.Add(1)

		go func() {
			defer wg.Done()
			<-start

			input := salePolicyInput{
				htlcID: uint64(clientID),
				amount: maxAmount,
			}
			call := clock.Add(1)
			output := checkSalePolicy(policy, input)
			ret := clock.Add(1)

			history <- porcupine.Operation{
				ClientId: clientID,
				Input:    input,
				Call:     call,
				Output:   output,
				Return:   ret,
			}
		}()
	}

	close(start)
	wg.Wait()
	close(history)

	operations := make([]porcupine.Operation, 0, numClients)
	for operation := range history {
		operations = append(operations, operation)
	}

	result := porcupine.CheckOperationsTimeout(
		model, operations, 5*time.Second,
	)
	require.Equal(t, porcupine.Ok, result)
}

// TestAssetSalePolicyModelRejectsOverAllocation is a negative control for the
// model. It represents the result of a check and track race in which two
// concurrent HTLCs each consume the full quote amount and are both accepted.
func TestAssetSalePolicyModelRejectsOverAllocation(t *testing.T) {
	t.Parallel()

	const maxAmount = lnwire.MilliSatoshi(1_000)

	operations := []porcupine.Operation{
		{
			ClientId: 0,
			Input: salePolicyInput{
				htlcID: 1,
				amount: maxAmount,
			},
			Call:   1,
			Output: salePolicyOutput{accepted: true},
			Return: 4,
		},
		{
			ClientId: 1,
			Input: salePolicyInput{
				htlcID: 2,
				amount: maxAmount,
			},
			Call:   2,
			Output: salePolicyOutput{accepted: true},
			Return: 3,
		},
	}

	result := porcupine.CheckOperationsTimeout(
		newSalePolicyModel(maxAmount), operations, time.Second,
	)
	require.Equal(t, porcupine.Illegal, result)
}
