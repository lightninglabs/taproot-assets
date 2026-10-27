package lndservices

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/lnrpc/chainrpc"
	"github.com/stretchr/testify/require"
)

// queuedNotifier is a fake lndclient.ChainNotifierClient that hands out a
// pre-seeded sequence of (event, error) channel pairs, one per registration,
// so a test can drive the adapter through a stream error and its
// re-registration. It mirrors lndclient's behaviour of surfacing a stream error
// on the error channel without closing the event channel.
type queuedNotifier struct {
	mu sync.Mutex

	confChans []chan *chainntnfs.TxConfirmation
	confErrs  []chan error
	confCalls int

	spendChans []chan *chainntnfs.SpendDetail
	spendErrs  []chan error
	spendCalls int
}

func (q *queuedNotifier) RegisterConfirmationsNtfn(_ context.Context,
	_ *chainhash.Hash, _ []byte, _, _ int32,
	_ ...lndclient.NotifierOption) (chan *chainntnfs.TxConfirmation,
	chan error, error) {

	q.mu.Lock()
	defer q.mu.Unlock()

	i := q.confCalls
	q.confCalls++

	return q.confChans[i], q.confErrs[i], nil
}

func (q *queuedNotifier) RegisterSpendNtfn(_ context.Context, _ *wire.OutPoint,
	_ []byte, _ int32, _ ...lndclient.NotifierOption) (
	chan *chainntnfs.SpendDetail, chan error, error) {

	q.mu.Lock()
	defer q.mu.Unlock()

	i := q.spendCalls
	q.spendCalls++

	return q.spendChans[i], q.spendErrs[i], nil
}

func (q *queuedNotifier) RegisterBlockEpochNtfn(_ context.Context) (chan int32,
	chan error, error) {

	return nil, nil, nil
}

func (q *queuedNotifier) RawClientWithMacAuth(ctx context.Context) (
	context.Context, time.Duration, chainrpc.ChainNotifierClient) {

	return ctx, 0, nil
}

func testAdapters(
	notifier lndclient.ChainNotifierClient) *LndFsmDaemonAdapters {

	return &LndFsmDaemonAdapters{
		lnd:         &lndclient.LndServices{ChainNotifier: notifier},
		retryConfig: fn.DefaultRetryConfig(),
		ContextGuard: fn.ContextGuard{
			DefaultTimeout: DefaultTimeout,
			Quit:           make(chan struct{}),
		},
	}
}

// TestRegisterConfirmationsNtfnResubscribes asserts that after the notifier
// stream errors, the adapter re-registers and a later confirmation still
// reaches the consumer. This is the #2286 regression: on the unfixed adapter
// the error channel is dropped, the confirmation never arrives, and this times
// out.
func TestRegisterConfirmationsNtfnResubscribes(t *testing.T) {
	t.Parallel()

	conf := &chainntnfs.TxConfirmation{}

	// The second registration's channel is pre-loaded with the
	// confirmation, so it is delivered as soon as the adapter re-registers.
	confChan2 := make(chan *chainntnfs.TxConfirmation, 1)
	confChan2 <- conf

	notifier := &queuedNotifier{
		confChans: []chan *chainntnfs.TxConfirmation{
			make(chan *chainntnfs.TxConfirmation), confChan2,
		},
		confErrs: []chan error{
			make(chan error, 1), make(chan error, 1),
		},
	}

	adapters := testAdapters(notifier)
	defer func() { require.NoError(t, adapters.Stop()) }()

	event, err := adapters.RegisterConfirmationsNtfn(
		&chainhash.Hash{}, []byte{}, 1, 100,
	)
	require.NoError(t, err)

	// Sever the first stream.
	notifier.confErrs[0] <- fmt.Errorf("stream died")

	select {
	case got := <-event.Confirmed:
		require.Same(t, conf, got)

	case <-time.After(5 * time.Second):
		t.Fatal("confirmation never arrived after re-registration")
	}
}

// TestRegisterSpendNtfnResubscribes is the spend-side twin of the confirmation
// regression test above.
func TestRegisterSpendNtfnResubscribes(t *testing.T) {
	t.Parallel()

	spend := &chainntnfs.SpendDetail{}

	spendChan2 := make(chan *chainntnfs.SpendDetail, 1)
	spendChan2 <- spend

	notifier := &queuedNotifier{
		spendChans: []chan *chainntnfs.SpendDetail{
			make(chan *chainntnfs.SpendDetail), spendChan2,
		},
		spendErrs: []chan error{
			make(chan error, 1), make(chan error, 1),
		},
	}

	adapters := testAdapters(notifier)
	defer func() { require.NoError(t, adapters.Stop()) }()

	event, err := adapters.RegisterSpendNtfn(
		&wire.OutPoint{}, []byte{}, 100,
	)
	require.NoError(t, err)

	// Sever the first stream.
	notifier.spendErrs[0] <- fmt.Errorf("stream died")

	select {
	case got := <-event.Spend:
		require.Same(t, spend, got)

	case <-time.After(5 * time.Second):
		t.Fatal("spend never arrived after re-registration")
	}
}
