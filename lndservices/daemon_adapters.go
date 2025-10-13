package lndservices

import (
	"bytes"
	"fmt"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/protofsm"
	"github.com/lightningnetwork/lnd/routing/route"
)

const (
	// DefaultTimeout is the default timeout we use for RPC and database
	// operations.
	DefaultTimeout = 30 * time.Second
)

// LndFsmDaemonAdapters is a struct that implements the protofsm.DaemonAdapters
// interface.
type LndFsmDaemonAdapters struct {
	// lnd is the LND services client that will be used to interact with
	// the LND node.
	lnd *lndclient.LndServices

	// retryConfig is the retry configuration that will be used for
	// operations that may fail due to temporary issues, such as network
	// errors or RPC timeouts.
	retryConfig fn.RetryConfig

	// msgTransport is the message transport client that will be used to
	// send messages to peers.
	msgTransport LndMsgTransportClient

	// chainBridge is the chain bridge that will be used to interact with
	// the blockchain.
	chainBridge LndRpcChainBridge

	// ContextGuard manages the context and quit channel for this service.
	fn.ContextGuard

	startOnce sync.Once
	stopOnce  sync.Once
}

// NewLndFsmDaemonAdapters creates a new instance of LndFsmDaemonAdapters.
func NewLndFsmDaemonAdapters(lnd *lndclient.LndServices,
	headerCache *BlockHeaderCache) *LndFsmDaemonAdapters {

	retryConfig := fn.DefaultRetryConfig()

	msgTransport := NewLndMsgTransportClient(lnd)

	// Initialize the chain bridge without the asset store, as it is not
	// needed for the FSM adapters.
	chainBridge := NewLndRpcChainBridge(lnd, nil, headerCache)
	chainBridge.retryConfig = retryConfig

	return &LndFsmDaemonAdapters{
		lnd:          lnd,
		retryConfig:  retryConfig,
		msgTransport: *msgTransport,
		chainBridge:  *chainBridge,
		ContextGuard: fn.ContextGuard{
			DefaultTimeout: DefaultTimeout,
			Quit:           make(chan struct{}),
		},
	}
}

// Start attempts to start the service.
func (l *LndFsmDaemonAdapters) Start() error {
	l.startOnce.Do(func() {})
	return nil
}

// Stop signals for the service to gracefully exit.
func (l *LndFsmDaemonAdapters) Stop() error {
	l.stopOnce.Do(func() {
		// Signal the quit channel which will cancel all active
		// contexts.
		close(l.Quit)
	})

	return nil
}

// SendMessages sends a slice of lnwire.Message to the peer with the given
// public key.
func (l *LndFsmDaemonAdapters) SendMessages(peer btcec.PublicKey,
	messages []lnwire.Message) error {

	// Convert messages to a slice of CustomMessage.
	customMessages := make([]lndclient.CustomMessage, 0, len(messages))
	for idx := range messages {
		msg := messages[idx]

		var buf bytes.Buffer
		if err := msg.Encode(&buf, 0); err != nil {
			return fmt.Errorf("unable to encode message: %w", err)
		}

		customMsg := lndclient.CustomMessage{
			Peer:    route.NewVertex(&peer),
			MsgType: uint32(msg.MsgType()),
			Data:    buf.Bytes(),
		}

		customMessages = append(customMessages, customMsg)
	}

	ctx, cancel := l.WithCtxQuitNoTimeout()
	defer cancel()

	// Send each message in turn.
	for idx := range customMessages {
		msg := customMessages[idx]

		err := l.msgTransport.SendCustomMessage(ctx, msg)
		if err != nil {
			return fmt.Errorf("unable to send custom message: %w",
				err)
		}
	}

	return nil
}

// BroadcastTransaction attempts to broadcast a transaction to the
// network. It uses the chain bridge to publish the transaction.
func (l *LndFsmDaemonAdapters) BroadcastTransaction(tx *wire.MsgTx,
	label string) error {

	ctx, cancel := l.WithCtxQuitNoTimeout()
	defer cancel()

	return l.chainBridge.PublishTransaction(ctx, tx, label)
}

// RegisterConfirmationsNtfn registers an intent to be notified once the
// transaction with the given txid reaches the specified number of
// confirmations.
func (l *LndFsmDaemonAdapters) RegisterConfirmationsNtfn(
	txid *chainhash.Hash, pkScript []byte, numConfs uint32,
	heightHint uint32,
	optFuncs ...chainntnfs.NotifierOption) (*chainntnfs.ConfirmationEvent,
	error) {

	opts := chainntnfs.DefaultNotifierOptions()
	for _, optFunc := range optFuncs {
		optFunc(opts)
	}

	lndCliOpt := make([]lndclient.NotifierOption, 0, len(optFuncs))
	if opts.IncludeBlock {
		lndCliOpt = append(lndCliOpt, lndclient.WithIncludeBlock())
	}

	ctx, cancel := l.WithCtxQuitNoTimeout()
	spendDetail, _, err := l.lnd.ChainNotifier.RegisterConfirmationsNtfn(
		ctx, txid, pkScript, int32(numConfs), int32(heightHint),
		lndCliOpt...,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to register for conf: %w", err)
	}

	return &chainntnfs.ConfirmationEvent{
		Confirmed:    spendDetail,
		Updates:      make(chan uint32),
		NegativeConf: make(chan int32),
		Done:         make(chan struct{}),
		Cancel:       cancel,
	}, nil
}

// RegisterSpendNtfn registers an intent to be notified once the outpoint
// is spent on-chain.
func (l *LndFsmDaemonAdapters) RegisterSpendNtfn(outpoint *wire.OutPoint,
	pkScript []byte, heightHint uint32) (*chainntnfs.SpendEvent, error) {

	ctx, cancel := l.WithCtxQuitNoTimeout()
	spendDetail, _, err := l.lnd.ChainNotifier.RegisterSpendNtfn(
		ctx, outpoint, pkScript, int32(heightHint),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to register for spend: %w", err)
	}

	return &chainntnfs.SpendEvent{
		Spend:  spendDetail,
		Reorg:  make(chan struct{}, 1),
		Done:   make(chan struct{}, 1),
		Cancel: cancel,
	}, nil
}

// Ensure LndFsmDaemonAdapters implements the protofsm.DaemonAdapters
// interface.
var _ protofsm.DaemonAdapters = (*LndFsmDaemonAdapters)(nil)
