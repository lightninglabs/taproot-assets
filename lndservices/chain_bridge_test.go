package lndservices

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	btcwalletchain "github.com/btcsuite/btcwallet/chain"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/tapnode"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/lnrpc/chainrpc"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestDefinitivePublishError(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name       string
		err        error
		definitive bool
	}{
		{
			name: "collapsed missing or spent input is ambiguous",
			err: status.Error(
				codes.Unknown, lnwallet.ErrDoubleSpend.Error(),
			),
			definitive: false,
		},
		{
			name: "mempool fee with detail",
			err: status.Error(
				codes.Unknown, lnwallet.ErrMempoolFee.Error()+
					": min relay fee not met",
			),
			definitive: true,
		},
		{
			name: "non final transaction",
			err: status.Error(
				codes.Unknown, "non-final",
			),
			definitive: true,
		},
		{
			name: "invalid argument is not the pinned wallet path",
			err: status.Error(
				codes.InvalidArgument,
				"transaction rejected: non final",
			),
			definitive: false,
		},
		{
			name: "failed precondition is not pinned wallet path",
			err: status.Error(
				codes.FailedPrecondition,
				"mandatory-script-verify-flag failed",
			),
			definitive: false,
		},
		{
			name: "bounded dust marker",
			err: status.Error(
				codes.Unknown, "dusting service failed",
			),
			definitive: false,
		},
		{
			name: "incidental standalone dust marker",
			err: status.Error(
				codes.Unknown, "backend dust cache unavailable",
			),
			definitive: false,
		},
		{
			name: "explicitly framed dust rejection",
			err: status.Error(
				codes.Unknown, "transaction rejected: dust",
			),
			definitive: true,
		},
		{
			name: "incidental nonstandard marker",
			err: status.Error(
				codes.Unknown,
				"backend nonstandard cache failure",
			),
			definitive: false,
		},
		{
			name: "bounded fee marker",
			err: status.Error(
				codes.Unknown, "insufficient feedback",
			),
			definitive: false,
		},
		{
			name: "missing inputs override policy marker",
			err: status.Error(
				codes.Unknown,
				"bad-txns-inputs-missingorspent: "+
					"insufficient fee",
			),
			definitive: false,
		},
		{
			name: "mempool conflict overrides dust marker",
			err: status.Error(
				codes.Unknown, "txn-mempool-conflict: dust",
			),
			definitive: false,
		},
		{
			name: "plural conflict overrides dust marker",
			err: status.Error(
				codes.Unknown,
				"transaction conflicts with mempool: dust",
			),
			definitive: false,
		},
		{
			name: "double spend overrides fee marker",
			err: status.Error(
				codes.Unknown, "double-spend: insufficient fee",
			),
			definitive: false,
		},
		{
			name: "replacement conflict overrides fee marker",
			err: status.Error(
				codes.Unknown,
				"replacement transaction underpriced: "+
					"min relay fee not met",
			),
			definitive: false,
		},
		{
			name: "already known overrides policy marker",
			err: status.Error(
				codes.Unknown,
				"txn-already-known: mempool min fee",
			),
			definitive: false,
		},
		{
			name: "known transaction overrides policy marker",
			err: status.Error(
				codes.Unknown,
				"transaction known: mempool min fee",
			),
			definitive: false,
		},
		{
			name: "already in block chain",
			err: status.Error(
				codes.Unknown,
				"transaction already in block chain: dust",
			),
			definitive: false,
		},
		{
			name: "bad txns allowlist entry",
			err: status.Error(
				codes.Unknown, "bad-txns-vout-negative",
			),
			definitive: true,
		},
		{
			name: "unrecognized bad txns reason",
			err: status.Error(
				codes.Unknown, "bad-txns-future-new-reason",
			),
			definitive: false,
		},
		{
			name: "generic application error",
			err: status.Error(
				codes.Unknown, "backend failure",
			),
			definitive: false,
		},
		{
			name: "transport failure",
			err: status.Error(
				codes.Unavailable, "connection closed",
			),
			definitive: false,
		},
		{
			name: "transport failure with policy text",
			err: status.Error(
				codes.Unavailable, "dust",
			),
			definitive: false,
		},
		{
			name: "internal failure with policy text",
			err: status.Error(
				codes.Internal, "insufficient fee",
			),
			definitive: false,
		},
		{
			name: "canceled with policy text",
			err: status.Error(
				codes.Canceled, "non-final",
			),
			definitive: false,
		},
		{
			name: "deadline exceeded with policy text",
			err: status.Error(
				codes.DeadlineExceeded, "dust",
			),
			definitive: false,
		},
		{
			name: "undefined application error with policy text",
			err: status.Error(
				codes.Unknown, "undefined: non-final",
			),
			definitive: false,
		},
		{
			name:       "plain error",
			err:        errors.New("local failure"),
			definitive: false,
		},
		{
			name:       "plain error with policy text",
			err:        errors.New("non-final"),
			definitive: false,
		},
		{
			name:       "raw undefined error with policy text",
			err:        errors.New("undefined: non-final"),
			definitive: false,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(
				t, testCase.definitive,
				isDefinitivePublishError(testCase.err),
			)
		})
	}
}

func TestDefinitivePublishRPCErrReasons(t *testing.T) {
	t.Parallel()

	definitive := []btcwalletchain.RPCErr{
		btcwalletchain.ErrInsufficientFee,
		btcwalletchain.ErrMempoolMinFeeNotMet,
		btcwalletchain.ErrMinRelayFeeNotMet,
		btcwalletchain.ErrMempoolChainTooLong,
		btcwalletchain.ErrEmptyOutput,
		btcwalletchain.ErrEmptyInput,
		btcwalletchain.ErrTxTooSmall,
		btcwalletchain.ErrDuplicateInput,
		btcwalletchain.ErrEmptyPrevOut,
		btcwalletchain.ErrBelowOutValue,
		btcwalletchain.ErrNegativeOutput,
		btcwalletchain.ErrLargeOutput,
		btcwalletchain.ErrLargeTotalOutput,
		btcwalletchain.ErrScriptVerifyFlag,
		btcwalletchain.ErrTooManySigOps,
		btcwalletchain.ErrOversizeTx,
		btcwalletchain.ErrNonStandardScript,
		btcwalletchain.ErrTxTooLarge,
		btcwalletchain.ErrDust,
		btcwalletchain.ErrNonFinal,
		btcwalletchain.ErrNonBIP68Final,
		btcwalletchain.ErrNonMandatoryScriptVerifyFlag,
	}
	for _, reason := range definitive {
		reason := reason
		t.Run(reason.Error(), func(t *testing.T) {
			err := status.Error(codes.Unknown, reason.Error())
			require.True(t, isDefinitivePublishError(err))
		})
	}

	ambiguous := []btcwalletchain.RPCErr{
		btcwalletchain.ErrMissingInputsOrSpent,
		btcwalletchain.ErrTxAlreadyKnown,
		btcwalletchain.ErrTxAlreadyConfirmed,
		btcwalletchain.ErrMempoolConflict,
		btcwalletchain.ErrReplacementAddsUnconfirmed,
		btcwalletchain.ErrTooManyReplacements,
		btcwalletchain.ErrConflictingTx,
		btcwalletchain.ErrTxAlreadyInMempool,
		btcwalletchain.ErrMissingInputs,
		btcwalletchain.ErrSameNonWitnessData,
	}
	for _, reason := range ambiguous {
		reason := reason
		t.Run(reason.Error(), func(t *testing.T) {
			err := status.Error(codes.Unknown, reason.Error())
			require.False(t, isDefinitivePublishError(err))
		})
	}
}

func TestWrapValidateAndPublishError(t *testing.T) {
	t.Parallel()

	definitiveSource := status.Error(codes.Unknown, "non-final")
	definitiveErr := wrapValidateAndPublishError(definitiveSource)
	require.ErrorContains(
		t, definitiveErr, "unable to validate and publish transaction",
	)
	require.True(t, tapnode.IsDefinitivePublishError(definitiveErr))
	require.ErrorIs(t, definitiveErr, definitiveSource)
	require.Equal(t, codes.Unknown, status.Code(definitiveErr))

	ambiguousSource := status.Error(codes.Unavailable, "connection closed")
	ambiguousErr := wrapValidateAndPublishError(ambiguousSource)
	require.ErrorContains(
		t, ambiguousErr, "unable to validate and publish transaction",
	)
	require.False(t, tapnode.IsDefinitivePublishError(ambiguousErr))
	require.ErrorIs(t, ambiguousErr, ambiguousSource)
	require.Equal(t, codes.Unavailable, status.Code(ambiguousErr))
}

// fakeChainNotifier is a minimal fake of the lndclient chain notifier
// that captures spend registrations and forwards caller-provided
// channels.
type fakeChainNotifier struct {
	spendChan chan *chainntnfs.SpendDetail
	errChan   chan error

	registeredOutpoint *wire.OutPoint
	registeredScript   []byte
	registeredHint     int32
	registeredOpts     *lndclient.NotifierOptions

	registerErr error
}

func (f *fakeChainNotifier) RawClientWithMacAuth(
	ctx context.Context) (context.Context, time.Duration,
	chainrpc.ChainNotifierClient) {

	return ctx, 0, nil
}

func (f *fakeChainNotifier) RegisterBlockEpochNtfn(
	ctx context.Context) (chan int32, chan error, error) {

	return nil, nil, nil
}

func (f *fakeChainNotifier) RegisterConfirmationsNtfn(ctx context.Context,
	txid *chainhash.Hash, pkScript []byte, numConfs, heightHint int32,
	opts ...lndclient.NotifierOption) (chan *chainntnfs.TxConfirmation,
	chan error, error) {

	return nil, nil, nil
}

func (f *fakeChainNotifier) RegisterSpendNtfn(ctx context.Context,
	outpoint *wire.OutPoint, pkScript []byte, heightHint int32,
	opts ...lndclient.NotifierOption) (chan *chainntnfs.SpendDetail,
	chan error, error) {

	if f.registerErr != nil {
		return nil, nil, f.registerErr
	}

	f.registeredOutpoint = outpoint
	f.registeredScript = pkScript
	f.registeredHint = heightHint

	options := lndclient.DefaultNotifierOptions()
	for _, opt := range opts {
		opt(options)
	}
	f.registeredOpts = options

	return f.spendChan, f.errChan, nil
}

// TestRegisterSpendNtfn asserts that the chain bridge forwards spend
// registrations to the underlying lnd notifier with the re-org channel
// wired through, and passes the spend event stream back unmodified.
func TestRegisterSpendNtfn(t *testing.T) {
	t.Parallel()

	fake := &fakeChainNotifier{
		spendChan: make(chan *chainntnfs.SpendDetail, 1),
		errChan:   make(chan error, 1),
	}
	bridge := NewLndRpcChainBridge(
		&lndclient.LndServices{ChainNotifier: fake}, nil, nil,
	)

	op := wire.OutPoint{Index: 7}
	op.Hash[0] = 0xaa
	script := []byte{0x51}
	reOrgChan := make(chan struct{}, 1)

	spendChan, errChan, err := bridge.RegisterSpendNtfn(
		context.Background(), &op, script, 42, reOrgChan,
	)
	require.NoError(t, err)

	// The registration must be forwarded verbatim, with the re-org
	// channel installed via the notifier option.
	require.Equal(t, &op, fake.registeredOutpoint)
	require.Equal(t, script, fake.registeredScript)
	require.EqualValues(t, 42, fake.registeredHint)
	require.NotNil(t, fake.registeredOpts)
	require.True(t, reOrgChan == fake.registeredOpts.ReOrgChan)

	// The event stream is a passthrough: a detail pushed by the
	// notifier arrives on the returned channel.
	detail := &chainntnfs.SpendDetail{SpendingHeight: 100}
	fake.spendChan <- detail
	select {
	case got := <-spendChan:
		require.Equal(t, detail, got)
	default:
		t.Fatal("spend detail not forwarded")
	}

	// Same for the error stream.
	fake.errChan <- errors.New("boom")
	select {
	case got := <-errChan:
		require.ErrorContains(t, got, "boom")
	default:
		t.Fatal("error not forwarded")
	}
}

// TestRegisterSpendNtfnNoReorgChan asserts that a nil re-org channel is
// not installed as a notifier option.
func TestRegisterSpendNtfnNoReorgChan(t *testing.T) {
	t.Parallel()

	fake := &fakeChainNotifier{
		spendChan: make(chan *chainntnfs.SpendDetail, 1),
		errChan:   make(chan error, 1),
	}
	bridge := NewLndRpcChainBridge(
		&lndclient.LndServices{ChainNotifier: fake}, nil, nil,
	)

	_, _, err := bridge.RegisterSpendNtfn(
		context.Background(), &wire.OutPoint{}, nil, 0, nil,
	)
	require.NoError(t, err)
	require.Nil(t, fake.registeredOpts.ReOrgChan)
}

// TestRegisterSpendNtfnError asserts that registration errors are
// surfaced, wrapped.
func TestRegisterSpendNtfnError(t *testing.T) {
	t.Parallel()

	fake := &fakeChainNotifier{registerErr: errors.New("nope")}
	bridge := NewLndRpcChainBridge(
		&lndclient.LndServices{ChainNotifier: fake}, nil, nil,
	)

	_, _, err := bridge.RegisterSpendNtfn(
		context.Background(), &wire.OutPoint{}, nil, 0, nil,
	)
	require.ErrorContains(t, err, "unable to register for spend")
	require.ErrorContains(t, err, "nope")
}
