package lndservices

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/lnrpc/chainrpc"
	"github.com/stretchr/testify/require"
)

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

// TestFindTxHeightInProofFileUnsetHeight asserts that a proof with an unset
// (zero) height doesn't count as a match for its anchor transaction, whether
// it's in the file itself or in an additional input.
func TestFindTxHeightInProofFileUnsetHeight(t *testing.T) {
	t.Parallel()

	// randProof returns a random proof anchored in a transaction with an
	// output of the given value, along with the transaction's hash.
	randProof := func(value int64) (proof.Proof, chainhash.Hash) {
		anchorTx := wire.NewMsgTx(2)
		anchorTx.AddTxIn(&wire.TxIn{})
		anchorTx.AddTxOut(&wire.TxOut{
			Value: value, PkScript: []byte{0x51},
		})
		block := wire.MsgBlock{Transactions: []*wire.MsgTx{anchorTx}}

		p := proof.RandProof(
			t, asset.RandGenesis(t, asset.Normal),
			test.RandPubKey(t), block, 0, 0,
		)

		return p, anchorTx.TxHash()
	}

	p, txid := randProof(1000)

	outer, _ := randProof(2000)
	outer.BlockHeight = 100

	findHeight := func(t *testing.T, height uint32,
		nested bool) (uint32, error) {

		p.BlockHeight = height
		f, err := proof.NewFile(proof.V0, p)
		require.NoError(t, err)

		if nested {
			outer.AdditionalInputs = []proof.File{*f}
			f, err = proof.NewFile(proof.V0, outer)
			require.NoError(t, err)
		}

		return findTxHeightInProofFile(f, txid)
	}

	tests := []struct {
		name   string
		nested bool
	}{{
		name:   "top level",
		nested: false,
	}, {
		name:   "additional input",
		nested: true,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			height, err := findHeight(t, 42, tc.nested)
			require.NoError(t, err)
			require.EqualValues(t, 42, height)

			_, err = findHeight(t, 0, tc.nested)
			require.ErrorIs(t, err, errTxNotFound)
		})
	}
}
