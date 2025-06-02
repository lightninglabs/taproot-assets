package supplycommit

import (
	"context"
	"sync"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/lightningnetwork/lnd/chainntnfs"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/stretchr/testify/mock"
)

// mockSupplyTreeView is a mock implementation of the SupplyTreeView interface.
type mockSupplyTreeView struct {
	mock.Mock
}

func (m *mockSupplyTreeView) FetchSubTree(_ context.Context,
	assetSpec asset.Specifier,
	treeType SupplySubTree) lfn.Result[mssmt.Tree] {

	args := m.Called(assetSpec, treeType)
	return args.Get(0).(lfn.Result[mssmt.Tree])
}

func (m *mockSupplyTreeView) FetchSubTrees(_ context.Context,
	assetSpec asset.Specifier) lfn.Result[SupplyTrees] {

	args := m.Called(assetSpec)
	return args.Get(0).(lfn.Result[SupplyTrees])
}

func (m *mockSupplyTreeView) FetchRootSupplyTree(_ context.Context,
	assetSpec asset.Specifier) lfn.Result[mssmt.Tree] {

	args := m.Called(assetSpec)
	return args.Get(0).(lfn.Result[mssmt.Tree])
}

// mockCommitmentTracker is a mock implementation of the CommitmentTracker
// interface.
type mockCommitmentTracker struct {
	mock.Mock
}

func (m *mockCommitmentTracker) UnspentPrecommits(ctx context.Context,
	assetSpec asset.Specifier) lfn.Result[PreCommits] {

	args := m.Called(ctx, assetSpec)
	return args.Get(0).(lfn.Result[PreCommits])
}

func (m *mockCommitmentTracker) SupplyCommit(ctx context.Context,
	assetSpec asset.Specifier) RootCommitResp {

	args := m.Called(ctx, assetSpec)
	return args.Get(0).(RootCommitResp)
}

// fundPsbtMockFn defines a type for the mock function used in FundPsbt,
// to simplify a long type assertion.
type fundPsbtMockFn func(
	context.Context, *psbt.Packet, uint32,
	chainfee.SatPerKWeight, int32,
) (*tapsend.FundedPsbt, error)

// signAndFinalizePsbtMockFn defines a type for the mock function used in
// SignAndFinalizePsbt, to simplify a long type assertion.
type signAndFinalizePsbtMockFn func(
	context.Context, *psbt.Packet,
) (*psbt.Packet, error)

// mockWallet is a mock implementation of the Wallet interface.
type mockWallet struct {
	mock.Mock
}

func (m *mockWallet) FundPsbt(
	ctx context.Context, packet *psbt.Packet, minConfs uint32,
	feeRate chainfee.SatPerKWeight, changeIdx int32,
) (*tapsend.FundedPsbt, error) {

	args := m.Called(ctx, packet, minConfs, feeRate, changeIdx)

	// Check if the first argument returned by the mock is a function.
	// If so, this indicates a custom mock implementation that should be
	// executed to get the actual return values.
	arg0 := args.Get(0)
	if fn, ok := arg0.(fundPsbtMockFn); ok {
		return fn(ctx, packet, minConfs, feeRate, changeIdx)
	}

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*tapsend.FundedPsbt), args.Error(1)
}

func (m *mockWallet) SignAndFinalizePsbt(ctx context.Context,
	packet *psbt.Packet) (*psbt.Packet, error) {

	args := m.Called(ctx, packet)

	// Check if the first argument returned by the mock is a function.
	// If so, this indicates a custom mock implementation that should be
	// executed to get the actual return values.
	arg0 := args.Get(0)
	if fn, ok := arg0.(signAndFinalizePsbtMockFn); ok {
		return fn(ctx, packet)
	}

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*psbt.Packet), args.Error(1)
}

func (m *mockWallet) ImportTaprootOutput(ctx context.Context,
	pubKey *btcec.PublicKey) (btcutil.Address, error) {

	args := m.Called(ctx, pubKey)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(btcutil.Address), args.Error(1)
}

func (m *mockWallet) UnlockInput(ctx context.Context, op wire.OutPoint) error {
	args := m.Called(ctx, op)
	return args.Error(0)
}

func (m *mockWallet) DeriveNextKey(
	ctx context.Context) (keychain.KeyDescriptor, error) {

	args := m.Called(ctx)
	if args.Get(0) == nil {
		return keychain.KeyDescriptor{}, args.Error(1)
	}
	return args.Get(0).(keychain.KeyDescriptor), args.Error(1)
}

// mockChainBridge is a mock implementation of the tapgarden.ChainBridge
// interface.
type mockChainBridge struct {
	mock.Mock
}

func (m *mockChainBridge) RegisterConfirmationsNtfn(
	ctx context.Context, txid *chainhash.Hash, pkScript []byte,
	numConfs, heightHint uint32, includeBlock bool,
	reOrgChan chan struct{},
) (*chainntnfs.ConfirmationEvent, chan error, error) {

	args := m.Called(
		ctx, txid, pkScript, numConfs, heightHint, includeBlock,
		reOrgChan,
	)
	if args.Get(0) == nil {
		return nil, nil, args.Error(2)
	}
	return args.Get(0).(*chainntnfs.ConfirmationEvent),
		args.Get(1).(chan error), args.Error(2)
}

func (m *mockChainBridge) RegisterSpendNtfn(ctx context.Context,
	outpoint *wire.OutPoint, pkScript []byte,
	heightHint uint32) (*chainntnfs.SpendEvent, error) {

	args := m.Called(ctx, outpoint, pkScript, heightHint)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*chainntnfs.SpendEvent), args.Error(1)
}

func (m *mockChainBridge) PublishTransaction(ctx context.Context,
	tx *wire.MsgTx, label string) error {

	args := m.Called(ctx, tx, label)
	return args.Error(0)
}

func (m *mockChainBridge) EstimateFee(ctx context.Context,
	confTarget uint32) (chainfee.SatPerKWeight, error) {

	args := m.Called(ctx, confTarget)
	if args.Get(0) == nil {
		return chainfee.SatPerKWeight(0), args.Error(1)
	}
	return args.Get(0).(chainfee.SatPerKWeight), args.Error(1)
}

func (m *mockChainBridge) CurrentHeight(ctx context.Context) (uint32, error) {
	args := m.Called(ctx)
	return args.Get(0).(uint32), args.Error(1)
}

func (m *mockChainBridge) RegisterBlockEpochNtfn(
	ctx context.Context) (chan int32, chan error, error) {

	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, nil, args.Error(2)
	}
	return args.Get(0).(chan int32), args.Get(1).(chan error), args.Error(2)
}

func (m *mockChainBridge) GetBlock(ctx context.Context,
	hash chainhash.Hash) (*wire.MsgBlock, error) {

	args := m.Called(ctx, hash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*wire.MsgBlock), args.Error(1)
}

func (m *mockChainBridge) GetBlockHash(ctx context.Context,
	height int64) (chainhash.Hash, error) {

	args := m.Called(ctx, height)
	return args.Get(0).(chainhash.Hash), args.Error(1)
}

func (m *mockChainBridge) VerifyBlock(ctx context.Context,
	header wire.BlockHeader, height uint32) error {

	args := m.Called(ctx, header, height)
	return args.Error(0)
}

func (m *mockChainBridge) GetBlockTimestamp(ctx context.Context,
	height uint32) int64 {

	args := m.Called(ctx, height)
	return args.Get(0).(int64)
}

func (m *mockChainBridge) GenFileChainLookup(f *proof.File) asset.ChainLookup {
	args := m.Called(f)
	return args.Get(0).(asset.ChainLookup)
}

func (m *mockChainBridge) GenProofChainLookup(
	p *proof.Proof) (asset.ChainLookup, error) {

	args := m.Called(p)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(asset.ChainLookup), args.Error(1)
}

// mockStateMachineStore is a mock implementation of the StateMachineStore
// interface.
type mockStateMachineStore struct {
	mock.Mock
}

func (m *mockStateMachineStore) InsertPendingUpdate(ctx context.Context,
	spec asset.Specifier, event SupplyUpdateEvent) error {

	args := m.Called(ctx, spec, event)
	return args.Error(0)
}

func (m *mockStateMachineStore) InsertSignedCommitTx(ctx context.Context,
	spec asset.Specifier, tx SupplyCommitTxn) error {

	args := m.Called(ctx, spec, tx)
	return args.Error(0)
}

func (m *mockStateMachineStore) CommitState(ctx context.Context,
	spec asset.Specifier, state State) error {

	args := m.Called(ctx, spec, state)
	return args.Error(0)
}

func (m *mockStateMachineStore) FetchState(ctx context.Context,
	spec asset.Specifier) (State, lfn.Option[SupplyStateTransition],
	error) {

	args := m.Called(ctx, spec)
	if args.Get(2) != nil {
		return nil, lfn.None[SupplyStateTransition](), args.Error(2)
	}
	state := args.Get(0)
	if state == nil {
		return nil, args.Get(1).(lfn.Option[SupplyStateTransition]),
			args.Error(2)
	}
	return state.(State),
		args.Get(1).(lfn.Option[SupplyStateTransition]), args.Error(2)
}

func (m *mockStateMachineStore) ApplyStateTransition(ctx context.Context,
	spec asset.Specifier, transition SupplyStateTransition) error {

	args := m.Called(ctx, spec, transition)
	return args.Error(0)
}

// mockDaemonAdapters is a mock implementation of the protofsm.DaemonAdapters
// interface.
type mockDaemonAdapters struct {
	mock.Mock

	confChan  chan *chainntnfs.TxConfirmation
	spendChan chan *chainntnfs.SpendDetail
}

func newMockDaemonAdapters() *mockDaemonAdapters {
	return &mockDaemonAdapters{
		confChan:  make(chan *chainntnfs.TxConfirmation, 1),
		spendChan: make(chan *chainntnfs.SpendDetail, 1),
	}
}

func (m *mockDaemonAdapters) BroadcastTransaction(
	tx *wire.MsgTx, label string) error {

	args := m.Called(tx, label)
	return args.Error(0)
}

func (m *mockDaemonAdapters) RegisterConfirmationsNtfn(
	txid *chainhash.Hash, pkScript []byte,
	numConfs, heightHint uint32, opts ...chainntnfs.NotifierOption,
) (*chainntnfs.ConfirmationEvent, error) {

	args := m.Called(txid, pkScript, numConfs, heightHint, opts)

	err := args.Error(0)

	return &chainntnfs.ConfirmationEvent{
		Confirmed: m.confChan,
	}, err
}

func (m *mockDaemonAdapters) RegisterSpendNtfn(outpoint *wire.OutPoint,
	pkScript []byte, heightHint uint32) (*chainntnfs.SpendEvent, error) {

	args := m.Called(outpoint, pkScript, heightHint)

	err := args.Error(0)

	return &chainntnfs.SpendEvent{
		Spend: m.spendChan,
	}, err
}

func (m *mockDaemonAdapters) SendMessages(pub btcec.PublicKey,
	msgs []lnwire.Message) error {

	args := m.Called(pub, msgs)
	return args.Error(0)
}

// mockErrorReporter is a mock implementation of the protofsm.ErrorReporter
// interface.
type mockErrorReporter struct {
	mock.Mock
	reportedError error
	mu            sync.Mutex
}

func (m *mockErrorReporter) ReportError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reportedError = err
	m.Called(err)
}

func (m *mockErrorReporter) GetReportedError() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.reportedError
}
