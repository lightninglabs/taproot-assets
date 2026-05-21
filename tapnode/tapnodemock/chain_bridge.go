package tapnodemock

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapnode"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
)

// ChainBridge is an in-memory mock implementation of tapnode.ChainBridge.
type ChainBridge struct {
	FeeEstimateSignal chan struct{}
	PublishReq        chan *wire.MsgTx
	ConfReqSignal     chan int
	BlockEpochSignal  chan struct{}

	NewBlocks chan int32

	ReqCount atomic.Int32

	// ConfReqs and confErr are not guarded by a mutex. Readers must
	// synchronise with the writer via the ConfReqSignal channel: the
	// writer (RegisterConfirmationsNtfn) populates ConfReqs and
	// reassigns confErr before sending the request number on
	// ConfReqSignal, so any receive from that channel happens-after
	// the corresponding store and a read of ConfReqs[reqNo] is safe.
	ConfReqs map[int]*chainntnfs.ConfirmationEvent

	// BlocksMu protects concurrent access to Blocks. Readers (GetBlock,
	// called from caretaker goroutines) hold it for read; all writers
	// must go through SetBlock so the invariant cannot be violated
	// piecemeal.
	BlocksMu sync.RWMutex
	Blocks   map[chainhash.Hash]*wire.MsgBlock

	failFeeEstimates atomic.Bool
	errConf          atomic.Int32
	emptyConf        atomic.Int32
	confErr          chan error
}

// NewChainBridge returns a freshly-initialised mock ChainBridge.
func NewChainBridge() *ChainBridge {
	return &ChainBridge{
		FeeEstimateSignal: make(chan struct{}),
		PublishReq:        make(chan *wire.MsgTx),
		ConfReqs:          make(map[int]*chainntnfs.ConfirmationEvent),
		ConfReqSignal:     make(chan int),
		BlockEpochSignal:  make(chan struct{}, 1),
		NewBlocks:         make(chan int32),
		Blocks:            make(map[chainhash.Hash]*wire.MsgBlock),
	}
}

// FailFeeEstimatesOnce arms the next call to EstimateFee to return an error.
func (m *ChainBridge) FailFeeEstimatesOnce() {
	m.failFeeEstimates.Store(true)
}

// FailConfOnce updates the ChainBridge such that the next call to
// RegisterConfirmationNtfn will fail by returning an error on the error channel
// returned from RegisterConfirmationNtfn.
func (m *ChainBridge) FailConfOnce() {
	// Store the incremented request count so we never store 0 as a value.
	m.errConf.Store(m.ReqCount.Load() + 1)
}

// EmptyConfOnce updates the ChainBridge such that the next confirmation event
// sent via SendConfNtfn will have an empty confirmation.
func (m *ChainBridge) EmptyConfOnce() {
	// Store the incremented request count so we never store 0 as a value.
	m.emptyConf.Store(m.ReqCount.Load() + 1)
}

// SendConfNtfn dispatches a synthetic confirmation event to the watcher
// registered as request reqNo.
func (m *ChainBridge) SendConfNtfn(reqNo int, blockHash *chainhash.Hash,
	blockHeight, blockIndex int, block *wire.MsgBlock,
	tx *wire.MsgTx) {

	// Compare to the incremented request count since we incremented it
	// when storing the request number.
	req := m.ConfReqs[reqNo]
	if m.emptyConf.Load() == int32(reqNo)+1 {
		m.emptyConf.Store(0)
		req.Confirmed <- nil
		return
	}

	req.Confirmed <- &chainntnfs.TxConfirmation{
		BlockHash:   blockHash,
		BlockHeight: uint32(blockHeight),
		TxIndex:     uint32(blockIndex),
		Block:       block,
		Tx:          tx,
	}
}

// RegisterConfirmationsNtfn records a confirmation subscription and signals
// the caller via ConfReqSignal.
func (m *ChainBridge) RegisterConfirmationsNtfn(ctx context.Context,
	_ *chainhash.Hash, _ []byte, _, _ uint32, _ bool,
	_ chan struct{}) (*chainntnfs.ConfirmationEvent, chan error, error) {

	select {
	case <-ctx.Done():
		return nil, nil, fmt.Errorf("shutting down")
	default:
	}

	defer func() {
		m.ReqCount.Add(1)
	}()

	req := &chainntnfs.ConfirmationEvent{
		Confirmed: make(chan *chainntnfs.TxConfirmation),
		Cancel:    func() {},
	}
	m.confErr = make(chan error, 1)

	currentReqCount := m.ReqCount.Load()
	m.ConfReqs[int(currentReqCount)] = req

	select {
	case m.ConfReqSignal <- int(currentReqCount):
	case <-ctx.Done():
	}

	// Compare to the incremented request count since we incremented it
	// when storing the request number.
	if m.errConf.CompareAndSwap(currentReqCount+1, 0) {
		m.confErr <- fmt.Errorf("confirmation registration error")
	}

	return req, m.confErr, nil
}

// RegisterBlockEpochNtfn returns the mock's NewBlocks channel and signals
// startup via BlockEpochSignal.
func (m *ChainBridge) RegisterBlockEpochNtfn(
	ctx context.Context) (chan int32, chan error, error) {

	select {
	case <-ctx.Done():
		return nil, nil, fmt.Errorf("shutting down")
	default:
	}

	select {
	case m.BlockEpochSignal <- struct{}{}:
	case <-ctx.Done():
	}

	return m.NewBlocks, make(chan error), nil
}

// GetBlock returns a chain block given its hash.
func (m *ChainBridge) GetBlock(ctx context.Context,
	hash chainhash.Hash) (*wire.MsgBlock, error) {

	m.BlocksMu.RLock()
	block, ok := m.Blocks[hash]
	m.BlocksMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("block %s not found", hash.String())
	}

	return block, nil
}

// SetBlock records a block under its hash so a later GetBlock can return
// it. All writers to Blocks must go through this helper so the BlocksMu
// invariant cannot be violated piecemeal.
func (m *ChainBridge) SetBlock(hash chainhash.Hash, block *wire.MsgBlock) {
	m.BlocksMu.Lock()
	m.Blocks[hash] = block
	m.BlocksMu.Unlock()
}

// GetBlockByHeight returns a block given the block height.
func (m *ChainBridge) GetBlockByHeight(ctx context.Context,
	blockHeight int64) (*wire.MsgBlock, error) {

	return &wire.MsgBlock{}, nil
}

// GetBlockHeaderByHeight returns a block header given the block height.
func (m *ChainBridge) GetBlockHeaderByHeight(ctx context.Context,
	blockHeight int64) (*wire.BlockHeader, error) {

	return &wire.BlockHeader{}, nil
}

// GetBlockHash returns the hash of the block in the best blockchain at the
// given height.
func (m *ChainBridge) GetBlockHash(ctx context.Context,
	blockHeight int64) (chainhash.Hash, error) {

	return chainhash.Hash{}, nil
}

// VerifyBlock returns an error if a block (with given header and height) is not
// present on-chain. It also checks to ensure that block height corresponds to
// the given block header.
func (m *ChainBridge) VerifyBlock(_ context.Context,
	_ wire.BlockHeader, _ uint32) error {

	return nil
}

// CurrentHeight returns the mock's current chain height (always 0).
func (m *ChainBridge) CurrentHeight(_ context.Context) (uint32, error) {
	return 0, nil
}

// GetBlockTimestamp returns the timestamp of the block at the given height.
func (m *ChainBridge) GetBlockTimestamp(_ context.Context, _ uint32) (int64,
	error) {

	return 0, nil
}

// PublishTransaction records the transaction to PublishReq.
func (m *ChainBridge) PublishTransaction(_ context.Context,
	tx *wire.MsgTx, _ string) error {

	m.PublishReq <- tx
	return nil
}

// EstimateFee returns chainfee.FeePerKwFloor unless FailFeeEstimatesOnce was
// armed, in which case it returns an error once.
func (m *ChainBridge) EstimateFee(ctx context.Context,
	_ uint32) (chainfee.SatPerKWeight, error) {

	select {
	case m.FeeEstimateSignal <- struct{}{}:

	case <-ctx.Done():
		return 0, fmt.Errorf("shutting down")
	}

	if m.failFeeEstimates.Load() {
		m.failFeeEstimates.Store(false)
		return 0, fmt.Errorf("failed to estimate fee")
	}

	return chainfee.FeePerKwFloor, nil
}

// TxBlockHeight returns the block height that the given transaction was
// included in.
func (m *ChainBridge) TxBlockHeight(context.Context,
	chainhash.Hash) (uint32, error) {

	return 123, nil
}

// MeanBlockTimestamp returns the timestamp of the block at the given height as
// a Unix timestamp in seconds, taking into account the mean time elapsed over
// the previous 11 blocks.
func (m *ChainBridge) MeanBlockTimestamp(context.Context,
	uint32) (time.Time, error) {

	return time.Now(), nil
}

// GenFileChainLookup generates a chain lookup interface for the given
// proof file that can be used to validate proofs.
func (m *ChainBridge) GenFileChainLookup(*proof.File) asset.ChainLookup {
	return m
}

// GenProofChainLookup generates a chain lookup interface for the given
// single proof that can be used to validate proofs.
func (m *ChainBridge) GenProofChainLookup(*proof.Proof) (asset.ChainLookup,
	error) {

	return m, nil
}

var _ asset.ChainLookup = (*ChainBridge)(nil)
var _ tapnode.ChainBridge = (*ChainBridge)(nil)

// GenGroupVerifier returns a no-op group verifier suitable for tests that
// don't care about group-key authenticity.
func GenGroupVerifier() func(*btcec.PublicKey) error {
	return func(groupKey *btcec.PublicKey) error {
		return nil
	}
}
