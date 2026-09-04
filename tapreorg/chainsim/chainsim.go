// Package chainsim provides an in-memory chain implementing
// tapreorg.ChainNotifier, for property tests that drive the watcher
// through mining, re-orgs and restarts without a chain backend.
//
// Subscriptions behave like lnd's: they dispatch historically on
// registration, re-notify after re-orgs, deliver only confirmed
// evidence, and enforce the notifier's registration limits. Per-
// subscription delivery is ordered and asynchronous, so chain
// mutations never block on consumers. Failure is first-class:
// FailNextCalls injects transient notifier errors, the Sever methods
// close streams the way lnd's pruning and restarts do, and the Error
// methods deliver errors on the subscription error channels, so
// tests can exercise the watcher's repair paths, not only its happy
// ones. Hostile orderings are first-class too: HoldDeliveries defers
// events while the chain moves on (a lagging consumer), and
// ReplayLastEvents duplicates standing reports (an at-least-once
// boundary), so tests can construct deterministically the stale and
// duplicated deliveries a consumer must survive. Re-orgs may shrink
// the chain.
package chainsim

import (
	"context"
	"fmt"
	"sync"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/tapreorg"
	"github.com/lightningnetwork/lnd/chainntnfs"
)

// baseHeight is the height of the simulated chain's genesis tip:
// block i of the chain sits at baseHeight+i+1.
const baseHeight = 100

// queueDepth bounds per-subscription event queues; a full queue
// panics, which in a test harness indicates a runaway scenario.
const queueDepth = 1024

// simBlock is one simulated block.
type simBlock struct {
	header wire.BlockHeader
	hash   chainhash.Hash
	height uint32
	txs    []*wire.MsgTx

	// seq orders blocks by connection time, for the historical
	// rescan bound on confirmation subscriptions.
	seq uint32
}

// txLocation locates a transaction in the current chain.
type txLocation struct {
	blockHash chainhash.Hash
	height    uint32
	txIndex   uint32
	tx        *wire.MsgTx
	block     *wire.MsgBlock
	seq       uint32
}

// spender describes the current confirmed spender of an outpoint.
type spender struct {
	tx         *wire.MsgTx
	txid       chainhash.Hash
	height     uint32
	inputIndex uint32
}

// eventQueue delivers one subscription's events in order without
// holding the chain lock.
type eventQueue struct {
	events chan func()
}

func newEventQueue(ctx context.Context) *eventQueue {
	q := &eventQueue{events: make(chan func(), queueDepth)}

	go func() {
		for {
			select {
			case deliver := <-q.events:
				deliver()

			case <-ctx.Done():
				return
			}
		}
	}()

	return q
}

func (q *eventQueue) push(deliver func()) {
	select {
	case q.events <- deliver:
	default:
		panic("chainsim: event queue overflow")
	}
}

// confSub is a confirmation subscription.
type confSub struct {
	ctx       context.Context
	txid      chainhash.Hash
	numConfs  uint32
	reorgChan chan struct{}
	confChan  chan *chainntnfs.TxConfirmation
	errChan   chan error
	queue     *eventQueue

	// heightHint and registeredSeq bound the historical rescan the
	// way lnd's does: a transaction confirmed below the hint in a
	// block that predates the registration is never found.
	heightHint    uint32
	registeredSeq uint32

	// lastBlock is the block hash last reported for the tx, nil if
	// the sub last reported (or started) unconfirmed (or below its
	// depth requirement).
	lastBlock *chainhash.Hash
}

// spendSub is a spend subscription.
type spendSub struct {
	ctx       context.Context
	op        wire.OutPoint
	reorgChan chan struct{}
	spendChan chan *chainntnfs.SpendDetail
	errChan   chan error
	queue     *eventQueue

	// last identifies the (txid, height) last reported as the
	// spender, nil if none.
	lastTxid   *chainhash.Hash
	lastHeight uint32
}

// epochSub is a block epoch subscription.
type epochSub struct {
	ctx       context.Context
	epochChan chan int32
	errChan   chan error
	queue     *eventQueue
}

// heldDelivery is a delivery deferred by HoldDeliveries.
type heldDelivery struct {
	queue   *eventQueue
	deliver func()
}

// Chain is the simulated chain.
type Chain struct {
	mu sync.Mutex

	blocks    []*simBlock
	allBlocks map[chainhash.Hash]*simBlock
	blockSeq  uint32

	confSubs  map[int]*confSub
	spendSubs map[int]*spendSub
	epochSubs map[int]*epochSub
	nextSubID int

	// pendingFailures counts down injected failures: while
	// positive, fallible notifier calls (registrations,
	// GetBlockHash, CurrentHeight) fail.
	pendingFailures int

	// holding, while true, defers every delivery into held rather
	// than pushing it to its subscription queue; ReleaseDeliveries
	// flushes in dispatch order.
	holding bool
	held    []heldDelivery
}

// New creates an empty simulated chain at baseHeight.
func New() *Chain {
	return &Chain{
		allBlocks: make(map[chainhash.Hash]*simBlock),
		confSubs:  make(map[int]*confSub),
		spendSubs: make(map[int]*spendSub),
		epochSubs: make(map[int]*epochSub),
	}
}

// BestHeight returns the current tip height.
func (c *Chain) BestHeight() uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.bestHeight()
}

func (c *Chain) bestHeight() uint32 {
	return baseHeight + uint32(len(c.blocks))
}

// MineBlock appends one block containing the given transactions and
// dispatches subscription events. It returns the new height.
func (c *Chain) MineBlock(txs ...*wire.MsgTx) uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.appendBlock(txs)
	c.dispatch()

	return c.bestHeight()
}

// MineBlocks appends n empty blocks.
func (c *Chain) MineBlocks(n int) uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()

	for i := 0; i < n; i++ {
		c.appendBlock(nil)
	}
	c.dispatch()

	return c.bestHeight()
}

// Reorg disconnects depth blocks from the tip and connects the given
// replacement blocks (outermost first). A replacement shorter than
// the disconnected range shrinks the chain — rare on a real network
// but entirely legal (a shorter chain can carry more work), and a
// consumer must survive its best height decreasing.
func (c *Chain) Reorg(depth int, replacement ...[]*wire.MsgTx) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if depth > len(c.blocks) {
		panic(fmt.Sprintf("chainsim: reorg depth %d exceeds chain "+
			"length %d", depth, len(c.blocks)))
	}

	c.blocks = c.blocks[:len(c.blocks)-depth]
	for _, txs := range replacement {
		c.appendBlock(txs)
	}
	c.dispatch()
}

// appendBlock builds and connects one block. The caller holds the
// lock.
func (c *Chain) appendBlock(txs []*wire.MsgTx) {
	c.blockSeq++

	var prev chainhash.Hash
	if len(c.blocks) > 0 {
		prev = c.blocks[len(c.blocks)-1].hash
	}

	// The nonce makes replacement blocks distinct from what they
	// replace; the header hash is the block hash, so GetBlock and
	// conf events stay self-consistent.
	header := wire.BlockHeader{
		Version:   2,
		PrevBlock: prev,
		Nonce:     c.blockSeq,
	}
	for _, tx := range txs {
		hash := tx.TxHash()
		for i, b := range hash {
			header.MerkleRoot[i] ^= b
		}
	}

	block := &simBlock{
		header: header,
		hash:   header.BlockHash(),
		height: c.bestHeight() + 1,
		txs:    txs,
		seq:    c.blockSeq,
	}
	c.blocks = append(c.blocks, block)
	c.allBlocks[block.hash] = block
}

// findTx locates a transaction in the current chain. The caller holds
// the lock.
func (c *Chain) findTx(txid chainhash.Hash) *txLocation {
	for _, block := range c.blocks {
		for i, tx := range block.txs {
			if tx.TxHash() != txid {
				continue
			}

			return &txLocation{
				blockHash: block.hash,
				height:    block.height,
				txIndex:   uint32(i),
				tx:        tx,
				block:     block.msgBlock(),
				seq:       block.seq,
			}
		}
	}

	return nil
}

// findSpender locates the confirmed spender of an outpoint in the
// current chain. The caller holds the lock.
func (c *Chain) findSpender(op wire.OutPoint) *spender {
	for _, block := range c.blocks {
		for _, tx := range block.txs {
			for i, txIn := range tx.TxIn {
				if txIn.PreviousOutPoint != op {
					continue
				}

				return &spender{
					tx:         tx,
					txid:       tx.TxHash(),
					height:     block.height,
					inputIndex: uint32(i),
				}
			}
		}
	}

	return nil
}

// msgBlock renders the simulated block as a wire block.
func (b *simBlock) msgBlock() *wire.MsgBlock {
	block := &wire.MsgBlock{Header: b.header}
	block.Transactions = append(block.Transactions, b.txs...)

	return block
}

// dispatch reconciles every subscription against the current chain.
// The caller holds the lock.
func (c *Chain) dispatch() {
	for id, sub := range c.confSubs {
		if sub.ctx.Err() != nil {
			delete(c.confSubs, id)
			continue
		}
		c.dispatchConf(sub)
	}

	for id, sub := range c.spendSubs {
		if sub.ctx.Err() != nil {
			delete(c.spendSubs, id)
			continue
		}
		c.dispatchSpend(sub)
	}

	height := int32(c.bestHeight())
	for id, sub := range c.epochSubs {
		if sub.ctx.Err() != nil {
			delete(c.epochSubs, id)
			continue
		}

		s := sub
		c.deliver(s.queue, func() {
			select {
			case s.epochChan <- height:
			case <-s.ctx.Done():
			}
		})
	}
}

// dispatchConf reconciles one confirmation subscription. The caller
// holds the lock. A subscription at numConfs fires only once the
// transaction genuinely holds that depth on the current chain, as
// lnd's notifier does.
func (c *Chain) dispatchConf(sub *confSub) {
	loc := c.findTx(sub.txid)
	if loc != nil {
		depth := c.bestHeight() - loc.height + 1
		if depth < sub.numConfs {
			loc = nil
		}
	}

	// Mirror lnd's historical rescan bound: registration scans only
	// [heightHint, tip], so a transaction already confirmed below
	// the hint before the registration existed is never found.
	// Blocks connected after registration dispatch regardless of
	// height, as lnd's block-connected path scans whole blocks.
	if loc != nil && loc.height < sub.heightHint &&
		loc.seq <= sub.registeredSeq {

		loc = nil
	}

	switch {
	// Newly (or differently) confirmed at depth: deliver the
	// location.
	case loc != nil && (sub.lastBlock == nil ||
		*sub.lastBlock != loc.blockHash):

		conf := &chainntnfs.TxConfirmation{
			Tx:          loc.tx,
			BlockHash:   &loc.blockHash,
			BlockHeight: loc.height,
			TxIndex:     loc.txIndex,
			Block:       loc.block,
		}
		blockHash := loc.blockHash
		sub.lastBlock = &blockHash

		s := sub
		c.deliver(s.queue, func() {
			select {
			case s.confChan <- conf:
			case <-s.ctx.Done():
			}
		})

	// Fell out of the chain (or below depth): signal the re-org.
	// A subscription without a re-org channel simply drops the
	// signal, as lndclient does for one-shot registrations.
	case loc == nil && sub.lastBlock != nil:
		sub.lastBlock = nil
		if sub.reorgChan == nil {
			return
		}

		s := sub
		c.deliver(s.queue, func() {
			select {
			case s.reorgChan <- struct{}{}:
			case <-s.ctx.Done():
			}
		})
	}
}

// dispatchSpend reconciles one spend subscription. The caller holds
// the lock.
func (c *Chain) dispatchSpend(sub *spendSub) {
	sp := c.findSpender(sub.op)

	// Unchanged?
	if sp == nil && sub.lastTxid == nil {
		return
	}
	if sp != nil && sub.lastTxid != nil && sp.txid == *sub.lastTxid &&
		sp.height == sub.lastHeight {

		return
	}

	// Anything previously reported has been displaced.
	if sub.lastTxid != nil {
		s := sub
		c.deliver(s.queue, func() {
			select {
			case s.reorgChan <- struct{}{}:
			case <-s.ctx.Done():
			}
		})
		sub.lastTxid = nil
	}

	if sp == nil {
		return
	}

	op := sub.op
	detail := &chainntnfs.SpendDetail{
		SpentOutPoint:     &op,
		SpenderTxHash:     &sp.txid,
		SpendingTx:        sp.tx,
		SpenderInputIndex: sp.inputIndex,
		SpendingHeight:    int32(sp.height),
	}
	txid := sp.txid
	sub.lastTxid = &txid
	sub.lastHeight = sp.height

	s := sub
	c.deliver(s.queue, func() {
		select {
		case s.spendChan <- detail:
		case <-s.ctx.Done():
		}
	})
}

// deliver pushes one delivery to a subscription queue, or defers it
// while deliveries are held. The caller holds the lock.
func (c *Chain) deliver(q *eventQueue, deliverFn func()) {
	if c.holding {
		c.held = append(c.held, heldDelivery{
			queue:   q,
			deliver: deliverFn,
		})
		return
	}

	q.push(deliverFn)
}

// HoldDeliveries defers all subsequent deliveries — confirmations,
// spends, re-org signals, epochs, injected errors and stream closes —
// until ReleaseDeliveries. The chain's own state keeps advancing, as
// a real notifier's does while its client lags: held events describe
// the world as it was when they were dispatched, so tests can
// deterministically construct the stale orderings a consumer must
// survive.
func (c *Chain) HoldDeliveries() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.holding = true
}

// ReleaseDeliveries flushes every held delivery in dispatch order and
// resumes direct delivery.
func (c *Chain) ReleaseDeliveries() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.holding = false
	for _, h := range c.held {
		h.queue.push(h.deliver)
	}
	c.held = nil
}

// ReplayLastEvents re-delivers every subscription's current standing
// report — the duplicate delivery an at-least-once notifier boundary
// permits. Subscriptions with nothing standing (unconfirmed, unspent)
// deliver nothing.
func (c *Chain) ReplayLastEvents() {
	c.mu.Lock()
	defer c.mu.Unlock()

	for id, sub := range c.confSubs {
		if sub.ctx.Err() != nil {
			delete(c.confSubs, id)
			continue
		}
		sub.lastBlock = nil
		c.dispatchConf(sub)
	}
	for id, sub := range c.spendSubs {
		if sub.ctx.Err() != nil {
			delete(c.spendSubs, id)
			continue
		}
		sub.lastTxid = nil
		c.dispatchSpend(sub)
	}
}

// ErrorSubscriptionStreams delivers an error on every open
// confirmation and spend subscription's error channel, as lnd does
// when a registration fails server-side. The subscriptions remain
// registered; a consumer that treats the stream as dead cancels it.
func (c *Chain) ErrorSubscriptionStreams(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, sub := range c.confSubs {
		s := sub
		c.deliver(s.queue, func() {
			select {
			case s.errChan <- err:
			case <-s.ctx.Done():
			}
		})
	}
	for _, sub := range c.spendSubs {
		s := sub
		c.deliver(s.queue, func() {
			select {
			case s.errChan <- err:
			case <-s.ctx.Done():
			}
		})
	}
}

// ErrorEpochStreams delivers an error on every open block epoch
// subscription's error channel.
func (c *Chain) ErrorEpochStreams(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, sub := range c.epochSubs {
		s := sub
		c.deliver(s.queue, func() {
			select {
			case s.errChan <- err:
			case <-s.ctx.Done():
			}
		})
	}
}

// FailNextCalls arranges for the next n fallible notifier calls —
// subscription registrations, GetBlockHash and CurrentHeight — to
// return an injected error, simulating a notifier under transient
// distress. Passing zero clears any pending injected failures.
func (c *Chain) FailNextCalls(n int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.pendingFailures = n
}

// failNext consumes one injected failure, if any are pending. The
// caller holds the lock.
func (c *Chain) failNext() error {
	if c.pendingFailures <= 0 {
		return nil
	}
	c.pendingFailures--

	return fmt.Errorf("chainsim: injected transient failure")
}

// SeverSubscriptionStreams closes every open confirmation and spend
// stream, as lnd does when it prunes subscriptions a safety margin
// past their dispatch or drops the connection entirely. Block epoch
// streams stay open; see SeverEpochStreams.
func (c *Chain) SeverSubscriptionStreams() {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Closes are pushed through each subscription's queue so they
	// order after any deliveries already in flight.
	for id, sub := range c.confSubs {
		s := sub
		c.deliver(s.queue, func() { close(s.confChan) })
		delete(c.confSubs, id)
	}
	for id, sub := range c.spendSubs {
		s := sub
		c.deliver(s.queue, func() { close(s.spendChan) })
		delete(c.spendSubs, id)
	}
}

// SeverEpochStreams closes every open block epoch stream, as losing
// lnd does.
func (c *Chain) SeverEpochStreams() {
	c.mu.Lock()
	defer c.mu.Unlock()

	for id, sub := range c.epochSubs {
		s := sub
		c.deliver(s.queue, func() { close(s.epochChan) })
		delete(c.epochSubs, id)
	}
}

// Length returns the number of blocks on the current chain (the
// maximum re-org depth).
func (c *Chain) Length() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	return len(c.blocks)
}

// TxHeight returns the height at which the given transaction sits in
// the current chain, if it does.
func (c *Chain) TxHeight(txid chainhash.Hash) (uint32, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	loc := c.findTx(txid)
	if loc == nil {
		return 0, false
	}

	return loc.height, true
}

// RegisterConfirmationsNtfn implements tapreorg.ChainNotifier.
func (c *Chain) RegisterConfirmationsNtfn(ctx context.Context,
	txid *chainhash.Hash, pkScript []byte, numConfs, heightHint uint32,
	includeBlock bool,
	reOrgChan chan struct{}) (*chainntnfs.ConfirmationEvent, chan error,
	error) {

	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.failNext(); err != nil {
		return nil, nil, err
	}

	// Mirror lnd's registration validation: depths beyond the
	// notifier's re-org safety limit are rejected outright.
	if numConfs > chainntnfs.MaxNumConfs {
		return nil, nil, fmt.Errorf("chainsim: numConfs %d "+
			"exceeds maximum %d", numConfs,
			uint32(chainntnfs.MaxNumConfs))
	}

	// Mirror lnd's script validation: NewConfRequest parses the
	// registered script and refuses nonstandard classes.
	if _, err := txscript.ParsePkScript(pkScript); err != nil {
		return nil, nil, fmt.Errorf("chainsim: unparseable "+
			"pkScript %x: %w", pkScript, err)
	}

	subCtx, cancel := context.WithCancel(ctx)
	if numConfs == 0 {
		numConfs = 1
	}
	sub := &confSub{
		ctx:           subCtx,
		txid:          *txid,
		numConfs:      numConfs,
		reorgChan:     reOrgChan,
		confChan:      make(chan *chainntnfs.TxConfirmation, 1),
		errChan:       make(chan error, 1),
		queue:         newEventQueue(subCtx),
		heightHint:    heightHint,
		registeredSeq: c.blockSeq,
	}

	id := c.nextSubID
	c.nextSubID++
	c.confSubs[id] = sub

	// Historical dispatch.
	c.dispatchConf(sub)

	event := &chainntnfs.ConfirmationEvent{
		Confirmed: sub.confChan,
		Cancel:    cancel,
	}

	return event, sub.errChan, nil
}

// RegisterSpendNtfn implements tapreorg.ChainNotifier.
func (c *Chain) RegisterSpendNtfn(ctx context.Context,
	outpoint *wire.OutPoint, pkScript []byte, heightHint uint32,
	reOrgChan chan struct{}) (chan *chainntnfs.SpendDetail, chan error,
	error) {

	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.failNext(); err != nil {
		return nil, nil, err
	}

	// Mirror lnd's script validation: NewSpendRequest parses the
	// registered script and refuses nonstandard classes.
	if _, err := txscript.ParsePkScript(pkScript); err != nil {
		return nil, nil, fmt.Errorf("chainsim: unparseable "+
			"pkScript %x: %w", pkScript, err)
	}

	sub := &spendSub{
		ctx:       ctx,
		op:        *outpoint,
		reorgChan: reOrgChan,
		spendChan: make(chan *chainntnfs.SpendDetail, 1),
		errChan:   make(chan error, 1),
		queue:     newEventQueue(ctx),
	}

	id := c.nextSubID
	c.nextSubID++
	c.spendSubs[id] = sub

	// Historical dispatch.
	c.dispatchSpend(sub)

	return sub.spendChan, sub.errChan, nil
}

// RegisterBlockEpochNtfn implements tapreorg.ChainNotifier.
func (c *Chain) RegisterBlockEpochNtfn(
	ctx context.Context) (chan int32, chan error, error) {

	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.failNext(); err != nil {
		return nil, nil, err
	}

	sub := &epochSub{
		ctx:       ctx,
		epochChan: make(chan int32, 1),
		errChan:   make(chan error, 1),
		queue:     newEventQueue(ctx),
	}

	id := c.nextSubID
	c.nextSubID++
	c.epochSubs[id] = sub

	// Current epoch on registration, as lnd does.
	height := int32(c.bestHeight())
	c.deliver(sub.queue, func() {
		select {
		case sub.epochChan <- height:
		case <-sub.ctx.Done():
		}
	})

	return sub.epochChan, sub.errChan, nil
}

// CurrentHeight implements tapreorg.ChainNotifier.
func (c *Chain) CurrentHeight(ctx context.Context) (uint32, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.failNext(); err != nil {
		return 0, err
	}

	return c.bestHeight(), nil
}

// GetBlockHash implements tapreorg.ChainNotifier.
func (c *Chain) GetBlockHash(ctx context.Context,
	blockHeight int64) (chainhash.Hash, error) {

	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.failNext(); err != nil {
		return chainhash.Hash{}, err
	}

	idx := blockHeight - baseHeight - 1
	if idx < 0 || idx >= int64(len(c.blocks)) {
		return chainhash.Hash{}, fmt.Errorf("no block at height %d",
			blockHeight)
	}

	return c.blocks[idx].hash, nil
}

// GetBlock implements tapreorg.ChainNotifier. Orphaned blocks remain
// fetchable, as on a real node that retains them.
func (c *Chain) GetBlock(ctx context.Context,
	hash chainhash.Hash) (*wire.MsgBlock, error) {

	c.mu.Lock()
	defer c.mu.Unlock()

	block, ok := c.allBlocks[hash]
	if !ok {
		return nil, fmt.Errorf("block %v not found", hash)
	}

	return block.msgBlock(), nil
}

// A compile-time assertion that the simulator satisfies the notifier
// contract.
var _ tapreorg.ChainNotifier = (*Chain)(nil)
