package tapreorg

import (
	"context"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightningnetwork/lnd/chainntnfs"
)

// ChainNotifier is the chain-sensing surface the watcher requires from
// its chain backend. It is deliberately declared here, in the package
// that consumes it, so that the dependency is a design contract rather
// than an accident of whatever a concrete chain bridge happens to
// expose.
//
// Semantics pinned by this contract:
//
//   - Only confirmed evidence is delivered. No notification below is
//     ever fired for a transaction that is merely in the mempool, and
//     nothing in the watcher derives state from unconfirmed evidence.
//
//   - Notifications are reorg-aware. A registration outlives its first
//     event: if the reported transaction is later re-organized out of
//     the chain, the corresponding reorg channel is signalled, and the
//     subscription re-notifies if the transaction (or, for spends, a
//     different spender) confirms again.
type ChainNotifier interface {
	// RegisterConfirmationsNtfn registers an intent to be notified
	// once txid reaches numConfs confirmations. If reOrgChan is
	// non-nil, the subscription stays open after the confirmation
	// event: a send on reOrgChan signals that the transaction was
	// re-organized out of the chain, and a subsequent confirmation
	// in a new block is delivered as a fresh confirmation event.
	RegisterConfirmationsNtfn(ctx context.Context,
		txid *chainhash.Hash, pkScript []byte, numConfs,
		heightHint uint32, includeBlock bool,
		reOrgChan chan struct{}) (*chainntnfs.ConfirmationEvent,
		chan error, error)

	// RegisterSpendNtfn registers an intent to be notified once the
	// given outpoint is spent by a confirmed transaction. The spend
	// detail carries the full spending transaction. If reOrgChan is
	// non-nil, the subscription stays open after the first spend
	// event: a send on reOrgChan signals that the previously
	// reported spend was re-organized out of the chain, and a
	// subsequent confirmed spend (by the same or a different
	// transaction) is delivered as a fresh spend detail.
	//
	// The subscription is torn down by cancelling the passed
	// context.
	RegisterSpendNtfn(ctx context.Context, outpoint *wire.OutPoint,
		pkScript []byte, heightHint uint32,
		reOrgChan chan struct{}) (chan *chainntnfs.SpendDetail,
		chan error, error)

	// RegisterBlockEpochNtfn registers an intent to be notified of
	// each new block connected to the main chain.
	RegisterBlockEpochNtfn(ctx context.Context) (chan int32,
		chan error, error)

	// CurrentHeight returns the current height of the main chain.
	CurrentHeight(ctx context.Context) (uint32, error)

	// GetBlock returns a chain block given its hash.
	GetBlock(ctx context.Context,
		hash chainhash.Hash) (*wire.MsgBlock, error)

	// GetBlockHash returns the hash of the block at the given
	// height in the best chain. The watcher uses it for startup
	// reconciliation: notifications missed while down are
	// recovered by historical dispatch only for transactions
	// still in the chain, so candidates recorded on-chain must be
	// re-verified against the dominant chain explicitly.
	GetBlockHash(ctx context.Context,
		blockHeight int64) (chainhash.Hash, error)
}
