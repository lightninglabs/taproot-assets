package tapnode

import (
	"context"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
)

// ChainBridge is our bridge to the target chain. It's used to get
// confirmation notifications, the current height, publish
// transactions, and also estimate fees.
type ChainBridge interface {
	proof.ChainLookupGenerator

	// RegisterConfirmationsNtfn registers an intent to be notified
	// once txid reaches numConfs confirmations.
	RegisterConfirmationsNtfn(ctx context.Context, txid *chainhash.Hash,
		pkScript []byte, numConfs, heightHint uint32,
		includeBlock bool,
		reOrgChan chan struct{}) (*chainntnfs.ConfirmationEvent,
		chan error, error)

	// RegisterBlockEpochNtfn registers an intent to be notified of
	// each new block connected to the main chain.
	RegisterBlockEpochNtfn(ctx context.Context) (chan int32, chan error,
		error)

	// GetBlock returns a chain block given its hash.
	GetBlock(context.Context, chainhash.Hash) (*wire.MsgBlock, error)

	// GetBlockByHeight returns a chain block given its height.
	GetBlockByHeight(ctx context.Context,
		blockHeight int64) (*wire.MsgBlock, error)

	// GetBlockHash returns the hash of the block in the best
	// blockchain at the given height.
	GetBlockHash(context.Context, int64) (chainhash.Hash, error)

	// VerifyBlock returns an error if a block (with given header and
	// height) is not present on-chain. It also checks to ensure that
	// block height corresponds to the given block header.
	VerifyBlock(ctx context.Context, header wire.BlockHeader,
		height uint32) error

	// CurrentHeight return the current height of the main chain.
	CurrentHeight(context.Context) (uint32, error)

	// GetBlockTimestamp returns the timestamp of the block at the
	// given height.
	GetBlockTimestamp(context.Context, uint32) (int64, error)

	// GetBlockHeaderByHeight returns a block header given the block
	// height.
	GetBlockHeaderByHeight(ctx context.Context,
		blockHeight int64) (*wire.BlockHeader, error)

	// PublishTransaction attempts to publish a new transaction to
	// the network.
	PublishTransaction(context.Context, *wire.MsgTx, string) error

	// EstimateFee returns a fee estimate for the confirmation
	// target.
	EstimateFee(ctx context.Context,
		confTarget uint32) (chainfee.SatPerKWeight, error)
}

// GenHeaderVerifier returns a proof header verifier backed by the
// given chain bridge.
func GenHeaderVerifier(ctx context.Context,
	chainBridge ChainBridge) func(wire.BlockHeader, uint32) error {

	return func(header wire.BlockHeader, height uint32) error {
		return chainBridge.VerifyBlock(ctx, header, height)
	}
}
