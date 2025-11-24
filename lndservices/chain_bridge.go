package lndservices

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/neutrino/cache/lru"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
)

const (
	// maxNumBlocksInCache is the maximum number of blocks we'll cache
	// timestamps for. With 400k blocks we should only take up approximately
	// 3200kB of memory (4 bytes for the block height and 4 bytes for the
	// timestamp, not including any map/cache overhead).
	maxNumBlocksInCache = 400_000

	// medianTimeBlocks is the number of previous blocks which should be
	// used to calculate the median time used to validate block timestamps.
	medianTimeBlocks = 11
)

var (
	// errTxNotfound is an error that is returned when a transaction
	// couldn't be found in the proof file.
	errTxNotFound = fmt.Errorf("transaction not found in proof file")
)

// cacheableTimestamp is a wrapper around an uint32 that can be used as a value
// in an LRU cache.
type cacheableTimestamp uint32

// Size returns the size of the cacheable timestamp. Since we scale the cache by
// the number of items and not the total memory size, we can simply return 1
// here to count each timestamp as 1 item.
func (c cacheableTimestamp) Size() (uint64, error) {
	return 1, nil
}

// LndRpcChainBridge is an implementation of the tapgarden.ChainBridge
// interface backed by an active remote lnd node.
type LndRpcChainBridge struct {
	lnd *lndclient.LndServices

	blockTimestampCache *lru.Cache[uint32, cacheableTimestamp]
	retryConfig         fn.RetryConfig

	assetStore *tapdb.AssetStore
}

// NewLndRpcChainBridge creates a new chain bridge from an active lnd services
// client.
func NewLndRpcChainBridge(lnd *lndclient.LndServices,
	assetStore *tapdb.AssetStore) *LndRpcChainBridge {

	return &LndRpcChainBridge{
		lnd: lnd,
		blockTimestampCache: lru.NewCache[uint32, cacheableTimestamp](
			maxNumBlocksInCache,
		),
		retryConfig: fn.DefaultRetryConfig(),
		assetStore:  assetStore,
	}
}

// RegisterConfirmationsNtfn registers an intent to be notified once
// txid reaches numConfs confirmations.
func (l *LndRpcChainBridge) RegisterConfirmationsNtfn(ctx context.Context,
	txid *chainhash.Hash, pkScript []byte, numConfs, heightHint uint32,
	includeBlock bool,
	reOrgChan chan struct{}) (*chainntnfs.ConfirmationEvent, chan error,
	error) {

	opts := []lndclient.NotifierOption{
		lndclient.WithReOrgChan(reOrgChan),
	}
	if includeBlock {
		opts = append(opts, lndclient.WithIncludeBlock())
	}

	ctx, cancel := context.WithCancel(ctx) // nolint:govet
	confChan, errChan, err := l.lnd.ChainNotifier.RegisterConfirmationsNtfn(
		ctx, txid, pkScript, int32(numConfs), int32(heightHint),
		opts...,
	)
	if err != nil {
		cancel()

		return nil, nil, fmt.Errorf("unable to register for conf: %w",
			err)
	}

	return &chainntnfs.ConfirmationEvent{
		Confirmed: confChan,
		Cancel:    cancel,
	}, errChan, nil
}

// RegisterBlockEpochNtfn registers an intent to be notified of each new block
// connected to the main chain.
func (l *LndRpcChainBridge) RegisterBlockEpochNtfn(
	ctx context.Context) (chan int32, chan error, error) {

	return l.lnd.ChainNotifier.RegisterBlockEpochNtfn(ctx)
}

// GetBlock returns a chain block given its hash.
func (l *LndRpcChainBridge) GetBlock(ctx context.Context,
	hash chainhash.Hash) (*wire.MsgBlock, error) {

	return fn.RetryFuncN(
		ctx, l.retryConfig, func() (*wire.MsgBlock, error) {
			block, err := l.lnd.ChainKit.GetBlock(ctx, hash)
			if err != nil {
				return nil, fmt.Errorf(
					"unable to retrieve block (hash=%s): "+
						"%w", hash.String(), err,
				)
			}
			return block, nil
		},
	)
}

// GetBlockByHeight returns a chain block given the block height.
func (l *LndRpcChainBridge) GetBlockByHeight(ctx context.Context,
	blockHeight int64) (*wire.MsgBlock, error) {

	// First, we need to resolve the block hash at the given height.
	blockHash, err := fn.RetryFuncN(
		ctx, l.retryConfig, func() (chainhash.Hash, error) {
			var zero chainhash.Hash

			blockHash, err := l.lnd.ChainKit.GetBlockHash(
				ctx, blockHeight,
			)
			if err != nil {
				return zero, fmt.Errorf(
					"unable to retrieve block hash: %w",
					err,
				)
			}

			return blockHash, nil
		},
	)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve block hash: %w", err)
	}

	// Now that we have the block hash, we can fetch the block.
	return l.GetBlock(ctx, blockHash)
}

// GetBlockHeader returns a block header given its hash.
func (l *LndRpcChainBridge) GetBlockHeader(ctx context.Context,
	hash chainhash.Hash) (*wire.BlockHeader, error) {

	return fn.RetryFuncN(
		ctx, l.retryConfig, func() (*wire.BlockHeader, error) {
			header, err := l.lnd.ChainKit.GetBlockHeader(ctx, hash)
			if err != nil {
				return nil, fmt.Errorf(
					"unable to retrieve block "+
						"header: %w", err,
				)
			}
			return header, nil
		},
	)
}

// GetBlockHeaderByHeight returns a block header given the block height.
func (l *LndRpcChainBridge) GetBlockHeaderByHeight(ctx context.Context,
	blockHeight int64) (*wire.BlockHeader, error) {

	// First, we need to resolve the block hash at the given height.
	blockHash, err := fn.RetryFuncN(
		ctx, l.retryConfig, func() (chainhash.Hash, error) {
			var zero chainhash.Hash

			blockHash, err := l.lnd.ChainKit.GetBlockHash(
				ctx, blockHeight,
			)
			if err != nil {
				return zero, fmt.Errorf(
					"unable to retrieve block hash: %w",
					err,
				)
			}

			return blockHash, nil
		},
	)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve block hash: %w", err)
	}

	// Now that we have the block hash, we can fetch the block header.
	return fn.RetryFuncN(
		ctx, l.retryConfig, func() (*wire.BlockHeader, error) {
			header, err := l.lnd.ChainKit.GetBlockHeader(
				ctx, blockHash,
			)
			if err != nil {
				return nil, fmt.Errorf(
					"unable to retrieve block header: %w",
					err,
				)
			}

			return header, nil
		},
	)
}

// GetBlockHash returns the hash of the block in the best blockchain at the
// given height.
func (l *LndRpcChainBridge) GetBlockHash(ctx context.Context,
	blockHeight int64) (chainhash.Hash, error) {

	return fn.RetryFuncN(
		ctx, l.retryConfig, func() (chainhash.Hash, error) {
			blockHash, err := l.lnd.ChainKit.GetBlockHash(
				ctx, blockHeight,
			)
			if err != nil {
				return chainhash.Hash{}, fmt.Errorf(
					"unable to retrieve block hash: %w",
					err,
				)
			}
			return blockHash, nil
		},
	)
}

// VerifyBlock returns an error if a block (with given header and height) is not
// present on-chain. It also checks to ensure that block height corresponds to
// the given block header.
func (l *LndRpcChainBridge) VerifyBlock(ctx context.Context,
	header wire.BlockHeader, height uint32) error {

	// TODO(ffranr): Once we've released 0.3.0, every proof should have an
	// assigned height. At that point, we should return an error for proofs
	// with unset (zero) block heights.
	if height == 0 {
		_, err := l.GetBlock(ctx, header.BlockHash())
		return err
	}

	// Ensure that the block hash matches the hash of the block
	// found at the given height.
	hash, err := l.GetBlockHash(ctx, int64(height))
	if err != nil {
		return err
	}

	expectedHash := header.BlockHash()
	if hash != expectedHash {
		return fmt.Errorf("block hash and block height "+
			"mismatch; (height: %d, hashAtHeight: %s, "+
			"expectedHash: %s)", height, hash, expectedHash)
	}

	// Ensure that the block header corresponds to a block on-chain. Fetch
	// only the corresponding block header and not the entire block if
	// supported.
	_, err = l.GetBlockHeader(ctx, header.BlockHash())
	return err
}

// CurrentHeight return the current height of the main chain.
func (l *LndRpcChainBridge) CurrentHeight(ctx context.Context) (uint32, error) {
	return fn.RetryFuncN(
		ctx, l.retryConfig, func() (uint32, error) {
			_, bestHeight, err := l.lnd.ChainKit.GetBestBlock(ctx)
			if err != nil {
				return 0, fmt.Errorf(
					"unable to grab block height: %w", err,
				)
			}
			return uint32(bestHeight), nil
		},
	)
}

// GetBlockTimestamp returns the timestamp of the block at the given height.
func (l *LndRpcChainBridge) GetBlockTimestamp(ctx context.Context,
	height uint32) int64 {

	// Shortcut any lookup in case we don't have a valid height in the first
	// place.
	if height == 0 {
		return 0
	}

	cacheTS, err := l.blockTimestampCache.Get(height)
	if err == nil {
		return int64(cacheTS)
	}

	hash, err := fn.RetryFuncN(
		ctx, l.retryConfig, func() (chainhash.Hash, error) {
			return l.lnd.ChainKit.GetBlockHash(ctx, int64(height))
		},
	)
	if err != nil {
		return 0
	}

	// Get block header.
	header, err := l.GetBlockHeader(ctx, hash)
	if err != nil {
		return 0
	}

	ts := uint32(header.Timestamp.Unix())
	_, _ = l.blockTimestampCache.Put(height, cacheableTimestamp(ts))

	return int64(ts)
}

// PublishTransaction attempts to publish a new transaction to the
// network.
func (l *LndRpcChainBridge) PublishTransaction(ctx context.Context,
	tx *wire.MsgTx, label string) error {

	_, err := fn.RetryFuncN(
		ctx, l.retryConfig, func() (struct{}, error) {
			return struct{}{}, l.lnd.WalletKit.PublishTransaction(
				ctx, tx, label,
			)
		},
	)
	return err
}

// EstimateFee returns a fee estimate for the confirmation target.
func (l *LndRpcChainBridge) EstimateFee(ctx context.Context,
	confTarget uint32) (chainfee.SatPerKWeight, error) {

	return fn.RetryFuncN(
		ctx, l.retryConfig, func() (chainfee.SatPerKWeight, error) {
			return l.lnd.WalletKit.EstimateFeeRate(
				ctx, int32(confTarget),
			)
		},
	)
}

// GenFileChainLookup generates a chain lookup interface for the given
// proof file that can be used to validate proofs.
func (l *LndRpcChainBridge) GenFileChainLookup(
	f *proof.File) asset.ChainLookup {

	return NewProofChainLookup(l, l.assetStore, f)
}

// GenProofChainLookup generates a chain lookup interface for the given
// single proof that can be used to validate proofs.
func (l *LndRpcChainBridge) GenProofChainLookup(
	p *proof.Proof) (asset.ChainLookup, error) {

	f, err := proof.NewFile(proof.V0, *p)
	if err != nil {
		return nil, err
	}

	return NewProofChainLookup(l, l.assetStore, f), nil
}

// A compile time assertion to ensure LndRpcChainBridge meets the
// tapgarden.ChainBridge interface.
var _ tapgarden.ChainBridge = (*LndRpcChainBridge)(nil)

// ProofChainLookup is an implementation of the asset.ChainLookup interface
// that uses a proof file to look up block height information of previous inputs
// while validating proofs.
type ProofChainLookup struct {
	chainBridge tapgarden.ChainBridge

	assetStore *tapdb.AssetStore

	proofFile *proof.File
}

// NewProofChainLookup creates a new ProofChainLookup instance.
func NewProofChainLookup(chainBridge tapgarden.ChainBridge,
	assetStore *tapdb.AssetStore, proofFile *proof.File) *ProofChainLookup {

	return &ProofChainLookup{
		chainBridge: chainBridge,
		assetStore:  assetStore,
		proofFile:   proofFile,
	}
}

// CurrentHeight returns the current height of the main chain.
func (l *ProofChainLookup) CurrentHeight(ctx context.Context) (uint32, error) {
	return l.chainBridge.CurrentHeight(ctx)
}

// TxBlockHeight returns the block height that the given transaction was
// included in.
func (l *ProofChainLookup) TxBlockHeight(ctx context.Context,
	txid chainhash.Hash) (uint32, error) {

	// If we don't have a proof available as context, we can only look up
	// the transaction in the database. Querying it on-chain would cause a
	// re-scan which might be very time costly for light clients.
	if l.proofFile == nil || l.proofFile.NumProofs() == 0 {
		return l.assetStore.TxHeight(ctx, txid)
	}

	// Let's walk back the proof chain and try to find the transaction.
	height, err := findTxHeightInProofFile(l.proofFile, txid)
	switch {
	case errors.Is(err, errTxNotFound):
		// Our last ditch attempt is to look up the transaction in the
		// database. But we might not have it there if the proof is for
		// a transaction that happened before the asset reached our
		// node.
		return l.assetStore.TxHeight(ctx, txid)

	case err != nil:
		return 0, fmt.Errorf("error fetching proof from context file: "+
			"%w", err)
	}

	return height, nil
}

// findTxHeightInProofFile is a helper function that recursively searches for
// the block height of a transaction in a proof file.
func findTxHeightInProofFile(f *proof.File, txid chainhash.Hash) (uint32,
	error) {

	for i := f.NumProofs() - 1; i >= 0; i-- {
		p, err := f.ProofAt(uint32(i))
		if err != nil {
			return 0, fmt.Errorf("error fetching proof from "+
				"file: %w", err)
		}

		if p.AnchorTx.TxHash() == txid {
			return p.BlockHeight, nil
		}

		for idx := range p.AdditionalInputs {
			additionalInput := p.AdditionalInputs[idx]
			height, err := findTxHeightInProofFile(
				&additionalInput, txid,
			)
			switch {
			case errors.Is(err, errTxNotFound):
				continue

			case err != nil:
				return 0, fmt.Errorf("error fetching proof "+
					"from additional input file: %w", err)
			}

			return height, nil
		}
	}

	// If we arrive here, we couldn't find the transaction in the proof
	// file.
	return 0, errTxNotFound
}

// MeanBlockTimestamp returns the timestamp of the block at the given height as
// a Unix timestamp in seconds, taking into account the mean time elapsed over
// the previous 11 blocks.
func (l *ProofChainLookup) MeanBlockTimestamp(ctx context.Context,
	blockHeight uint32) (time.Time, error) {

	// Create a slice of the previous few block timestamps used to calculate
	// the median per the number defined by the constant medianTimeBlocks.
	//
	// NOTE: The code below is an adaptation of the code in btcd's
	// blockchain.CalcPastMedianTime function.
	timestamps := make([]int64, medianTimeBlocks)
	numNodes := 0
	for i := uint32(0); i < medianTimeBlocks; i++ {
		// If we have reached the beginning of the blockchain, we can't
		// go back any further. This also prevents an underflow in the
		// next step.
		if i > blockHeight {
			break
		}

		unixTs := l.chainBridge.GetBlockTimestamp(ctx, blockHeight-i)
		if unixTs == 0 {
			return time.Time{}, fmt.Errorf("couldn't find "+
				"timestamp for block height %d", blockHeight)
		}

		timestamps[i] = unixTs
		numNodes++
	}

	// Prune the slice to the actual number of available timestamps which
	// will be fewer than desired near the beginning of the blockchain and
	// sort them.
	timestamps = timestamps[:numNodes]
	sort.Slice(timestamps, func(i, j int) bool {
		return timestamps[i] < timestamps[j]
	})

	// NOTE: The consensus rules incorrectly calculate the median for even
	// numbers of blocks.  A true median averages the middle two elements
	// for a set with an even number of elements in it.   Since the constant
	// for the previous number of blocks to be used is odd, this is only an
	// issue for a few blocks near the beginning of the chain.  I suspect
	// this is an optimization even though the result is slightly wrong for
	// a few of the first blocks since after the first few blocks, there
	// will always be an odd number of blocks in the set per the constant.
	//
	// This code follows suit to ensure the same rules are used, however, be
	// aware that should the medianTimeBlocks constant ever be changed to an
	// even number, this code will be wrong.
	medianTimestamp := timestamps[numNodes/2]
	return time.Unix(medianTimestamp, 0), nil
}

var _ asset.ChainLookup = (*ProofChainLookup)(nil)
