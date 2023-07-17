package taprootassets

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
)

// LndRpcChainBridge is an implementation of the tapgarden.ChainBridge
// interface backed by an active remote lnd node.
type LndRpcChainBridge struct {
	lnd *lndclient.LndServices
}

// NewLndRpcChainBridge creates a new chain bridge from an active lnd services
// client.
func NewLndRpcChainBridge(lnd *lndclient.LndServices) *LndRpcChainBridge {
	return &LndRpcChainBridge{
		lnd: lnd,
	}
}

// RegisterConfirmationsNtfn registers an intent to be notified once
// txid reaches numConfs confirmations.
func (l *LndRpcChainBridge) RegisterConfirmationsNtfn(ctx context.Context,
	txid *chainhash.Hash, pkScript []byte, numConfs, heightHint uint32,
	includeBlock bool) (*chainntnfs.ConfirmationEvent, chan error, error) {

	var opts []lndclient.NotifierOption
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

// GetBlock returns a chain block given its hash.
func (l *LndRpcChainBridge) GetBlock(ctx context.Context,
	hash chainhash.Hash) (*wire.MsgBlock, error) {

	block, err := l.lnd.ChainKit.GetBlock(ctx, hash)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve block: %w", err)
	}

	return block, nil
}

// GetBlockHash returns the hash of the block in the best blockchain at the
// given height.
func (l *LndRpcChainBridge) GetBlockHash(ctx context.Context,
	blockHeight int64) (chainhash.Hash, error) {

	blockHash, err := l.lnd.ChainKit.GetBlockHash(ctx, blockHeight)
	if err != nil {
		return chainhash.Hash{}, fmt.Errorf("unable to retrieve "+
			"block hash: %w", err)
	}

	return blockHash, nil
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
			"mismatch; (height: %x, hashAtHeight: %s, "+
			"expectedHash: %s)", height, hash, expectedHash)
	}

	// Ensure that the block header corresponds to a block on-chain.
	_, err = l.GetBlock(ctx, header.BlockHash())
	return err
}

// CurrentHeight return the current height of the main chain.
func (l *LndRpcChainBridge) CurrentHeight(ctx context.Context) (uint32, error) {
	info, err := l.lnd.Client.GetInfo(ctx)
	if err != nil {
		return 0, fmt.Errorf("unable to grab block height: %w", err)
	}

	return info.BlockHeight, nil
}

// PublishTransaction attempts to publish a new transaction to the
// network.
func (l *LndRpcChainBridge) PublishTransaction(ctx context.Context,
	tx *wire.MsgTx) error {

	label := "tapd-asset-minting"
	return l.lnd.WalletKit.PublishTransaction(ctx, tx, label)
}

// EstimateFee returns a fee estimate for the confirmation target.
func (l *LndRpcChainBridge) EstimateFee(ctx context.Context,
	confTarget uint32) (chainfee.SatPerKWeight, error) {

	return l.lnd.WalletKit.EstimateFeeRate(ctx, int32(confTarget))
}

// A compile time assertion to ensure LndRpcChainBridge meets the
// tapgarden.ChainBridge interface.
var _ tapgarden.ChainBridge = (*LndRpcChainBridge)(nil)
