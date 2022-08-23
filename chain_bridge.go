package taro

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taro/tarogarden"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
)

// LndRpcChainBridge is an implementation of the tarogarden.ChainBridge
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
	txid *chainhash.Hash, pkScript []byte,
	numConfs, heightHint uint32,
	includeBlock bool) (*chainntnfs.ConfirmationEvent, chan error, error) {

	var opts []lndclient.NotifierOption
	if includeBlock {
		opts = append(opts, lndclient.WithIncludeBlock())
	}

	ctx, cancel := context.WithCancel(ctx)
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

	label := "tarod-asset-minting"
	return l.lnd.WalletKit.PublishTransaction(ctx, tx, label)
}

// EstimateFee returns a fee estimate for the confirmation target.
func (l *LndRpcChainBridge) EstimateFee(ctx context.Context,
	confTarget uint32) (chainfee.SatPerKWeight, error) {

	return l.lnd.WalletKit.EstimateFeeRate(ctx, int32(confTarget))
}

// A compile time assertion to ensure LndRpcChainBridge meets the
// tarogarden.ChainBridge interface.
var _ tarogarden.ChainBridge = (*LndRpcChainBridge)(nil)
