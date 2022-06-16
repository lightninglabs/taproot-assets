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

// NewRpcLndChainBridge creates a new chain bridge from an active lnd services
// client.
func NewLndRpcChainBridge(lnd *lndclient.LndServices) *LndRpcChainBridge {
	return &LndRpcChainBridge{
		lnd: lnd,
	}
}

// RegisterConfirmationsNtfn registers an intent to be notified once
// txid reaches numConfs confirmations.
func (l *LndRpcChainBridge) RegisterConfirmationsNtfn(txid *chainhash.Hash, pkScript []byte,
	numConfs, heightHint uint32) (*chainntnfs.ConfirmationEvent, error) {

	ctx, cancel := context.WithCancel(context.Background())
	confChan, _, err := l.lnd.ChainNotifier.RegisterConfirmationsNtfn(
		ctx, txid, pkScript, int32(numConfs), int32(heightHint),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to register for conf: %w", err)
	}

	return &chainntnfs.ConfirmationEvent{
		Confirmed: confChan,
		Cancel:    cancel,
	}, nil
}

// CurrentHeight return the current height of the main chain.
func (l *LndRpcChainBridge) CurrentHeight() (uint32, error) {
	info, err := l.lnd.Client.GetInfo(context.Background())
	if err != nil {
		return 0, fmt.Errorf("unable to grab block height: %w", err)
	}

	return info.BlockHeight, nil
}

// PublishTransaction attempts to publish a new transaction to the
// network.
func (l *LndRpcChainBridge) PublishTransaction(tx *wire.MsgTx) error {
	label := "tarod-asset-minting"
	return l.lnd.WalletKit.PublishTransaction(
		context.Background(), tx, label,
	)
}

// EstimateFee returns a fee estimate for the confirmation target.
func (l *LndRpcChainBridge) EstimateFee(confTarget uint32) (chainfee.SatPerKWeight, error) {
	return l.lnd.WalletKit.EstimateFeeRate(
		context.Background(), int32(confTarget),
	)
}

// A compile time assertion to ensure LndRpcChainBridge meets the
// tarogarden.ChainBridge interface.
var _ tarogarden.ChainBridge = (*LndRpcChainBridge)(nil)
