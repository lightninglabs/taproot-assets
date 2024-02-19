package taprootassets

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/rfq"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/lnrpc/verrpc"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
)

// LndRpcChainBridge is an implementation of the tapgarden.ChainBridge
// interface backed by an active remote lnd node.
type LndRpcChainBridge struct {
	lnd *lndclient.LndServices

	getBlockHeaderSupported *bool
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

	block, err := l.lnd.ChainKit.GetBlock(ctx, hash)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve block: %w", err)
	}

	return block, nil
}

// GetBlockHeader returns a block header given its hash.
func (l *LndRpcChainBridge) GetBlockHeader(ctx context.Context,
	hash chainhash.Hash) (*wire.BlockHeader, error) {

	header, err := l.lnd.ChainKit.GetBlockHeader(ctx, hash)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve block header: %w",
			err)
	}

	return header, nil
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

// GetBlockHeaderSupported returns true if the chain backend supports the
// `GetBlockHeader` RPC call.
func (l *LndRpcChainBridge) GetBlockHeaderSupported(ctx context.Context) bool {
	// Check if we've already asserted the compatibility of the chain
	// backend.
	if l.getBlockHeaderSupported != nil {
		return *l.getBlockHeaderSupported
	}

	// The ChainKit.GetBlockHeader() RPC call was added in lnd v0.17.1.
	getBlockHeaderMinimalVersion := &verrpc.Version{
		AppMajor: 0,
		AppMinor: 17,
		AppPatch: 1,
	}

	getBlockHeaderUnsupported := lndclient.AssertVersionCompatible(
		l.lnd.Version, getBlockHeaderMinimalVersion,
	)
	getBlockHeaderSupported := getBlockHeaderUnsupported == nil

	l.getBlockHeaderSupported = &getBlockHeaderSupported
	return *l.getBlockHeaderSupported
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
	if l.GetBlockHeaderSupported(ctx) {
		_, err = l.GetBlockHeader(ctx, header.BlockHash())
		return err
	}

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

// LndMsgTransportClient is an LND RPC message transport client.
type LndMsgTransportClient struct {
	lnd *lndclient.LndServices
}

// NewLndMsgTransportClient creates a new message transport RPC client for a
// given LND service.
func NewLndMsgTransportClient(
	lnd *lndclient.LndServices) *LndMsgTransportClient {

	return &LndMsgTransportClient{
		lnd: lnd,
	}
}

// SubscribeCustomMessages creates a subscription to custom messages received
// from our peers.
func (l *LndMsgTransportClient) SubscribeCustomMessages(
	ctx context.Context) (<-chan lndclient.CustomMessage,
	<-chan error, error) {

	return l.lnd.Client.SubscribeCustomMessages(ctx)
}

// SendCustomMessage sends a custom message to a peer.
func (l *LndMsgTransportClient) SendCustomMessage(ctx context.Context,
	msg lndclient.CustomMessage) error {

	return l.lnd.Client.SendCustomMessage(ctx, msg)
}

// Ensure LndMsgTransportClient implements the rfq.PeerMessenger interface.
var _ rfq.PeerMessenger = (*LndMsgTransportClient)(nil)

// LndRouterClient is an LND router RPC client.
type LndRouterClient struct {
	lnd *lndclient.LndServices
}

// NewLndRouterClient creates a new LND router client for a given LND service.
func NewLndRouterClient(lnd *lndclient.LndServices) *LndRouterClient {
	return &LndRouterClient{
		lnd: lnd,
	}
}

// InterceptHtlcs intercepts all incoming HTLCs and calls the given handler
// function with the HTLC details. The handler function can then decide whether
// to accept or reject the HTLC.
func (l *LndRouterClient) InterceptHtlcs(
	ctx context.Context, handler lndclient.HtlcInterceptHandler) error {

	return l.lnd.Router.InterceptHtlcs(ctx, handler)
}

// Ensure LndRouterClient implements the rfq.HtlcInterceptor interface.
var _ rfq.HtlcInterceptor = (*LndRouterClient)(nil)
