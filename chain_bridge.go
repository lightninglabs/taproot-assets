package taprootassets

import (
	"bytes"
	"context"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/neutrino/cache/lru"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/rfq"
	"github.com/lightninglabs/taproot-assets/tapchannel"
	"github.com/lightninglabs/taproot-assets/tapdb"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/funding"
	"github.com/lightningnetwork/lnd/lnrpc/routerrpc"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
)

const (
	// maxNumBlocksInCache is the maximum number of blocks we'll cache
	// timestamps for. With 100k blocks we should only take up approximately
	// 800kB of memory (4 bytes for the block height and 4 bytes for the
	// timestamp, not including any map/cache overhead).
	maxNumBlocksInCache = 100_000
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
		assetStore: assetStore,
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
	_, bestHeight, err := l.lnd.ChainKit.GetBestBlock(ctx)
	if err != nil {
		return 0, fmt.Errorf("unable to grab block height: %w", err)
	}

	return uint32(bestHeight), nil
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

	hash, err := l.lnd.ChainKit.GetBlockHash(ctx, int64(height))
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

	return l.lnd.WalletKit.PublishTransaction(ctx, tx, label)
}

// EstimateFee returns a fee estimate for the confirmation target.
func (l *LndRpcChainBridge) EstimateFee(ctx context.Context,
	confTarget uint32) (chainfee.SatPerKWeight, error) {

	return l.lnd.WalletKit.EstimateFeeRate(ctx, int32(confTarget))
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

// SendMessage sends a message to a remote peer.
func (l *LndMsgTransportClient) SendMessage(ctx context.Context,
	peer btcec.PublicKey, msg lnwire.Message) error {

	var buf bytes.Buffer
	if err := msg.Encode(&buf, 0); err != nil {
		return fmt.Errorf("unable to encode message: %w", err)
	}

	return l.SendCustomMessage(ctx, lndclient.CustomMessage{
		Peer:    route.NewVertex(&peer),
		MsgType: uint32(msg.MsgType()),
		Data:    buf.Bytes(),
	})
}

// ReportError sends a custom message with the error type to a peer.
//
// NOTE: In order for this custom message to be sent over the lnd RPC interface,
// lnd needs to be configured with the `--custom-message=17` flag, which allows
// sending the non-custom error message type.
func (l *LndMsgTransportClient) ReportError(ctx context.Context,
	peer btcec.PublicKey, pid funding.PendingChanID, err error) {

	srvrLog.Errorf("Error in funding flow for pending chan ID %x: %v",
		pid[:], err)

	msg := &lnwire.Error{
		ChanID: pid,
		Data:   []byte(err.Error()),
	}

	sendErr := l.SendMessage(ctx, peer, msg)
	if sendErr != nil {
		srvrLog.Errorf("Error sending error message to peer %x: %v",
			peer.SerializeCompressed(), sendErr)
	}
}

// Ensure LndMsgTransportClient implements the rfq.PeerMessenger,
// tapchannel.PeerMessenger and tapchannel.ErrorReporter interfaces.
var _ rfq.PeerMessenger = (*LndMsgTransportClient)(nil)
var _ tapchannel.PeerMessenger = (*LndMsgTransportClient)(nil)
var _ tapchannel.ErrorReporter = (*LndMsgTransportClient)(nil)

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

// AddLocalAlias adds a database mapping from the passed alias to the passed
// base SCID.
func (l *LndRouterClient) AddLocalAlias(ctx context.Context, alias,
	baseScid lnwire.ShortChannelID) error {

	return l.lnd.Router.XAddLocalChanAlias(ctx, alias, baseScid)
}

// DeleteLocalAlias removes a mapping from the database and the Manager's maps.
func (l *LndRouterClient) DeleteLocalAlias(ctx context.Context, alias,
	baseScid lnwire.ShortChannelID) error {

	return l.lnd.Router.XDeleteLocalChanAlias(ctx, alias, baseScid)
}

// SubscribeHtlcEvents subscribes to a stream of events related to
// HTLC updates.
func (l *LndRouterClient) SubscribeHtlcEvents(
	ctx context.Context) (<-chan *routerrpc.HtlcEvent,
	<-chan error, error) {

	return l.lnd.Router.SubscribeHtlcEvents(ctx)
}

// Ensure LndRouterClient implements the rfq.HtlcInterceptor interface.
var _ rfq.HtlcInterceptor = (*LndRouterClient)(nil)
var _ rfq.ScidAliasManager = (*LndRouterClient)(nil)
var _ rfq.HtlcSubscriber = (*LndRouterClient)(nil)

// LndInvoicesClient is an LND invoices RPC client.
type LndInvoicesClient struct {
	lnd *lndclient.LndServices
}

// NewLndInvoicesClient creates a new LND invoices client for a given LND
// service.
func NewLndInvoicesClient(lnd *lndclient.LndServices) *LndInvoicesClient {
	return &LndInvoicesClient{
		lnd: lnd,
	}
}

// HtlcModifier is a bidirectional streaming RPC that allows a client to
// intercept and modify the HTLCs that attempt to settle the given invoice. The
// server will send HTLCs of invoices to the client and the client can modify
// some aspects of the HTLC in order to pass the invoice acceptance tests.
func (l *LndInvoicesClient) HtlcModifier(ctx context.Context,
	handler lndclient.InvoiceHtlcModifyHandler) error {

	return l.lnd.Invoices.HtlcModifier(ctx, handler)
}

// Ensure LndInvoicesClient implements the tapchannel.InvoiceHtlcModifier
// interface.
var _ tapchannel.InvoiceHtlcModifier = (*LndInvoicesClient)(nil)
