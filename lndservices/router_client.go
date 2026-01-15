package lndservices

import (
	"context"

	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/rfq"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/routerrpc"
	"github.com/lightningnetwork/lnd/lnwire"
)

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

// FetchBaseAlias finds the base channel ID for a given alias.
func (l *LndRouterClient) FetchBaseAlias(ctx context.Context,
	alias lnwire.ShortChannelID) (lnwire.ShortChannelID, error) {

	return l.lnd.Router.XFindBaseLocalChanAlias(ctx, alias)
}

// SubscribeHtlcEvents subscribes to a stream of events related to
// HTLC updates.
func (l *LndRouterClient) SubscribeHtlcEvents(
	ctx context.Context) (<-chan *routerrpc.HtlcEvent,
	<-chan error, error) {

	return l.lnd.Router.SubscribeHtlcEvents(ctx)
}

// LookupHtlcResolution retrieves the final resolution for an HTLC.
func (l *LndRouterClient) LookupHtlcResolution(ctx context.Context,
	chanID uint64, htlcID uint64) (*lnrpc.LookupHtlcResolutionResponse,
	error) {

	rpcCtx, timeout, client := l.lnd.Client.RawClientWithMacAuth(ctx)
	rpcCtx, cancel := context.WithTimeout(rpcCtx, timeout)
	defer cancel()

	return client.LookupHtlcResolution(rpcCtx,
		&lnrpc.LookupHtlcResolutionRequest{
			ChanId:    chanID,
			HtlcIndex: htlcID,
		},
	)
}

// Ensure LndRouterClient implements the rfq.HtlcInterceptor interface.
var _ rfq.HtlcInterceptor = (*LndRouterClient)(nil)
var _ rfq.ScidAliasManager = (*LndRouterClient)(nil)
var _ rfq.HtlcSubscriber = (*LndRouterClient)(nil)
