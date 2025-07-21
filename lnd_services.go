package taprootassets

import (
	"context"

	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/rfq"
	"github.com/lightninglabs/taproot-assets/tapchannel"
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
