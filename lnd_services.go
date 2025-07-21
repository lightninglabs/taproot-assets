package taprootassets

import (
	"context"

	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/tapchannel"
)

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
