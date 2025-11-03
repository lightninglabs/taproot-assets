package rfq

import (
	"context"

	"github.com/lightninglabs/taproot-assets/rfqmsg"
)

// PolicyStore abstracts persistence of RFQ policies.
type PolicyStore interface {
	// StoreSalePolicy stores an asset sale policy.
	StoreSalePolicy(ctx context.Context, accept rfqmsg.BuyAccept) error

	// StorePurchasePolicy stores an asset purchase policy.
	StorePurchasePolicy(ctx context.Context, accept rfqmsg.SellAccept) error

	// FetchAcceptedQuotes fetches all accepted buy and sell quotes.
	FetchAcceptedQuotes(ctx context.Context) ([]rfqmsg.BuyAccept,
		[]rfqmsg.SellAccept, error)
}
