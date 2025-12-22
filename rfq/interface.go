package rfq

import (
	"context"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightningnetwork/lnd/routing/route"
)

// RfqPolicyType denotes the type of a persisted RFQ policy.
type RfqPolicyType string

const (
	// RfqPolicyTypeAssetSale identifies an asset sale policy.
	RfqPolicyTypeAssetSale RfqPolicyType = "RFQ_POLICY_TYPE_SALE"

	// RfqPolicyTypeAssetPurchase identifies an asset purchase policy.
	RfqPolicyTypeAssetPurchase RfqPolicyType = "RFQ_POLICY_TYPE_PURCHASE"
)

// String converts the policy type to its string representation.
func (t RfqPolicyType) String() string {
	return string(t)
}

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

// ForwardInput contains the data needed to log a forward event.
type ForwardInput struct {
	// SettledAt is the time when the forward settled.
	SettledAt time.Time

	// RfqID is the RFQ session identifier for this forward.
	RfqID rfqmsg.ID

	// ChanIDIn is the short channel ID of the incoming channel.
	ChanIDIn uint64

	// ChanIDOut is the short channel ID of the outgoing channel.
	ChanIDOut uint64

	// HtlcID is the HTLC ID on the incoming channel.
	HtlcID uint64

	// AssetAmt is the asset amount involved in this swap.
	AssetAmt uint64
}

// QueryForwardsParams contains the parameters for querying forward records.
type QueryForwardsParams struct {
	// MinTimestamp filters forwards to those settled at or after this time.
	// Zero value means no lower bound.
	MinTimestamp time.Time

	// MaxTimestamp filters forwards to those settled at or before this
	// time. Zero value means no upper bound.
	MaxTimestamp time.Time

	// Peer filters forwards to those with this counterparty.
	// Nil means no filter.
	Peer *route.Vertex

	// AssetID filters forwards to those involving this asset.
	// Nil means no filter.
	AssetID *asset.ID

	// AssetGroupKey filters forwards to those involving this asset group.
	// Nil means no filter.
	AssetGroupKey *btcec.PublicKey

	// Limit is the maximum number of records to return.
	Limit int32

	// Offset is the number of records to skip (for pagination).
	Offset int32
}

// RfqForwardRecord is a complete forward record including policy data.
type RfqForwardRecord struct {
	// ID is the database ID.
	ID int64

	// SettledAt is the time when the forward settled.
	SettledAt time.Time

	// RfqID is the RFQ session identifier.
	RfqID rfqmsg.ID

	// ChanIDIn is the short channel ID of the incoming channel.
	ChanIDIn uint64

	// ChanIDOut is the short channel ID of the outgoing channel.
	ChanIDOut uint64

	// HtlcID is the HTLC ID on the incoming channel.
	HtlcID uint64

	// AssetAmt is the asset amount involved in this swap.
	AssetAmt uint64

	// PolicyType indicates whether this was a sale or purchase from the
	// edge node's perspective.
	PolicyType RfqPolicyType

	// Peer is the counterparty peer's public key.
	Peer route.Vertex

	// AssetID is the specific asset ID (if set).
	AssetID *asset.ID

	// AssetGroupKey is the asset group key (if set).
	AssetGroupKey *btcec.PublicKey

	// Rate is the exchange rate used for this forward.
	Rate rfqmath.BigIntFixedPoint
}

// ForwardStore abstracts persistence of RFQ forward events.
type ForwardStore interface {
	// LogForward persists a new forward event to the database.
	LogForward(ctx context.Context, input ForwardInput) (int64, error)

	// QueryForwards retrieves forward records matching the given filters.
	QueryForwards(ctx context.Context,
		params QueryForwardsParams) ([]RfqForwardRecord, error)

	// CountForwards returns the count of forward records matching the
	// filters.
	CountForwards(ctx context.Context, params QueryForwardsParams) (int64,
		error)

	// SumAssetVolume returns the sum of asset amounts for forward records
	// matching the filters. This represents total swap volume in asset
	// units.
	SumAssetVolume(ctx context.Context, params QueryForwardsParams) (uint64,
		error)
}
