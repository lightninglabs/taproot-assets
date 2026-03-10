package rfq

import (
	"context"
	"time"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
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

	// RfqPolicyTypeAssetPeerAcceptedBuy identifies a peer-accepted buy
	// quote that was persisted for historical SCID lookup.
	//nolint:lll
	RfqPolicyTypeAssetPeerAcceptedBuy RfqPolicyType = "RFQ_POLICY_TYPE_PEER_ACCEPTED_BUY"
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

	// FetchAcceptedQuotes fetches all non-expired accepted quotes.
	// Returns sale policies as buy accepts, purchase policies as sell
	// accepts, and peer-accepted buy quotes separately.
	FetchAcceptedQuotes(ctx context.Context) ([]rfqmsg.BuyAccept,
		[]rfqmsg.SellAccept, []rfqmsg.BuyAccept, error)

	// StorePeerAcceptedBuyQuote persists a peer-accepted buy quote for
	// historical SCID-to-peer lookup.
	StorePeerAcceptedBuyQuote(ctx context.Context,
		accept rfqmsg.BuyAccept) error

	// LookUpScid looks up the peer associated with the given SCID from
	// persisted peer-accepted buy quote policies.
	LookUpScid(ctx context.Context, scid uint64) (route.Vertex, error)
}

// ForwardInput contains the data needed to upsert a forward event.
type ForwardInput struct {
	// OpenedAt is the time when the forward was initiated.
	OpenedAt time.Time

	// SettledAt is the time when the forward settled (if any).
	SettledAt fn.Option[time.Time]

	// FailedAt is the time when the forward failed (if any).
	FailedAt fn.Option[time.Time]

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

	// AmtInMsat is the actual amount received on the incoming channel in
	// millisatoshis.
	AmtInMsat uint64

	// AmtOutMsat is the actual amount sent on the outgoing channel in
	// millisatoshis.
	AmtOutMsat uint64
}

// QueryForwardsParams contains the parameters for querying forwarding event
// records.
type QueryForwardsParams struct {
	// MinTimestamp filters forwarding events to those settled at or after
	// this time.
	// None means no lower bound.
	MinTimestamp fn.Option[time.Time]

	// MaxTimestamp filters forwarding events to those settled at or before
	// this
	// time. None means no upper bound.
	MaxTimestamp fn.Option[time.Time]

	// Peer filters forwarding events to those with this counterparty.
	// Nil means no filter.
	Peer *route.Vertex

	// AssetSpecifier filters forwarding events to those involving this
	// asset or
	// asset group. Nil means no filter.
	AssetSpecifier *asset.Specifier

	// Limit is the maximum number of records to return.
	Limit int32

	// Offset is the number of records to skip (for pagination).
	Offset int32
}

// ForwardingEvent is a complete forwarding event record including policy data.
type ForwardingEvent struct {
	// OpenedAt is the time when the forward was initiated.
	OpenedAt time.Time

	// SettledAt is the time when the forward settled (nil if not settled).
	SettledAt *time.Time

	// FailedAt is the time when the forward failed (nil if not failed).
	FailedAt *time.Time

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

	// AmtInMsat is the actual amount received on the incoming channel in
	// millisatoshis.
	AmtInMsat uint64

	// AmtOutMsat is the actual amount sent on the outgoing channel in
	// millisatoshis.
	AmtOutMsat uint64

	// PolicyType indicates whether this was a sale or purchase from the
	// edge node's perspective.
	PolicyType RfqPolicyType

	// Peer is the counterparty peer's public key.
	Peer route.Vertex

	// AssetSpecifier identifies the specific asset or asset group (if set).
	AssetSpecifier asset.Specifier

	// Rate is the exchange rate used for this forward.
	Rate rfqmath.BigIntFixedPoint
}

// ForwardStore abstracts persistence of forwarding events.
type ForwardStore interface {
	// UpsertForward inserts or updates a forwarding event record in the
	// database.
	UpsertForward(ctx context.Context, input ForwardInput) error

	// PendingForwards retrieves forwards that haven't settled or failed.
	PendingForwards(ctx context.Context) ([]ForwardInput, error)

	// QueryForwardsWithCount retrieves forwarding event records matching
	// the given filters along with the total count.
	QueryForwardsWithCount(ctx context.Context,
		params QueryForwardsParams) ([]ForwardingEvent, int64, error)
}
