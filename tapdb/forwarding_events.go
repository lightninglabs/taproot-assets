package tapdb

import (
	"context"
	"database/sql"
	"fmt"
	"math/big"
	"time"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/rfq"
	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightningnetwork/lnd/lnwire"
)

// ForwardingEvent represents a single asset forwarding event that occurred
// when an HTLC was accepted and forwarded.
type ForwardingEvent struct {
	// Timestamp is the time when the forwarding event occurred.
	Timestamp time.Time

	// IncomingHTLCID is the ID of the incoming HTLC.
	IncomingHTLCID uint64

	// OutgoingHTLCID is the ID of the outgoing HTLC.
	OutgoingHTLCID uint64

	// AssetID is the ID of the asset that was forwarded.
	AssetID asset.ID

	// AmountInMsat is the incoming amount in millisatoshis.
	AmountInMsat lnwire.MilliSatoshi

	// AmountOutMsat is the outgoing amount in millisatoshis.
	AmountOutMsat lnwire.MilliSatoshi

	// Rate is the exchange rate used for the forward.
	Rate rfqmath.BigIntFixedPoint

	// FeeMsat is the fee earned in millisatoshis.
	FeeMsat lnwire.MilliSatoshi

	// IncomingChannelID is the incoming channel ID.
	IncomingChannelID uint64

	// OutgoingChannelID is the outgoing channel ID.
	OutgoingChannelID uint64
}

// ForwardingEventStore is an interface that defines the methods for storing
// and querying forwarding events.
type ForwardingEventStore interface {
	// LogForwardingEvent logs a forwarding event to the database.
	LogForwardingEvent(ctx context.Context, event *ForwardingEvent) error

	// QueryForwardingEvents queries forwarding events from the database
	// with optional filters.
	QueryForwardingEvents(ctx context.Context,
		params QueryForwardingEventsParams) ([]*ForwardingEvent, error)
}

// RfqForwardingEventStore implements the ForwardingEventStore interface using
// the sqlc-generated queries.
type RfqForwardingEventStore struct {
	db *TransactionExecutor[sqlc.Querier]
}

// NewRfqForwardingEventStore creates a new RfqForwardingEventStore.
func NewRfqForwardingEventStore(
	db *TransactionExecutor[sqlc.Querier]) *RfqForwardingEventStore {

	return &RfqForwardingEventStore{
		db: db,
	}
}

// LogForwardingEvent logs a forwarding event to the database.
func (r *RfqForwardingEventStore) LogForwardingEvent(ctx context.Context,
	event *ForwardingEvent) error {

	writeTxOpts := WriteTxOption()
	return r.db.ExecTx(ctx, writeTxOpts, func(db sqlc.Querier) error {
		// Encode the rate coefficient as bytes.
		rateCoefficient := event.Rate.Coefficient.Bytes()

		params := sqlc.InsertForwardingEventParams{
			Timestamp:         event.Timestamp.UTC(),
			IncomingHtlcID:    int64(event.IncomingHTLCID),
			OutgoingHtlcID:    int64(event.OutgoingHTLCID),
			AssetID:           event.AssetID[:],
			AmountInMsat:      int64(event.AmountInMsat),
			AmountOutMsat:     int64(event.AmountOutMsat),
			RateCoefficient:   rateCoefficient,
			RateScale:         int32(event.Rate.Scale),
			FeeMsat:           int64(event.FeeMsat),
			IncomingChannelID: int64(event.IncomingChannelID),
			OutgoingChannelID: int64(event.OutgoingChannelID),
		}
		return db.InsertForwardingEvent(ctx, params)
	})
}

// QueryForwardingEventsParams holds the query parameters for forwarding events.
type QueryForwardingEventsParams struct {
	StartTime time.Time
	EndTime   time.Time
	AssetID   *asset.ID
	Offset    int32
	Limit     int32
	SortDesc  bool
}

// QueryForwardingEvents queries forwarding events from the database with
// optional filters.
func (r *RfqForwardingEventStore) QueryForwardingEvents(ctx context.Context,
	params QueryForwardingEventsParams) ([]*ForwardingEvent, error) {

	var events []*ForwardingEvent

	readTxOpts := ReadTxOption()
	err := r.db.ExecTx(ctx, readTxOpts, func(db sqlc.Querier) error {
		// Prepare query parameters.
		var assetIDBytes []byte
		if params.AssetID != nil {
			assetIDBytes = params.AssetID[:]
		}

		// Set sort direction: 0 = ASC, 1 = DESC
		sortDirection := int32(0)
		if params.SortDesc {
			sortDirection = 1
		}

		queryParams := sqlc.QueryForwardingEventsParams{
			NumOffset: params.Offset,
			NumLimit:  params.Limit,
			SortDirection: sql.NullInt32{
				Int32: sortDirection,
				Valid: true,
			},
		}

		// Only set start/end time if they're not zero values.
		if !params.StartTime.IsZero() {
			queryParams.StartTime = sql.NullTime{
				Time:  params.StartTime.UTC(),
				Valid: true,
			}
		}
		if !params.EndTime.IsZero() {
			queryParams.EndTime = sql.NullTime{
				Time:  params.EndTime.UTC(),
				Valid: true,
			}
		}
		if assetIDBytes != nil {
			queryParams.AssetID = assetIDBytes
		}

		dbEvents, err := db.QueryForwardingEvents(ctx, queryParams)
		if err != nil {
			return fmt.Errorf("unable to query forwarding events: "+
				"%w", err)
		}

		// Convert database rows to ForwardingEvent structs.
		events = make([]*ForwardingEvent, len(dbEvents))
		for i, dbEvent := range dbEvents {
			var assetID asset.ID
			copy(assetID[:], dbEvent.AssetID)

			// Reconstruct the rate from coefficient and scale.
			coefficient := new(big.Int).SetBytes(
				dbEvent.RateCoefficient,
			)
			rate := rfqmath.FixedPoint[rfqmath.BigInt]{
				Coefficient: rfqmath.NewBigInt(coefficient),
				Scale:       uint8(dbEvent.RateScale),
			}

			events[i] = &ForwardingEvent{
				Timestamp:      dbEvent.Timestamp.UTC(),
				IncomingHTLCID: uint64(dbEvent.IncomingHtlcID),
				OutgoingHTLCID: uint64(dbEvent.OutgoingHtlcID),
				AssetID:        assetID,
				AmountInMsat: lnwire.MilliSatoshi(
					dbEvent.AmountInMsat,
				),
				AmountOutMsat: lnwire.MilliSatoshi(
					dbEvent.AmountOutMsat,
				),
				Rate: rate,
				FeeMsat: lnwire.MilliSatoshi(
					dbEvent.FeeMsat,
				),
				IncomingChannelID: uint64(
					dbEvent.IncomingChannelID,
				),
				OutgoingChannelID: uint64(
					dbEvent.OutgoingChannelID,
				),
			}
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return events, nil
}

// ExtractForwardingEventFromAcceptHtlc extracts a ForwardingEvent from an
// AcceptHtlcEvent.
func ExtractForwardingEventFromAcceptHtlc(
	event *rfq.AcceptHtlcEvent) (*ForwardingEvent, error) {

	// Extract asset ID from the policy.
	var assetID asset.ID
	switch policy := event.Policy.(type) {
	case *rfq.AssetSalePolicy:
		assetID = extractAssetIDFromSpecifier(policy.AssetSpecifier)
	case *rfq.AssetPurchasePolicy:
		assetID = extractAssetIDFromSpecifier(policy.AssetSpecifier)
	case *rfq.AssetForwardPolicy:
		// For forward policies, we need to get the asset ID from one
		// of the policies (they should be the same asset).
		return nil, fmt.Errorf("forward policy not yet supported")
	default:
		return nil, fmt.Errorf("unknown policy type: %T", policy)
	}

	// Extract rate from the policy.
	var rate rfqmath.BigIntFixedPoint
	switch policy := event.Policy.(type) {
	case *rfq.AssetSalePolicy:
		rate = policy.AskAssetRate
	case *rfq.AssetPurchasePolicy:
		rate = policy.BidAssetRate
	default:
		return nil, fmt.Errorf("unsupported policy type for rate "+
			"extraction: %T", policy)
	}

	// Calculate the fee.
	feeMsat := event.Htlc.AmountInMsat - event.Htlc.AmountOutMsat

	return &ForwardingEvent{
		Timestamp:      event.Timestamp(),
		IncomingHTLCID: event.Htlc.IncomingCircuitKey.HtlcID,
		// At interception time, we don't have the outgoing HTLC ID
		// yet, so we use the incoming HTLC ID as a proxy.
		OutgoingHTLCID: event.Htlc.IncomingCircuitKey.HtlcID,
		AssetID:        assetID,
		AmountInMsat:   event.Htlc.AmountInMsat,
		AmountOutMsat:  event.Htlc.AmountOutMsat,
		Rate:           rate,
		FeeMsat:        feeMsat,
		IncomingChannelID: event.Htlc.IncomingCircuitKey.
			ChanID.ToUint64(),
		OutgoingChannelID: event.Htlc.OutgoingChannelID.
			ToUint64(),
	}, nil
}

// extractAssetIDFromSpecifier extracts the asset ID from an asset specifier.
func extractAssetIDFromSpecifier(spec asset.Specifier) asset.ID {
	assetID, err := spec.UnwrapIdOrErr()
	if err != nil {
		// If there's no asset ID, return a zero ID.
		return asset.ID{}
	}

	return assetID
}

// LogAcceptHtlcEvent logs an accept HTLC event to the database.
// This is a wrapper around LogForwardingEvent that converts the
// AcceptHtlcEvent.
func (r *RfqForwardingEventStore) LogAcceptHtlcEvent(ctx context.Context,
	htlcEvent *rfq.AcceptHtlcEvent) error {

	event, err := ExtractForwardingEventFromAcceptHtlc(htlcEvent)
	if err != nil {
		return fmt.Errorf("unable to extract forwarding "+
			"event: %w", err)
	}

	return r.LogForwardingEvent(ctx, event)
}

// Ensure RfqForwardingEventStore implements ForwardingEventStore.
var _ ForwardingEventStore = (*RfqForwardingEventStore)(nil)
