package tapdb

import (
	"context"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/rfq"
	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightningnetwork/lnd/routing/route"
)

// ForwardStore is the database interface for forwarding event records.
type ForwardStore interface {
	// UpsertForward inserts or updates a forwarding event record.
	UpsertForward(ctx context.Context,
		arg sqlc.UpsertForwardParams) (int64, error)

	// QueryPendingForwards fetches events without a terminal state.
	QueryPendingForwards(ctx context.Context) (
		[]sqlc.QueryPendingForwardsRow, error)

	// QueryForwards queries forwarding event records with optional filters.
	QueryForwards(ctx context.Context,
		arg sqlc.QueryForwardsParams) ([]sqlc.QueryForwardsRow, error)

	// CountForwards counts forwarding event records matching the filters.
	CountForwards(ctx context.Context,
		arg sqlc.CountForwardsParams) (int64, error)
}

// BatchedForwardingEventStore supports batched database operations.
type BatchedForwardingEventStore interface {
	ForwardStore
	BatchedTx[ForwardStore]
}

// PersistedForwardStore provides methods to persist and query forwarding
// events.
type PersistedForwardStore struct {
	db BatchedForwardingEventStore
}

// NewPersistedForwardStore creates a new forward persistence helper.
func NewPersistedForwardStore(
	db BatchedForwardingEventStore) *PersistedForwardStore {

	return &PersistedForwardStore{
		db: db,
	}
}

// UpsertForward inserts or updates a forwarding event record.
func (s *PersistedForwardStore) UpsertForward(ctx context.Context,
	input rfq.ForwardInput) error {

	writeOpts := WriteTxOption()

	return s.db.ExecTx(ctx, writeOpts, func(q ForwardStore) error {
		_, err := q.UpsertForward(ctx, sqlc.UpsertForwardParams{
			OpenedAt:   input.OpenedAt.UTC(),
			SettledAt:  sqlOptTime(input.SettledAt),
			FailedAt:   sqlOptTime(input.FailedAt),
			RfqID:      input.RfqID[:],
			ChanIDIn:   int64(input.ChanIDIn),
			ChanIDOut:  int64(input.ChanIDOut),
			HtlcID:     int64(input.HtlcID),
			AssetAmt:   int64(input.AssetAmt),
			AmtInMsat:  int64(input.AmtInMsat),
			AmtOutMsat: int64(input.AmtOutMsat),
		})
		if err != nil {
			return fmt.Errorf("error upserting forwarding event: "+
				"%w", err)
		}

		return nil
	})
}

// PendingForwards retrieves events without a settled or failed timestamp.
func (s *PersistedForwardStore) PendingForwards(
	ctx context.Context,
) ([]rfq.ForwardInput, error) {

	readOpts := ReadTxOption()
	var forwards []rfq.ForwardInput

	err := s.db.ExecTx(ctx, readOpts, func(q ForwardStore) error {
		rows, err := q.QueryPendingForwards(ctx)
		if err != nil {
			return fmt.Errorf("querying pending forwarding "+
				"events: %w", err)
		}

		forwards = make([]rfq.ForwardInput, 0, len(rows))
		for _, row := range rows {
			input, err := forwardInputFromPendingRow(row)
			if err != nil {
				return fmt.Errorf(
					"converting pending forward: %w", err)
			}

			forwards = append(forwards, input)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return forwards, nil
}

type forwardQueryFilters struct {
	openedAfter   time.Time
	openedBefore  time.Time
	peer          []byte
	assetID       []byte
	assetGroupKey []byte
}

func buildForwardQueryFilters(
	params rfq.QueryForwardsParams) forwardQueryFilters {

	// Set default time bounds if not specified.
	openedAfter := params.MinTimestamp.UnwrapOr(time.Unix(0, 0).UTC())
	openedBefore := params.MaxTimestamp.UnwrapOr(MaxValidSQLTime)

	filters := forwardQueryFilters{
		openedAfter:  openedAfter.UTC(),
		openedBefore: openedBefore.UTC(),
	}

	if params.Peer != nil {
		filters.peer = params.Peer[:]
	}

	if params.AssetSpecifier != nil {
		params.AssetSpecifier.WhenId(func(id asset.ID) {
			filters.assetID = id[:]
		})

		params.AssetSpecifier.WhenGroupPubKey(
			func(key btcec.PublicKey) {
				filters.assetGroupKey =
					key.SerializeCompressed()
			},
		)
	}

	return filters
}

func queryForwardRecords(ctx context.Context, q ForwardStore,
	queryParams sqlc.QueryForwardsParams) ([]rfq.ForwardingEvent, error) {

	rows, err := q.QueryForwards(ctx, queryParams)
	if err != nil {
		return nil, fmt.Errorf("error querying forwarding events: %w",
			err)
	}

	records := make([]rfq.ForwardingEvent, 0, len(rows))
	for _, row := range rows {
		record, err := forwardRecordFromRow(row)
		if err != nil {
			return nil, fmt.Errorf("error converting row: %w",
				err)
		}

		records = append(records, record)
	}

	return records, nil
}

func countForwardRecords(ctx context.Context, q ForwardStore,
	countParams sqlc.CountForwardsParams) (int64, error) {

	count, err := q.CountForwards(ctx, countParams)
	if err != nil {
		return 0, fmt.Errorf("error counting forwarding events: %w",
			err)
	}

	return count, nil
}

// QueryForwardsWithCount retrieves forwarding event records matching the given
// filters along with the total count in a single transaction.
func (s *PersistedForwardStore) QueryForwardsWithCount(ctx context.Context,
	params rfq.QueryForwardsParams) ([]rfq.ForwardingEvent, int64, error) {

	filters := buildForwardQueryFilters(params)
	queryParams := sqlc.QueryForwardsParams{
		OpenedAfter:   filters.openedAfter,
		OpenedBefore:  filters.openedBefore,
		NumLimit:      params.Limit,
		NumOffset:     params.Offset,
		Peer:          filters.peer,
		AssetID:       filters.assetID,
		AssetGroupKey: filters.assetGroupKey,
	}
	countParams := sqlc.CountForwardsParams{
		OpenedAfter:   filters.openedAfter,
		OpenedBefore:  filters.openedBefore,
		Peer:          filters.peer,
		AssetID:       filters.assetID,
		AssetGroupKey: filters.assetGroupKey,
	}

	readOpts := ReadTxOption()
	var (
		records []rfq.ForwardingEvent
		count   int64
	)

	err := s.db.ExecTx(ctx, readOpts, func(q ForwardStore) error {
		var err error
		records, err = queryForwardRecords(ctx, q, queryParams)
		if err != nil {
			return err
		}

		count, err = countForwardRecords(ctx, q, countParams)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return nil, 0, err
	}

	return records, count, nil
}

// forwardInputFromPendingRow converts a pending forward row to a forward input.
func forwardInputFromPendingRow(
	row sqlc.QueryPendingForwardsRow,
) (rfq.ForwardInput, error) {

	var rfqID rfqmsg.ID
	if len(row.RfqID) != len(rfqID) {
		return rfq.ForwardInput{},
			fmt.Errorf("invalid RFQ ID length: %d", len(row.RfqID))
	}
	copy(rfqID[:], row.RfqID)

	return rfq.ForwardInput{
		OpenedAt:   row.OpenedAt.UTC(),
		SettledAt:  fn.None[time.Time](),
		FailedAt:   fn.None[time.Time](),
		RfqID:      rfqID,
		ChanIDIn:   uint64(row.ChanIDIn),
		ChanIDOut:  uint64(row.ChanIDOut),
		HtlcID:     uint64(row.HtlcID),
		AssetAmt:   uint64(row.AssetAmt),
		AmtInMsat:  uint64(row.AmtInMsat),
		AmtOutMsat: uint64(row.AmtOutMsat),
	}, nil
}

// forwardRecordFromRow converts a database row to a ForwardingEvent.
func forwardRecordFromRow(row sqlc.QueryForwardsRow) (rfq.ForwardingEvent,
	error) {

	var rfqID rfqmsg.ID
	copy(rfqID[:], row.RfqID)

	var peer route.Vertex
	copy(peer[:], row.Peer)

	var assetID *asset.ID
	if len(row.AssetID) > 0 {
		id := new(asset.ID)
		copy(id[:], row.AssetID)
		assetID = id
	}

	var groupKey *btcec.PublicKey
	if len(row.AssetGroupKey) > 0 {
		var err error
		groupKey, err = btcec.ParsePubKey(row.AssetGroupKey)
		if err != nil {
			return rfq.ForwardingEvent{}, fmt.Errorf("error "+
				"parsing group key: %w", err)
		}
	}

	assetSpecifier, err := asset.NewSpecifier(
		assetID, groupKey, nil, false,
	)
	if err != nil {
		return rfq.ForwardingEvent{}, fmt.Errorf("error "+
			"building asset specifier: %w", err)
	}

	rate := rfqmath.BigIntFixedPoint{
		Coefficient: rfqmath.BigInt{}.FromBytes(row.RateCoefficient),
		Scale:       uint8(row.RateScale),
	}

	// Convert nullable timestamps to pointers.
	var settledAt *time.Time
	if row.SettledAt.Valid {
		t := row.SettledAt.Time.UTC()
		settledAt = &t
	}

	var failedAt *time.Time
	if row.FailedAt.Valid {
		t := row.FailedAt.Time.UTC()
		failedAt = &t
	}

	return rfq.ForwardingEvent{
		OpenedAt:       row.OpenedAt.UTC(),
		SettledAt:      settledAt,
		FailedAt:       failedAt,
		RfqID:          rfqID,
		ChanIDIn:       uint64(row.ChanIDIn),
		ChanIDOut:      uint64(row.ChanIDOut),
		HtlcID:         uint64(row.HtlcID),
		AssetAmt:       uint64(row.AssetAmt),
		AmtInMsat:      uint64(row.AmtInMsat),
		AmtOutMsat:     uint64(row.AmtOutMsat),
		PolicyType:     rfq.RfqPolicyType(row.PolicyType),
		Peer:           peer,
		AssetSpecifier: assetSpecifier,
		Rate:           rate,
	}, nil
}
