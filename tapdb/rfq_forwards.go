package tapdb

import (
	"context"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/rfq"
	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightningnetwork/lnd/routing/route"
)

// RfqForwardStore is the database interface for RFQ forward records.
type RfqForwardStore interface {
	// InsertRfqForward inserts a new forward record.
	InsertRfqForward(ctx context.Context,
		arg sqlc.InsertRfqForwardParams) (int64, error)

	// QueryRfqForwards queries forward records with optional filters.
	QueryRfqForwards(ctx context.Context,
		arg sqlc.QueryRfqForwardsParams) ([]sqlc.QueryRfqForwardsRow,
		error)

	// CountRfqForwards counts forward records matching the filters.
	CountRfqForwards(ctx context.Context,
		arg sqlc.CountRfqForwardsParams) (int64, error)
}

// BatchedRfqForwardStore supports batched database operations.
type BatchedRfqForwardStore interface {
	RfqForwardStore
	BatchedTx[RfqForwardStore]
}

// PersistedForwardStore provides methods to persist and query RFQ forwards.
type PersistedForwardStore struct {
	db BatchedRfqForwardStore
}

// NewPersistedForwardStore creates a new forward persistence helper.
func NewPersistedForwardStore(
	db BatchedRfqForwardStore) *PersistedForwardStore {

	return &PersistedForwardStore{
		db: db,
	}
}

// LogForward persists a new forward record.
func (s *PersistedForwardStore) LogForward(ctx context.Context,
	input rfq.ForwardInput) (int64, error) {

	writeOpts := WriteTxOption()
	var id int64

	err := s.db.ExecTx(ctx, writeOpts, func(q RfqForwardStore) error {
		var err error
		id, err = q.InsertRfqForward(ctx, sqlc.InsertRfqForwardParams{
			SettledAt: input.SettledAt.UTC(),
			RfqID:     input.RfqID[:],
			ChanIDIn:  int64(input.ChanIDIn),
			ChanIDOut: int64(input.ChanIDOut),
			HtlcID:    int64(input.HtlcID),
			AssetAmt:  int64(input.AssetAmt),
		})
		if err != nil {
			return fmt.Errorf("error inserting RFQ "+
				"forward: %w", err)
		}

		return nil
	})
	if err != nil {
		return 0, err
	}

	return id, nil
}

// QueryForwards retrieves forward records matching the given filters.
func (s *PersistedForwardStore) QueryForwards(ctx context.Context,
	params rfq.QueryForwardsParams) ([]rfq.RfqForwardRecord, error) {

	// Set default time bounds if not specified.
	settledAfter := params.MinTimestamp
	if settledAfter.IsZero() {
		settledAfter = time.Unix(0, 0).UTC()
	}

	settledBefore := params.MaxTimestamp
	if settledBefore.IsZero() {
		settledBefore = MaxValidSQLTime
	}

	queryParams := sqlc.QueryRfqForwardsParams{
		SettledAfter:  settledAfter.UTC(),
		SettledBefore: settledBefore.UTC(),
		NumLimit:      params.Limit,
		NumOffset:     params.Offset,
	}

	if params.Peer != nil {
		queryParams.Peer = params.Peer[:]
	}
	if params.AssetID != nil {
		queryParams.AssetID = params.AssetID[:]
	}
	if params.AssetGroupKey != nil {
		groupKey := params.AssetGroupKey.SerializeCompressed()
		queryParams.AssetGroupKey = groupKey
	}

	readOpts := ReadTxOption()
	var records []rfq.RfqForwardRecord

	err := s.db.ExecTx(ctx, readOpts, func(q RfqForwardStore) error {
		rows, err := q.QueryRfqForwards(ctx, queryParams)
		if err != nil {
			return fmt.Errorf("error querying forwards: %w", err)
		}

		records = make([]rfq.RfqForwardRecord, 0, len(rows))
		for _, row := range rows {
			record, err := forwardRecordFromRow(row)
			if err != nil {
				return fmt.Errorf("error converting row: %w",
					err)
			}

			records = append(records, record)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return records, nil
}

// CountForwards returns the count of forward records matching the filters.
func (s *PersistedForwardStore) CountForwards(ctx context.Context,
	params rfq.QueryForwardsParams) (int64, error) {

	// Set default time bounds if not specified.
	settledAfter := params.MinTimestamp
	if settledAfter.IsZero() {
		settledAfter = time.Unix(0, 0).UTC()
	}

	settledBefore := params.MaxTimestamp
	if settledBefore.IsZero() {
		settledBefore = MaxValidSQLTime
	}

	countParams := sqlc.CountRfqForwardsParams{
		SettledAfter:  settledAfter.UTC(),
		SettledBefore: settledBefore.UTC(),
	}

	if params.Peer != nil {
		countParams.Peer = params.Peer[:]
	}
	if params.AssetID != nil {
		countParams.AssetID = params.AssetID[:]
	}
	if params.AssetGroupKey != nil {
		groupKey := params.AssetGroupKey.SerializeCompressed()
		countParams.AssetGroupKey = groupKey
	}

	readOpts := ReadTxOption()
	var count int64

	err := s.db.ExecTx(ctx, readOpts, func(q RfqForwardStore) error {
		var err error
		count, err = q.CountRfqForwards(ctx, countParams)
		if err != nil {
			return fmt.Errorf("error counting forwards: %w", err)
		}

		return nil
	})
	if err != nil {
		return 0, err
	}

	return count, nil
}

// forwardRecordFromRow converts a database row to an RfqForwardRecord.
func forwardRecordFromRow(row sqlc.QueryRfqForwardsRow) (rfq.RfqForwardRecord,
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
			return rfq.RfqForwardRecord{}, fmt.Errorf("error "+
				"parsing group key: %w", err)
		}
	}

	rate := rfqmath.BigIntFixedPoint{
		Coefficient: rfqmath.BigInt{}.FromBytes(row.RateCoefficient),
		Scale:       uint8(row.RateScale),
	}

	return rfq.RfqForwardRecord{
		ID:            row.ID,
		SettledAt:     row.SettledAt.UTC(),
		RfqID:         rfqID,
		ChanIDIn:      uint64(row.ChanIDIn),
		ChanIDOut:     uint64(row.ChanIDOut),
		HtlcID:        uint64(row.HtlcID),
		AssetAmt:      uint64(row.AssetAmt),
		PolicyType:    rfq.RfqPolicyType(row.PolicyType),
		Peer:          peer,
		AssetID:       assetID,
		AssetGroupKey: groupKey,
		Rate:          rate,
	}, nil
}
