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

	// SumRfqAssetVolume sums the asset amounts of forward records matching
	// the filters.
	SumRfqAssetVolume(ctx context.Context,
		arg sqlc.SumRfqAssetVolumeParams) (interface{}, error)
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
			SettledAt: input.SettledAt.UTC().Unix(),
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

	queryParams := sqlc.QueryRfqForwardsParams{
		QueryLimit:  params.Limit,
		QueryOffset: params.Offset,
	}

	if !params.MinTimestamp.IsZero() {
		queryParams.MinTimestamp = params.MinTimestamp.UTC().Unix()
	}
	if !params.MaxTimestamp.IsZero() {
		queryParams.MaxTimestamp = params.MaxTimestamp.UTC().Unix()
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

	countParams := sqlc.CountRfqForwardsParams{}

	if !params.MinTimestamp.IsZero() {
		countParams.MinTimestamp = params.MinTimestamp.UTC().Unix()
	}
	if !params.MaxTimestamp.IsZero() {
		countParams.MaxTimestamp = params.MaxTimestamp.UTC().Unix()
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

// SumAssetVolume returns the sum of asset amounts for forward records matching
// the filters.
func (s *PersistedForwardStore) SumAssetVolume(ctx context.Context,
	params rfq.QueryForwardsParams) (uint64, error) {

	sumParams := sqlc.SumRfqAssetVolumeParams{}

	if !params.MinTimestamp.IsZero() {
		sumParams.MinTimestamp = params.MinTimestamp.UTC().Unix()
	}
	if !params.MaxTimestamp.IsZero() {
		sumParams.MaxTimestamp = params.MaxTimestamp.UTC().Unix()
	}
	if params.AssetID != nil {
		sumParams.AssetID = params.AssetID[:]
	}
	if params.AssetGroupKey != nil {
		groupKey := params.AssetGroupKey.SerializeCompressed()
		sumParams.AssetGroupKey = groupKey
	}

	readOpts := ReadTxOption()
	var total uint64

	err := s.db.ExecTx(ctx, readOpts, func(q RfqForwardStore) error {
		result, err := q.SumRfqAssetVolume(ctx, sumParams)
		if err != nil {
			return fmt.Errorf("error summing asset volume: %w", err)
		}

		// The COALESCE in SQL returns 0 if no rows, but we need to
		// handle the interface{} type from sqlc.
		switch v := result.(type) {
		case int64:
			total = uint64(v)
		case float64:
			total = uint64(v)
		default:
			// Default to 0 if unexpected type.
			total = 0
		}

		return nil
	})
	if err != nil {
		return 0, err
	}

	return total, nil
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
		SettledAt:     time.Unix(row.SettledAt, 0).UTC(),
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
