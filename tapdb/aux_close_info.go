package tapdb

import (
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
)

// ErrNoAuxCloseInfo is returned when no row exists for the requested channel
// point.
var ErrNoAuxCloseInfo = errors.New("no aux close info")

// AuxCloseInfoStore is the set of generated query methods needed to manage
// the aux_channel_close_info table.
type AuxCloseInfoStore interface {
	UpsertAuxCloseInfo(ctx context.Context,
		arg sqlc.UpsertAuxCloseInfoParams) error

	FetchAuxCloseInfo(ctx context.Context, chanPoint []byte) ([]byte, error)

	DeleteAuxCloseInfo(ctx context.Context, chanPoint []byte) error
}

// BatchedAuxCloseInfoStore enables batched access to the underlying query
// surface — required for ExecTx.
type BatchedAuxCloseInfoStore interface {
	AuxCloseInfoStore
	BatchedTx[AuxCloseInfoStore]
}

// PersistedAuxCloseStore is a byte-level store for per-channel aux close
// info, backed by sqlite/postgres via sqlc. The consumer (tapchannel) owns
// the on-disk encoding of the blob; this layer just persists and retrieves
// raw bytes keyed by channel point.
type PersistedAuxCloseStore struct {
	db BatchedAuxCloseInfoStore
}

// NewPersistedAuxCloseStore returns a store backed by the given queries
// handle.
func NewPersistedAuxCloseStore(
	db BatchedAuxCloseInfoStore) *PersistedAuxCloseStore {

	return &PersistedAuxCloseStore{db: db}
}

// PutAuxCloseBlob inserts or overwrites the close-info blob for the given
// channel point.
func (s *PersistedAuxCloseStore) PutAuxCloseBlob(ctx context.Context,
	chanPoint wire.OutPoint, blob []byte) error {

	key := encodeChanPoint(chanPoint)

	return s.db.ExecTx(
		ctx, WriteTxOption(), func(q AuxCloseInfoStore) error {
			return q.UpsertAuxCloseInfo(
				ctx, sqlc.UpsertAuxCloseInfoParams{
					ChanPoint: key,
					InfoBlob:  blob,
				},
			)
		},
	)
}

// FetchAuxCloseBlob returns the persisted close-info blob for the given
// channel point. Returns ErrNoAuxCloseInfo if no row exists.
func (s *PersistedAuxCloseStore) FetchAuxCloseBlob(ctx context.Context,
	chanPoint wire.OutPoint) ([]byte, error) {

	key := encodeChanPoint(chanPoint)

	var blob []byte
	err := s.db.ExecTx(
		ctx, ReadTxOption(), func(q AuxCloseInfoStore) error {
			out, err := q.FetchAuxCloseInfo(ctx, key)
			switch {
			case errors.Is(err, sql.ErrNoRows):
				return ErrNoAuxCloseInfo
			case err != nil:
				return fmt.Errorf("fetch aux close info: %w",
					err)
			}
			blob = out
			return nil
		},
	)
	if err != nil {
		return nil, err
	}

	return blob, nil
}

// DeleteAuxCloseBlob removes the row for the given channel point. Deleting a
// non-existent row is a no-op.
func (s *PersistedAuxCloseStore) DeleteAuxCloseBlob(ctx context.Context,
	chanPoint wire.OutPoint) error {

	key := encodeChanPoint(chanPoint)

	return s.db.ExecTx(
		ctx, WriteTxOption(), func(q AuxCloseInfoStore) error {
			return q.DeleteAuxCloseInfo(ctx, key)
		},
	)
}

// encodeChanPoint serializes a wire.OutPoint as 32 bytes of txid followed by
// 4 bytes of big-endian output index — matching the CHECK constraint on the
// chan_point column.
func encodeChanPoint(op wire.OutPoint) []byte {
	out := make([]byte, 36)
	copy(out[:32], op.Hash[:])
	binary.BigEndian.PutUint32(out[32:], op.Index)
	return out
}
