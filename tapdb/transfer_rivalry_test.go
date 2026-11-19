package tapdb

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// addRivalTransfer records a transfer spending the given outpoint,
// with its own anchor transaction, optionally confirmed. It returns
// the transfer's row ID.
//
// Two local transfers may legitimately spend one input: the sweeper's
// fee bump composes a replacement form against the same outpoint, and
// only the losing form is abandoned.
func (f *contractFixture) addRivalTransfer(t require.TestingT,
	anchorPoint []byte, genAssetID, scriptKey []byte,
	confirmed bool) int64 {

	ctx := context.Background()

	f.anchorNonce++
	var txid [32]byte
	binary.BigEndian.PutUint64(txid[:8], f.anchorNonce)
	txid[8] = 0xfe

	var (
		blockHash   any
		blockHeight any
	)
	if confirmed {
		blockHash = bytes.Repeat([]byte{0x77}, 32)
		blockHeight = 700
	}

	_, err := f.db.DB.ExecContext(
		ctx, "INSERT INTO chain_txns "+
			"(txid, chain_fees, raw_tx, block_hash, block_height) "+
			"VALUES ($1, 0, $2, $3, $4)",
		txid[:], []byte{0x00}, blockHash, blockHeight,
	)
	require.NoError(t, err)

	_, err = f.db.DB.ExecContext(
		ctx, "INSERT INTO asset_transfers "+
			"(height_hint, anchor_txn_id, transfer_time_unix) "+
			"SELECT 1, txn_id, CURRENT_TIMESTAMP FROM chain_txns "+
			"WHERE txid = $1", txid[:],
	)
	require.NoError(t, err)

	var transferID int64
	err = f.db.DB.QueryRowContext(
		ctx, "SELECT id FROM asset_transfers ORDER BY id DESC LIMIT 1",
	).Scan(&transferID)
	require.NoError(t, err)

	f.addTransferInput(t, transferID, anchorPoint, genAssetID, scriptKey)

	return transferID
}

// addTransferInput records an input on an existing transfer.
func (f *contractFixture) addTransferInput(t require.TestingT,
	transferID int64, anchorPoint, genAssetID, scriptKey []byte) {

	_, err := f.db.DB.ExecContext(
		context.Background(), "INSERT INTO asset_transfer_inputs "+
			"(transfer_id, anchor_point, asset_id, script_key, "+
			"amount) VALUES ($1, $2, $3, $4, 1)",
		transferID, anchorPoint, genAssetID, scriptKey,
	)
	require.NoError(t, err)
}

// setTransferSuperseded marks a transfer as a rivalry loser.
func (f *contractFixture) setTransferSuperseded(t require.TestingT,
	transferID int64) {

	_, err := f.db.DB.ExecContext(
		context.Background(),
		"UPDATE asset_transfers SET superseded = TRUE WHERE id = $1",
		transferID,
	)
	require.NoError(t, err)
}

// transferSuperseded reports a transfer's superseded flag.
func (f *contractFixture) transferSuperseded(t require.TestingT,
	transferID int64) bool {

	var superseded bool
	err := f.db.DB.QueryRowContext(
		context.Background(),
		"SELECT superseded FROM asset_transfers WHERE id = $1",
		transferID,
	).Scan(&superseded)
	require.NoError(t, err)

	return superseded
}

// assetSpent reports an asset row's spent flag.
func (f *contractFixture) assetSpent(t require.TestingT, dbID int64) bool {
	var spent bool
	err := f.db.DB.QueryRowContext(
		context.Background(),
		"SELECT spent FROM assets WHERE asset_id = $1", dbID,
	).Scan(&spent)
	require.NoError(t, err)

	return spent
}

// TestTransferRivalryContract asserts the two invariants that govern
// what an abandonment may undo when several transfers contend for one
// input.
//
// Both are inverse-operation properties: abandoning a transfer must
// undo what that transfer did, and nothing a surviving transfer or a
// prior abandonment established.
func TestTransferRivalryContract(t *testing.T) {
	t.Parallel()

	f := newContractFixture(t)
	ctx := context.Background()

	rapid.Check(t, func(rt *rapid.T) {
		// One asset, spent by the transfers below.
		w := genContractWorld(rt, t, f)
		inputDBID := w.assetDBIDs[0]

		anchorPoint, err := encodeOutpoint(wire.OutPoint{
			Hash: w.anchorTxid, Index: 0,
		})
		require.NoError(rt, err)

		var (
			genAssetID []byte
			scriptKey  []byte
		)
		err = f.db.DB.QueryRowContext(
			ctx, "SELECT genesis_assets.asset_id, "+
				"script_keys.tweaked_script_key "+
				"FROM assets "+
				"JOIN genesis_assets ON assets.genesis_id = "+
				"genesis_assets.gen_asset_id "+
				"JOIN script_keys ON assets.script_key_id = "+
				"script_keys.script_key_id "+
				"WHERE assets.asset_id = $1", inputDBID,
		).Scan(&genAssetID, &scriptKey)
		require.NoError(rt, err)

		_, err = f.db.DB.ExecContext(
			ctx, "UPDATE assets SET spent = TRUE "+
				"WHERE asset_id = $1", inputDBID,
		)
		require.NoError(rt, err)

		// A rival form against the same input, confirmed or not,
		// and a sibling that a prior abandonment already killed.
		rivalConfirmed := rapid.Bool().Draw(rt, "rivalConfirmed")
		rival := f.addRivalTransfer(
			rt, anchorPoint, genAssetID, scriptKey, rivalConfirmed,
		)

		deadSibling := f.addRivalTransfer(
			rt, anchorPoint, genAssetID, scriptKey, false,
		)
		require.NoError(
			rt, f.db.MarkTransferSuperseded(ctx, deadSibling),
		)

		// The losing form is abandoned: its inputs are released
		// and superseded rivals are reconsidered.
		losing := f.addRivalTransfer(
			rt, anchorPoint, genAssetID, scriptKey, false,
		)

		_, err = f.db.SetAssetUnspent(ctx, sqlc.SetAssetUnspentParams{
			ScriptKey:   scriptKey,
			GenAssetID:  genAssetID,
			AnchorPoint: anchorPoint,
		})
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			require.NoError(rt, err)
		}

		_, err = reviveSafeRivals(
			ctx, f.db.Queries, losing, [][]byte{anchorPoint}, nil,
		)
		require.NoError(rt, err)

		// A confirmed rival still consumes the input, so the
		// abandonment of a losing form must not restore it.
		if rivalConfirmed {
			require.True(
				rt, f.assetSpent(rt, inputDBID),
				"input un-spent while a confirmed transfer "+
					"still claims it",
			)
		}

		// A transfer killed by a prior abandonment can never
		// confirm; reviving it resumes a dead parcel at startup.
		require.True(
			rt, f.transferSuperseded(rt, deadSibling),
			"abandonment revived a permanently dead transfer",
		)

		_ = rival
	})
}

// TestReviveScopesOverRivalInputs pins the scope of the revive step: a
// rival sharing an input with the abandoned transfer is revived only
// if it can still confirm, which is a question about every one of its
// inputs. Sharing input X with the losing form says nothing about the
// rival's input Y: if a confirmed transfer claims Y, or the foreclosing
// transaction consumed it, the rival's anchor is doomed, and reviving
// it would resume a parcel that rebroadcasts it. Such a rival keeps
// its flags as they are.
func TestReviveScopesOverRivalInputs(t *testing.T) {
	t.Parallel()

	f := newContractFixture(t)
	ctx := context.Background()

	testCases := []struct {
		name string

		// claimed plants a confirmed transfer spending Y.
		claimed bool

		// foreclosed hands Y to the revive step as consumed by
		// the foreclosing transaction.
		foreclosed bool

		revived bool
	}{{
		name:    "Y unclaimed",
		revived: true,
	}, {
		name:    "Y claimed by a confirmed transfer",
		claimed: true,
	}, {
		name:       "Y consumed by the forecloser",
		foreclosed: true,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pointX, err := encodeOutpoint(test.RandOp(t))
			require.NoError(t, err)
			opY := test.RandOp(t)
			pointY, err := encodeOutpoint(opY)
			require.NoError(t, err)
			genAssetID := test.RandBytes(32)
			scriptKey := test.RandBytes(33)

			if tc.claimed {
				f.addRivalTransfer(
					t, pointY, genAssetID, scriptKey, true,
				)
			}

			// The rival: a superseded form spending X and Y.
			rival := f.addRivalTransfer(
				t, pointX, genAssetID, scriptKey, false,
			)
			f.addTransferInput(
				t, rival, pointY, genAssetID, scriptKey,
			)
			f.setTransferSuperseded(t, rival)

			// The losing form at X is abandoned.
			losing := f.addRivalTransfer(
				t, pointX, genAssetID, scriptKey, false,
			)
			var foreclosed map[wire.OutPoint]struct{}
			if tc.foreclosed {
				foreclosed = map[wire.OutPoint]struct{}{
					opY: {},
				}
			}
			numRevived, err := reviveSafeRivals(
				ctx, f.db.Queries, losing, [][]byte{pointX},
				foreclosed,
			)
			require.NoError(t, err)

			if tc.revived {
				require.Equal(t, 1, numRevived)
				require.False(t, f.transferSuperseded(t, rival))

				return
			}

			require.Zero(t, numRevived)
			require.True(
				t, f.transferSuperseded(t, rival),
				"revived a rival whose other input is lost",
			)
			require.False(
				t, f.transferAbandoned(t, rival),
				"a rival left superseded must not be marked "+
					"abandoned: that flag records its own "+
					"compensation",
			)
		})
	}
}
