package tapdb

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// Nontrivial re-org ladders.
//
// The per-site persistence tests walk one hand-built ladder against one
// asset: confirm in block A, re-confirm in block B, unconfirm, abandon.
// Real re-organizations are neither that short nor that orderly. A
// chain can oscillate — witness, lose it, re-witness at a third height,
// lose it again — and every rung of that ladder is delivered to a world
// holding several assets, some of which the site does not own.
//
// The properties below generate both halves: the world (via
// genContractWorld) and the ladder itself. They assert what each rung
// owes its caller, at every rung rather than only at the end:
//
//   - Totality: no rung fails, in any order, at any depth. A rung runs
//     inside the watcher's delivery transaction, so an error rolls back
//     the phase acknowledgement and the anchoring retries forever.
//   - Convergence: applying a rung twice equals applying it once. In
//     particular a re-stamp must replace the tip proof, never append —
//     a growing proof file is the signature of a non-convergent
//     re-confirmation.
//   - Scope: a re-stamp reaches exactly the assets the site staked.
//     Passive holdings belong to the porter's transfer and must not be
//     touched by a receive re-confirmation, just as they must survive
//     its abandonment.
//   - Freshness: after re-confirmation at a new height, no asset is
//     left carrying a stale block context. This is the property a
//     re-org actually threatens, and the one the single-asset ladders
//     only ever check against a single row.

// rungKind enumerates the phase transitions an anchoring's persistence
// layer must absorb.
type rungKind uint8

const (
	// rungReconfirm re-confirms the anchor transaction, either in a
	// fresh block (the re-org case) or in the block already recorded
	// (the redelivery case).
	rungReconfirm rungKind = iota

	// rungUnconfirm withdraws the recorded confirmation: the
	// potency-tier soft downgrade.
	rungUnconfirm

	// rungAbandon applies terminal compensation.
	rungAbandon
)

// reorgRung is one step of a generated ladder.
type reorgRung struct {
	kind rungKind

	// nonce selects the block a re-confirmation lands in. Reusing a
	// previous rung's nonce models a redelivered confirmation; a
	// fresh one models a re-organized re-confirmation elsewhere.
	nonce uint32

	// height is the block height for a re-confirmation.
	height uint32
}

// genReorgLadder draws a sequence of phase transitions. Abandonment is
// terminal and absorbing, so it appears at most once; it may fall
// anywhere in the ladder, or nowhere. The watcher derives no phase past
// an abandonment, but the bodies are convergent by contract and owe
// that regardless of what reaches them: a rung delivered after the
// compensation, however it got there, must not resurrect what the
// compensation withdrew. Rungs after the abandonment model exactly
// that.
func genReorgLadder(rt *rapid.T) []reorgRung {
	numRungs := rapid.IntRange(2, 6).Draw(rt, "numRungs")

	// The abandonment's position, if any: before the rung at that
	// index, or after the last one.
	abandonAt := -1
	if rapid.Bool().Draw(rt, "abandon") {
		abandonAt = rapid.IntRange(0, numRungs).Draw(rt, "abandonAt")
	}

	rungs := make([]reorgRung, 0, numRungs+1)

	// nonce 10 is the first block; a fresh block bumps it, a
	// redelivery reuses it.
	nonce := uint32(10)
	height := uint32(700)

	for i := 0; i < numRungs; i++ {
		if i == abandonAt {
			rungs = append(rungs, reorgRung{kind: rungAbandon})
		}

		label := fmt.Sprintf("rung%d", i)
		if rapid.Bool().Draw(rt, label+"unconfirm") {
			rungs = append(rungs, reorgRung{kind: rungUnconfirm})

			continue
		}

		// A re-confirmation either redelivers the current block or
		// lands in a new one.
		if rapid.Bool().Draw(rt, label+"newBlock") {
			nonce++
			height++
		}

		rungs = append(rungs, reorgRung{
			kind:   rungReconfirm,
			nonce:  nonce,
			height: height,
		})
	}

	if abandonAt == numRungs {
		rungs = append(rungs, reorgRung{kind: rungAbandon})
	}

	return rungs
}

// tipStamp reports the block context stamped on an asset's stored proof
// tip, along with the number of proofs in the file. The count is the
// convergence witness: a re-stamp replaces the tip, so a file that grows
// across re-confirmations is appending instead.
func (f *contractFixture) tipStamp(t require.TestingT,
	dbID int64) (chainhash.Hash, uint32, int) {

	ctx := context.Background()

	blob, err := f.db.AssetProofBlobByAssetID(ctx, dbID)
	require.NoError(t, err)

	file := &proof.File{}
	require.NoError(t, file.Decode(bytes.NewReader(blob)))

	numProofs := file.NumProofs()
	require.NotZero(t, numProofs)

	tip, err := file.ProofAt(uint32(numProofs - 1))
	require.NoError(t, err)

	return tip.BlockHeader.BlockHash(), tip.BlockHeight, numProofs
}

// chainConfirmed reports the recorded block hash for the anchor
// transaction, or nil when the transaction is unconfirmed.
func (f *contractFixture) chainConfirmed(t require.TestingT,
	txid chainhash.Hash) []byte {

	chainTx, err := f.db.FetchChainTx(context.Background(), txid[:])
	require.NoError(t, err)

	return chainTx.BlockHash
}

// completedEvents counts the address events keyed to the anchor
// transaction that still record a completed receive.
func (f *contractFixture) completedEvents(t require.TestingT,
	txid chainhash.Hash) int {

	var count int
	err := f.db.DB.QueryRowContext(
		context.Background(),
		"SELECT COUNT(*) FROM addr_events "+
			"WHERE status = $1 AND chain_txn_id IN "+
			"(SELECT txn_id FROM chain_txns WHERE txid = $2)",
		int16(address.StatusCompleted), txid[:],
	).Scan(&count)
	require.NoError(t, err)

	return count
}

// TestCrossSiteReorgLadderContract drives the self-send shape — one
// anchor transaction staked by the porter and the receive at once —
// through a generated re-org ladder, abandoning it from both sites in
// a generated order wherever the ladder places the loss.
//
// The existing compensation contract covers both orders, but only for
// a bare abandonment applied to a freshly built world. A real loss is
// reached through a ladder: the transaction confirms, is re-organized
// away, re-confirms elsewhere, and only then is foreclosed. Each rung
// leaves state behind for the next, so the ordering hazard the two
// sites already guard against has to hold at every depth, not just at
// depth zero.
//
// The end-state property is the one the single-site tests cannot
// state: the two compensations divide the work between them, the
// porter shedding the custody reference and the receive resetting the
// event that pointed through it. Neither alone leaves a coherent
// ledger, so the assertion is on their conjunction — no completed
// receive may survive a transaction the chain discarded.
func TestCrossSiteReorgLadderContract(t *testing.T) {
	t.Parallel()

	f := newContractFixture(t)
	ctx := context.Background()

	rapid.Check(t, func(rt *rapid.T) {
		w := genContractWorld(rt, t, f)
		ladder := genReorgLadder(rt)

		apply := func(fn func(q *sqlc.Queries) error) error {
			return f.executor.ExecTx(ctx, WriteTxOption(), fn)
		}

		detected := int16(address.StatusTransactionDetected)
		porterAbandon := func() error {
			return apply(func(q *sqlc.Queries) error {
				return f.assetsStore.ApplyTransferAbandonment(
					ctx, q, w.anchorTxid, w.foreclosure,
				)
			})
		}
		receiveAbandon := func() error {
			return apply(func(q *sqlc.Queries) error {
				return f.assetsStore.ApplyReceiveAbandonment(
					ctx, q, w.anchorTxid,
					int16(address.StatusTransactionDetected),
				)
			})
		}

		numEvents := f.eventsWithStatus(
			rt, w.anchorTxid, address.StatusCompleted,
		)

		// Terminal loss from both sites, in a generated order, each
		// applied twice: the two sites' deliveries redeliver
		// independently. Both compensations are then asserted in
		// full.
		abandon := func(where string) {
			if rapid.Bool().Draw(rt, where+" porterFirst") {
				require.NoError(
					rt, porterAbandon(),
					where+" porter first",
				)
				require.NoError(
					rt, receiveAbandon(),
					where+" receive second",
				)
			} else {
				require.NoError(
					rt, receiveAbandon(),
					where+" receive first",
				)
				require.NoError(
					rt, porterAbandon(),
					where+" porter second",
				)
			}
			require.NoError(
				rt, porterAbandon(),
				where+" porter redelivered",
			)
			require.NoError(
				rt, receiveAbandon(),
				where+" receive redelivered",
			)

			f.assertTransferCompensated(rt, w, where)
			f.assertReceiveCompensated(rt, w, numEvents, where)
		}

		// The potency-tier rungs, on the receive side. The porter's
		// confirmation path rebuilds from the transfer's full
		// pending state, which this generated world does not carry;
		// its own persistence test drives that ladder against a
		// fully built transfer.
		abandoned := false
		for i, rung := range ladder {
			where := fmt.Sprintf("rung %d", i)

			switch rung.kind {
			case rungReconfirm:
				hash, header, merkle := blockContextFor(
					t, w.anchorTx, rung.nonce,
				)
				require.NoError(rt, apply(
					func(q *sqlc.Queries) error {
						return f.assetsStore.
							ApplyReceiveReconfirm(
								ctx, q,
								w.anchorTxid,
								hash,
								rung.height, 0,
								header, merkle,
							)
					},
				), where)

				require.Equal(
					rt, hash[:],
					f.chainConfirmed(rt, w.anchorTxid),
					"%s: chain row not re-confirmed", where,
				)

			case rungUnconfirm:
				// Both sites withdraw the confirmation at
				// the potency tier.
				require.NoError(rt, apply(
					func(q *sqlc.Queries) error {
						return f.assetsStore.
							ApplyReceiveUnconfirm(
								ctx, q,
								w.anchorTxid,
							)
					},
				), where)
				require.NoError(rt, apply(
					func(q *sqlc.Queries) error {
						return f.assetsStore.
							ApplyAnchorTxUnconfirm(
								ctx, q,
								w.anchorTxid,
							)
					},
				), where+" porter")

				require.Nil(
					rt, f.chainConfirmed(rt, w.anchorTxid),
					"%s: confirmation not withdrawn", where,
				)

			case rungAbandon:
				abandon(where)
				abandoned = true

			default:
				rt.Fatalf("unhandled rung kind %d", rung.kind)
			}

			// Nothing delivered after the loss may undo the
			// compensation: the outputs stay withdrawn, the
			// inputs keep the state the loss decided, the
			// transfer stays dead and no receive is completed
			// again. Only the chain row follows the rung, since a
			// (re)confirmation of that row is what the potency
			// bodies converge to.
			if !abandoned {
				continue
			}

			f.assertOutputsWithdrawn(rt, w, where)
			for _, dbID := range w.inputDBIDs {
				require.Equal(
					rt, w.foreclosed[dbID],
					f.assetSpent(rt, dbID),
					"%s: input %d changed state after the "+
						"loss", where, dbID,
				)
			}
			require.True(
				rt, f.transferSuperseded(rt, w.transferID),
				"%s: abandoned transfer revived", where,
			)
			require.True(
				rt, f.transferAbandoned(rt, w.transferID),
				"%s: abandoned flag lost", where,
			)
			require.Zero(
				rt, f.completedEvents(rt, w.anchorTxid),
				"%s: a receive was completed again after the "+
					"loss", where,
			)
		}

		// Terminal loss at whatever depth the ladder reached, when
		// the ladder itself did not deliver it.
		if !abandoned {
			abandon("end")
		}

		live := f.liveAssets(rt, w.assetDBIDs)
		for _, dbID := range w.passiveDBIDs {
			require.True(
				rt, live[dbID],
				"passive holding %d was destroyed", dbID,
			)
		}

		// The conjunction property: no completed receive survives a
		// discarded transaction.
		require.Zero(
			rt, f.completedEvents(rt, w.anchorTxid),
			"a completed receive survived the abandonment of "+
				"the transaction it was recorded against",
		)
	})
}

// addSuccessorPassive records a later transfer that re-anchors the
// given asset as one of its passive holdings, and returns its row ID.
//
// This is the shape genContractWorld cannot draw. There, an asset is
// either a transfer output or a passive holding — the generator picks
// one branch per asset — so a passive_assets row never points at a row
// some other transfer materialized as its own output. On a live node
// the two are routinely the same row: a transfer's output is an
// ordinary holding, and the next transfer that spends a sibling asset
// under the same anchor UTXO re-anchors it passively.
func (f *contractFixture) addSuccessorPassive(t *testing.T,
	dbID int64) int64 {

	ctx := context.Background()

	// A distinct anchor transaction for the successor transfer.
	f.anchorNonce++
	var txid chainhash.Hash
	binary.BigEndian.PutUint64(txid[:8], f.anchorNonce)
	txid[8] = 0x5c

	_, err := f.db.DB.ExecContext(
		ctx, "INSERT INTO chain_txns (txid, chain_fees, raw_tx) "+
			"VALUES ($1, 0, $2)", txid[:], []byte{0x00},
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

	_, err = f.db.DB.ExecContext(
		ctx, "INSERT INTO passive_assets "+
			"(transfer_id, asset_id, new_anchor_utxo, "+
			"script_key, asset_version) "+
			"SELECT $1, $2, assets.anchor_utxo_id, "+
			"script_keys.tweaked_script_key, 0 "+
			"FROM assets "+
			"JOIN script_keys ON assets.script_key_id = "+
			"script_keys.script_key_id "+
			"WHERE assets.asset_id = $2",
		transferID, dbID,
	)
	require.NoError(t, err)

	return transferID
}

// TestPorterAbandonmentSuccessorPassive pins the reference-shedding
// contract for a re-org that abandons a transfer whose output a later
// transfer has since adopted as a passive holding.
//
// Abandonment deletes the asset rows its transfer materialized. Four
// tables reference assets(asset_id); three are shed first
// (addr_event_proofs, asset_witnesses, asset_proofs). The fourth,
// passive_assets, carries a NOT NULL reference with no ON DELETE, so a
// surviving row makes the delete a constraint violation — and because
// compensation runs inside the watcher's delivery transaction, the
// violation rolls back the phase acknowledgement along with it. The
// anchoring then retries the same failing delivery forever, leaving
// the inputs spent, the outputs materialized and the leases held: the
// precise state abandonment exists to unwind.
//
// The receive and mint compensations owe the same guarantee; see
// TestAnchoredSuccessorPassive.
func TestPorterAbandonmentSuccessorPassive(t *testing.T) {
	t.Parallel()

	f := newContractFixture(t)
	ctx := context.Background()

	rapid.Check(t, func(rt *rapid.T) {
		w := genContractWorld(rt, t, f)

		// The shape only exists if the world materialized at least
		// one output for a successor to adopt.
		if len(w.outputDBIDs) == 0 {
			return
		}

		adopted := w.outputDBIDs[0]
		f.addSuccessorPassive(t, adopted)

		err := f.executor.ExecTx(
			ctx, WriteTxOption(), func(q *sqlc.Queries) error {
				return f.assetsStore.ApplyTransferAbandonment(
					ctx, q, w.anchorTxid, nil,
				)
			},
		)
		require.NoError(
			rt, err,
			"abandonment must shed the successor's passive "+
				"reference to asset %d before deleting it; "+
				"it runs inside the delivery transaction, so "+
				"failing here wedges the anchoring forever",
			adopted,
		)
	})
}

// TestReceiveReorgLadderContract drives generated worlds through
// generated re-org ladders on the receive site, asserting totality,
// convergence, scope and freshness at every rung.
func TestReceiveReorgLadderContract(t *testing.T) {
	t.Parallel()

	f := newContractFixture(t)
	ctx := context.Background()

	rapid.Check(t, func(rt *rapid.T) {
		w := genContractWorld(rt, t, f)
		ladder := genReorgLadder(rt)

		reconfirm := func(hash chainhash.Hash, height uint32,
			header wire.BlockHeader,
			merkle proof.TxMerkleProof) error {

			return f.executor.ExecTx(
				ctx, WriteTxOption(),
				func(q *sqlc.Queries) error {
					return f.assetsStore.
						ApplyReceiveReconfirm(
							ctx, q, w.anchorTxid,
							hash, height, 0,
							header, merkle,
						)
				},
			)
		}
		unconfirm := func() error {
			return f.executor.ExecTx(
				ctx, WriteTxOption(),
				func(q *sqlc.Queries) error {
					return f.assetsStore.
						ApplyReceiveUnconfirm(
							ctx, q, w.anchorTxid,
						)
				},
			)
		}
		detected := int16(address.StatusTransactionDetected)
		abandon := func() error {
			return f.executor.ExecTx(
				ctx, WriteTxOption(),
				func(q *sqlc.Queries) error {
					return f.assetsStore.
						ApplyReceiveAbandonment(
							ctx, q, w.anchorTxid,
							detected,
						)
				},
			)
		}

		// The passive holdings' stamps before the ladder runs. They
		// are staked by the porter's transfer, so no receive rung
		// may move them.
		passiveBefore := make(map[int64]chainhash.Hash)
		for _, dbID := range w.passiveDBIDs {
			hash, _, _ := f.tipStamp(rt, dbID)
			passiveBefore[dbID] = hash
		}

		numEvents := f.eventsWithStatus(
			rt, w.anchorTxid, address.StatusCompleted,
		)

		abandoned := false

		for i, rung := range ladder {
			where := fmt.Sprintf("rung %d", i)

			switch rung.kind {
			case rungReconfirm:
				hash, header, merkle := blockContextFor(
					t, w.anchorTx, rung.nonce,
				)

				// Totality, and convergence: the rung is
				// applied twice at every depth.
				require.NoError(
					rt, reconfirm(
						hash, rung.height, header,
						merkle,
					), where,
				)
				require.NoError(
					rt, reconfirm(
						hash, rung.height, header,
						merkle,
					), where+" redelivered",
				)

				require.Equal(
					rt, hash[:],
					f.chainConfirmed(rt, w.anchorTxid),
					"%s: chain row not re-confirmed",
					where,
				)

				// A certification delivered after the loss
				// re-confirms the chain row, as asserted
				// above, and nothing else: the withdrawn
				// assets stay withdrawn and no receive is
				// completed again.
				if abandoned {
					f.assertOutputsWithdrawn(rt, w, where)
					require.Zero(
						rt, f.completedEvents(
							rt, w.anchorTxid,
						),
						"%s: a receive was completed "+
							"again after the loss",
						where,
					)

					break
				}

				// Freshness and scope. Only assets the
				// receive staked are re-stamped.

				for _, dbID := range w.outputDBIDs {
					got, height, num := f.tipStamp(
						rt, dbID,
					)
					require.Equal(
						rt, hash, got,
						"%s: asset %d carries a "+
							"stale block hash",
						where, dbID,
					)
					require.Equal(
						rt, rung.height, height,
						"%s: asset %d carries a "+
							"stale height",
						where, dbID,
					)
					require.Equal(
						rt, 1, num,
						"%s: asset %d proof file "+
							"grew; the re-stamp "+
							"appended instead of "+
							"replacing",
						where, dbID,
					)
				}

			case rungUnconfirm:
				require.NoError(rt, unconfirm(), where)
				require.NoError(
					rt, unconfirm(),
					where+" redelivered",
				)

				require.Nil(
					rt,
					f.chainConfirmed(rt, w.anchorTxid),
					"%s: confirmation not withdrawn",
					where,
				)

				// A downgrade after the loss withdraws the
				// confirmation and nothing else.
				if abandoned {
					f.assertOutputsWithdrawn(rt, w, where)
					require.Zero(
						rt, f.completedEvents(
							rt, w.anchorTxid,
						),
						"%s: a receive was completed "+
							"again after the loss",
						where,
					)
				}

			case rungAbandon:
				require.NoError(rt, abandon(), where)
				require.NoError(
					rt, abandon(), where+" redelivered",
				)
				abandoned = true

				// The compensation in full: the receive's
				// stake is withdrawn, the events are reset
				// and the confirmation is gone.
				f.assertReceiveCompensated(
					rt, w, numEvents, where,
				)

			default:
				rt.Fatalf("unhandled rung kind %d", rung.kind)
			}

			// Scope, checked after every rung rather than only
			// at the end: a passive holding's stamp is the
			// porter's, and no receive rung may move it.
			for dbID, before := range passiveBefore {
				got, _, _ := f.tipStamp(rt, dbID)
				require.Equal(
					rt, before, got,
					"%s: re-stamped passive asset %d, "+
						"which the receive never "+
						"staked", where, dbID,
				)
			}
		}
	})
}

// TestAnchoredSuccessorPassive asserts that a holding a receive (or a
// mint) materialized stays that transaction's to converge after a
// successor transfer has staked it as a passive holding. Passive
// references are written before the successor broadcasts, so while
// the successor is unconfirmed the asset row still sits at the
// materializing transaction's output, carrying that transaction's
// proof at its tip, with a passive_assets row from the successor
// pointing at it.
//
// Two things follow. A re-confirmation of the materializing
// transaction must re-stamp that proof: it is the tip the successor's
// own proof will be appended to, and a stale block header there fails
// verification downstream. And an abandonment must delete the row —
// the holding was materialized by a transaction the chain discarded,
// so on the surviving chain it never existed — shedding the
// successor's reference first, since passive_assets.asset_id is a
// NOT NULL reference with no ON DELETE and the delivery transaction
// would otherwise fail and retry forever. A passive reference from
// the transaction's own transfer is a different matter: that marks a
// pre-existing holding the transfer carried along, restored by the
// porter's compensation, and the world's own passives pin that it is
// left alone.
func TestAnchoredSuccessorPassive(t *testing.T) {
	t.Parallel()

	f := newContractFixture(t)
	ctx := context.Background()

	rapid.Check(t, func(rt *rapid.T) {
		w := genContractWorld(rt, t, f)

		// The shape only exists if the world materialized at least
		// one output for a successor to adopt.
		if len(w.outputDBIDs) == 0 {
			return
		}

		adopted := w.outputDBIDs[0]
		f.addSuccessorPassive(t, adopted)

		// The mint body reuses the receive's re-stamp and owns a
		// compensation of the same shape, minus the address events
		// a mint never has; it is driven on worlds without them.
		viaMint := len(w.eventDBIDs) == 0 &&
			rapid.Bool().Draw(rt, "viaMint")
		rawBatchKey := bytes.Repeat([]byte{0x02}, 33)
		resetStatus := int16(address.StatusTransactionDetected)

		// Freshness: a re-confirmation re-stamps the adopted
		// holding along with the rest of the transaction's
		// outputs, and leaves the world's own passives alone.
		hash, header, merkle := blockContextFor(t, w.anchorTx, 77)
		passiveBefore := make(map[int64]chainhash.Hash)
		for _, dbID := range w.passiveDBIDs {
			before, _, _ := f.tipStamp(rt, dbID)
			passiveBefore[dbID] = before
		}
		err := f.executor.ExecTx(
			ctx, WriteTxOption(), func(q *sqlc.Queries) error {
				_, err := f.assetsStore.ApplyReceiveReconfirm(
					ctx, q, w.anchorTxid, hash, 777, 0,
					header, merkle,
				)
				return err
			},
		)
		require.NoError(rt, err)

		got, height, _ := f.tipStamp(rt, adopted)
		require.Equal(
			rt, hash, got,
			"successor-staked asset %d carries a stale block "+
				"hash after re-confirmation", adopted,
		)
		require.EqualValues(rt, 777, height)
		for dbID, before := range passiveBefore {
			got, _, _ := f.tipStamp(rt, dbID)
			require.Equal(
				rt, before, got,
				"re-stamped passive asset %d, which the "+
					"transaction's own transfer carried",
				dbID,
			)
		}

		// Totality and scope: abandonment deletes the adopted
		// holding, successor reference and all, and leaves the
		// world's own passives alone.
		abandon := func() error {
			return f.executor.ExecTx(
				ctx, WriteTxOption(),
				func(q *sqlc.Queries) error {
					var err error
					if viaMint {
						_, err = f.assetsStore.
							ApplyMintAbandonment(
								ctx, q,
								w.anchorTxid,
								rawBatchKey,
							)
					} else {
						_, err = f.assetsStore.
							ApplyReceiveAbandonment(
								ctx, q,
								w.anchorTxid,
								resetStatus,
							)
					}
					return err
				},
			)
		}
		require.NoError(
			rt, abandon(),
			"abandonment must shed the successor's passive "+
				"reference to asset %d before deleting it; "+
				"it runs inside the delivery transaction, so "+
				"failing here wedges the anchoring forever",
			adopted,
		)

		live := f.liveAssets(rt, w.assetDBIDs)
		require.False(
			rt, live[adopted],
			"abandonment left successor-staked asset %d, "+
				"anchored at an outpoint the chain discarded",
			adopted,
		)
		for _, dbID := range w.passiveDBIDs {
			require.True(
				rt, live[dbID],
				"abandonment deleted passive asset %d, which "+
					"the transaction's own transfer "+
					"carried", dbID,
			)
		}

		// Convergence.
		require.NoError(rt, abandon(), "redelivered abandonment failed")
		require.Equal(rt, live, f.liveAssets(rt, w.assetDBIDs))
	})
}
