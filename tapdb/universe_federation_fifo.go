package tapdb

import (
	"context"
	"database/sql"
	"fmt"
	"sort"

	"github.com/lightninglabs/taproot-assets/universe"
)

// FetchPendingProofsSyncLogFIFO returns pending federation proof pushes in
// insertion order. The federation pusher relies on this order so an anchor
// proof cannot be overtaken by a later reissuance after a retry or restart.
func (u *UniverseFederationDB) FetchPendingProofsSyncLogFIFO(
	ctx context.Context,
	syncDirection *universe.SyncDirection) ([]*universe.ProofSyncLogEntry,
	error) {

	var (
		readTx        = NewUniverseFederationReadTx()
		proofSyncLogs []*universe.ProofSyncLogEntry
	)

	err := u.db.ExecTx(ctx, &readTx, func(db UniverseServerStore) error {
		var sqlSyncDirection sql.NullString
		if syncDirection != nil {
			sqlSyncDirection = sqlStr(string(*syncDirection))
		}

		params := QueryFedProofSyncLogParams{
			SyncDirection: sqlSyncDirection,
			Status: sqlStr(
				string(universe.ProofSyncStatusPending),
			),
		}
		logEntries, err := db.QueryFederationProofSyncLog(ctx, params)
		if err != nil {
			return fmt.Errorf("unable to query proof sync log: %w",
				err)
		}

		// The row ID is allocated when the push is first queued and is
		// not changed by later attempts, making it the durable FIFO key.
		sort.Slice(logEntries, func(i, j int) bool {
			return logEntries[i].ID < logEntries[j].ID
		})

		proofSyncLogs = make(
			[]*universe.ProofSyncLogEntry, 0, len(logEntries),
		)
		for idx := range logEntries {
			entry := logEntries[idx]

			parsedLogEntry, err := fetchProofSyncLogEntry(
				ctx, entry, db,
			)
			if err != nil {
				return err
			}

			proofSyncLogs = append(proofSyncLogs, parsedLogEntry)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return proofSyncLogs, nil
}
