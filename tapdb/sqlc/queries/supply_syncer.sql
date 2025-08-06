-- name: InsertSupplySyncerPushLog :exec
-- Inserts a new push log entry to track a successful supply commitment
-- push to a remote universe server. The commit_txid and output_index are
-- taken directly from the RootCommitment outpoint.
INSERT INTO supply_syncer_push_log (
    group_key, max_pushed_block_height, server_address, 
    commit_txid, output_index, num_leaves_pushed, created_at
) VALUES (
    @group_key, @max_pushed_block_height, @server_address,
    @commit_txid, @output_index, @num_leaves_pushed, @created_at
);

-- name: FetchSupplySyncerPushLogs :many
-- Fetches all push log entries for a given asset group, ordered by
-- creation time with the most recent entries first.
SELECT id, group_key, max_pushed_block_height, server_address,
       commit_txid, output_index, num_leaves_pushed, created_at
FROM supply_syncer_push_log 
WHERE group_key = @group_key
ORDER BY created_at DESC;
