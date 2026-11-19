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

-- name: FetchSupplySyncerPushedServers :many
-- Fetches the addresses of the servers a given supply commitment has
-- already been pushed to, identified by its commitment outpoint. The
-- push log records every successful remote insert, so this is the
-- sender's durable view of which servers already hold the commitment.
SELECT server_address
FROM supply_syncer_push_log
WHERE group_key = @group_key
  AND commit_txid = @commit_txid
  AND output_index = @output_index;
