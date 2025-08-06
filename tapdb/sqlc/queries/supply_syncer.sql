-- name: UpsertSupplySyncerLog :exec
INSERT INTO supply_syncer_log (group_key, latest_sync_block_height)
VALUES (@group_key, @latest_sync_block_height)
ON CONFLICT (group_key)
    DO UPDATE SET latest_sync_block_height = EXCLUDED.latest_sync_block_height;

-- name: FetchSupplySyncerLog :one
SELECT group_key, latest_sync_block_height
FROM supply_syncer_log
WHERE group_key = @group_key;
