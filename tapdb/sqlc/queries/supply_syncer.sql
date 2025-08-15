-- name: UpsertSupplySyncerLog :exec
INSERT INTO supply_syncer_log (
   group_key, max_fetched_block_height, max_inserted_block_height
) VALUES (
  @group_key, @max_fetched_block_height, @max_inserted_block_height
)
ON CONFLICT (group_key) DO UPDATE SET
    max_fetched_block_height = COALESCE(@max_fetched_block_height, supply_syncer_log.max_fetched_block_height),
    max_inserted_block_height = COALESCE(@max_inserted_block_height, supply_syncer_log.max_inserted_block_height);

-- name: FetchSupplySyncerLog :one
SELECT group_key, max_fetched_block_height, max_inserted_block_height
FROM supply_syncer_log
WHERE group_key = @group_key;

