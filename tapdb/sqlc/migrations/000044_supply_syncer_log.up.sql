-- Table to track the latest synced block height for supply syncers per asset
-- group.
CREATE TABLE supply_syncer_log (
    id INTEGER PRIMARY KEY,

    -- The tweaked group key identifying the asset group this sync log belongs
    -- to. This should match the group_key format used in universe_supply_roots.
    group_key BLOB UNIQUE NOT NULL CHECK(length(group_key) = 33),

    -- The latest block height that has been successfully synced for this asset
    -- group.
    latest_sync_block_height INTEGER NOT NULL
);

-- Add index for frequent lookups by group key.
CREATE INDEX supply_syncer_log_group_key_idx ON supply_syncer_log(group_key);