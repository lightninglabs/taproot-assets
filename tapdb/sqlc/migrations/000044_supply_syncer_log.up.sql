-- Table to track the latest synced block height for supply syncers per asset
-- group.
CREATE TABLE supply_syncer_log (
    id INTEGER PRIMARY KEY,

    -- The tweaked group key identifying the asset group this sync log belongs
    -- to. This should match the group_key format used in universe_supply_roots.
    group_key BLOB NOT NULL CHECK(length(group_key) = 33),

    -- The highest block height among all supply leaves fetched so far
    -- for this asset group during syncing. If NULL, no leaves have been
    -- fetched yet.
    max_fetched_block_height INTEGER,

    -- The highest block height among all supply leaves inserted so far
    -- into the canonical universe for this asset group. If NULL, no leaves
    -- have been inserted yet.
    max_inserted_block_height INTEGER
);

-- Add index for frequent lookups by group key.
CREATE UNIQUE INDEX supply_syncer_log_group_key_idx
    ON supply_syncer_log(group_key);

-- A nullable column to track the previous supply commitment that was spent to
-- create a new supply commitment. This is only NULL for the very first
-- commitment of an asset group, each subsequent commitment needs to spend a
-- prior commitment to ensure continuity in the supply chain.
ALTER TABLE supply_commitments
    ADD COLUMN spent_commitment BIGINT
        REFERENCES supply_commitments(commit_id);

-- Add an index to speed up lookups by spent commitment.
CREATE INDEX supply_commitments_spent_commitment_idx
    ON supply_commitments(spent_commitment);

-- We also add an index on the output index of the supply commitment to speed
-- up lookups of commitments by outpoint (will need a join over chain_txns).
CREATE INDEX supply_commitments_output_index_idx
    ON supply_commitments(output_index);
