-- Table to track supply commitment pushes to remote universe servers.
CREATE TABLE supply_syncer_push_log (
    id INTEGER PRIMARY KEY,

    -- The tweaked group key identifying the asset group this push log belongs
    -- to. This should match the group_key format used in universe_supply_roots.
    group_key BLOB NOT NULL CHECK(length(group_key) = 33),

    -- The highest block height among all supply leaves in this push.
    max_pushed_block_height INTEGER NOT NULL,

    -- The server address (host:port) where the commitment was pushed.
    server_address TEXT NOT NULL,

    -- The transaction ID (hash) of the supply commitment.
    commit_txid BLOB NOT NULL CHECK(length(commit_txid) = 32),

    -- The supply commitment output index within the commitment transaction.
    output_index INTEGER NOT NULL,

    -- The number of leaves included in this specific push (diff count between
    -- last commitment and current commitment).
    num_leaves_pushed INTEGER NOT NULL,

    -- The timestamp when this push log entry was created (unix timestamp in seconds).
    created_at BIGINT NOT NULL
);

-- Add index for frequent lookups by group key.
CREATE INDEX supply_syncer_push_log_group_key_idx
    ON supply_syncer_push_log(group_key);

-- Add index for lookups by server address.
CREATE INDEX supply_syncer_push_log_server_address_idx
    ON supply_syncer_push_log(server_address);

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

-- The outpoint of a supply commitment must be unique. Because we don't have a
-- separate field for the outpoint, we create a unique index over the chain
-- transaction ID and output index. This ensures that each commitment can be
-- uniquely identified by its transaction and output index, preventing
-- duplicate commitments for the same output.
CREATE UNIQUE INDEX supply_commitments_outpoint_uk
    ON supply_commitments(chain_txn_id, output_index);
