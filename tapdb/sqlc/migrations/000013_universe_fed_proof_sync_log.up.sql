-- This table stores the log of federation universe proof sync attempts. Rows
-- in this table are specific to a given proof leaf, server, and sync direction.
CREATE TABLE IF NOT EXISTS federation_proof_sync_log (
    id BIGINT PRIMARY KEY,

    -- The status of the proof sync attempt.
    status TEXT NOT NULL CHECK(status IN ('pending', 'complete')),

    -- The timestamp of when the log entry for the associated proof was last
    -- updated.
    timestamp TIMESTAMP NOT NULL,

    -- The number of attempts that have been made to sync the proof.
    attempt_counter BIGINT NOT NULL DEFAULT 0,

    -- The direction of the proof sync attempt.
    sync_direction TEXT NOT NULL CHECK(sync_direction IN ('push', 'pull')),

    -- The ID of the subject proof leaf.
    proof_leaf_id BIGINT NOT NULL REFERENCES universe_leaves(id),

    -- The ID of the universe that the proof leaf belongs to.
    universe_root_id BIGINT NOT NULL REFERENCES universe_roots(id),

    -- The ID of the server that the proof will be/was synced to.
    servers_id BIGINT NOT NULL REFERENCES universe_servers(id)
);

-- Create a unique index on table federation_proof_sync_log
CREATE UNIQUE INDEX federation_proof_sync_log_unique_index_proof_leaf_id_servers_id
ON federation_proof_sync_log (
    sync_direction,
    proof_leaf_id,
    universe_root_id,
    servers_id
);