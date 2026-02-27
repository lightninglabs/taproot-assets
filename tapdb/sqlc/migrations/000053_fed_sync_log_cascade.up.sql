-- Add ON DELETE CASCADE to federation_proof_sync_log FKs that
-- reference universe_leaves(id) and universe_roots(id).
--
-- SQLite cannot ALTER constraints, so we recreate the table.

-- Step 1: Create replacement table with CASCADE constraints.
CREATE TABLE new_federation_proof_sync_log (
    id INTEGER PRIMARY KEY,

    status TEXT NOT NULL CHECK(
        status IN ('pending', 'complete')
    ),

    timestamp TIMESTAMP NOT NULL,

    attempt_counter BIGINT NOT NULL DEFAULT 0,

    sync_direction TEXT NOT NULL CHECK(
        sync_direction IN ('push', 'pull')
    ),

    proof_leaf_id BIGINT NOT NULL
        REFERENCES universe_leaves(id) ON DELETE CASCADE,

    universe_root_id BIGINT NOT NULL
        REFERENCES universe_roots(id) ON DELETE CASCADE,

    servers_id BIGINT NOT NULL
        REFERENCES universe_servers(id)
);

-- Step 2: Copy existing data.
INSERT INTO new_federation_proof_sync_log
SELECT * FROM federation_proof_sync_log;

-- Step 3: Drop old table and its unique index.
DROP INDEX IF EXISTS federation_proof_sync_log_unique_index_proof_leaf_id_servers_id;
DROP TABLE federation_proof_sync_log;

-- Step 4: Rename new table.
ALTER TABLE new_federation_proof_sync_log
    RENAME TO federation_proof_sync_log;

-- Step 5: Recreate unique index.
CREATE UNIQUE INDEX federation_proof_sync_log_unique_index_proof_leaf_id_servers_id
ON federation_proof_sync_log (
    sync_direction,
    proof_leaf_id,
    universe_root_id,
    servers_id
);
