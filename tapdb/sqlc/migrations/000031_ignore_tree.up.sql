-- Migration 30: Update UNIQUE constraint on universe_leaves table.
-- =================================================================
--
-- OVERVIEW:
--
-- This migration modifies the UNIQUE constraint on the universe_leaves table
-- to allow assets to exist in multiple universe trees simultaneously. We change
-- from a two-column constraint (minting_point, script_key_bytes) to a three-column
-- constraint (minting_point, script_key_bytes, leaf_node_namespace).
--
-- PROBLEM STATEMENT:
--
-- In the current schema, the universe_leaves table enforces uniqueness based on
-- minting_point and script_key_bytes. This design assumes an asset belongs to only
-- one type of universe tree (transfer or issuance). However, with the introduction
-- of "ignore" and "burn" universe trees, the same asset might need to exist in
-- multiple trees simultaneously.
--
-- SOLUTION:
--
-- We expand the unique constraint to include the leaf_node_namespace column. This
-- additional dimension allows distinguishing between assets based on which universe
-- tree they belong to, while still preventing duplicates within the same tree.
--
-- MIGRATION STRATEGY:
--
-- Since SQLite has limited ALTER TABLE capabilities and we need to maintain
-- compatibility with both SQLite and PostgreSQL, we use a table recreation approach:
--
-- 1. Handle foreign key dependencies (back up and remove federation_proof_sync_log).
-- 2. Create a new table with the updated constraint.
-- 3. Copy existing data.
-- 4. Replace the old table with the new one.
-- 5. Restore dependent tables with proper references.
--
-- This approach works with both database engines while preserving data integrity.
--

-- ==== PHASE 1: HANDLE FOREIGN KEY DEPENDENCIES ====
-- Before we can drop the universe_leaves table, we need to temporarily remove
-- any foreign key references pointing to it. The federation_proof_sync_log table
-- has a foreign key to universe_leaves.id that would prevent dropping the table.

-- Create a temporary backup table for federation_proof_sync_log.
CREATE TABLE new_federation_proof_sync_log (
    id INTEGER PRIMARY KEY,
    status TEXT NOT NULL CHECK(status IN ('pending', 'complete')),
    timestamp TIMESTAMP NOT NULL,
    attempt_counter BIGINT NOT NULL DEFAULT 0,
    sync_direction TEXT NOT NULL CHECK(sync_direction IN ('push', 'pull')),
    proof_leaf_id BIGINT NOT NULL, -- FK constraint intentionally omitted for now.
    universe_root_id BIGINT NOT NULL REFERENCES universe_roots(id),
    servers_id BIGINT NOT NULL REFERENCES universe_servers(id)
);


-- Backup all existing federation_proof_sync_log data.
INSERT INTO new_federation_proof_sync_log
SELECT * FROM federation_proof_sync_log;

-- Remove the table with the foreign key constraint to universe_leaves.
-- This allows us to safely drop universe_leaves later.
DROP TABLE federation_proof_sync_log;
DROP INDEX IF EXISTS federation_proof_sync_log_unique_index_proof_leaf_id_servers_id;

-- ==== PHASE 2: CREATE NEW TABLE WITH UPDATED CONSTRAINT ====
-- Create a new universe_leaves table with the enhanced 3-column unique constraint.
CREATE TABLE new_universe_leaves (
    id INTEGER PRIMARY KEY,
    asset_genesis_id BIGINT NOT NULL REFERENCES genesis_assets(gen_asset_id),
    minting_point BLOB NOT NULL,
    script_key_bytes BLOB NOT NULL CHECK(LENGTH(script_key_bytes) = 32),
    universe_root_id BIGINT NOT NULL REFERENCES universe_roots(id),
    leaf_node_key BLOB,
    leaf_node_namespace VARCHAR NOT NULL
);

-- Create the named unique index separately. This way it can be dropped later
-- and we won't need as involved migrations in the future.
CREATE UNIQUE INDEX universe_leaves_unique_minting_script_namespace ON new_universe_leaves(minting_point, script_key_bytes, leaf_node_namespace);

-- ==== PHASE 3: MIGRATE DATA ====
-- Copy all existing data from the original table to the new one.
INSERT INTO new_universe_leaves (
    id,
    asset_genesis_id,
    minting_point,
    script_key_bytes,
    universe_root_id,
    leaf_node_key,
    leaf_node_namespace
)
SELECT
    id,
    asset_genesis_id,
    minting_point,
    script_key_bytes,
    universe_root_id,
    leaf_node_key,
    leaf_node_namespace
FROM universe_leaves;

-- ==== PHASE 4: TABLE REPLACEMENT ====
-- Now that data is safely copied, remove the old table.
DROP TABLE universe_leaves;

-- Rename the new table to replace the old one.
ALTER TABLE new_universe_leaves RENAME TO universe_leaves;

-- Recreate indexes that existed on the original table.
CREATE INDEX IF NOT EXISTS universe_leaves_key_idx ON universe_leaves(leaf_node_key);
CREATE INDEX IF NOT EXISTS universe_leaves_namespace ON universe_leaves(leaf_node_namespace);

-- ==== PHASE 5: RESTORE DEPENDENT TABLES ====
-- Recreate the federation_proof_sync_log table with proper foreign key references.
CREATE TABLE federation_proof_sync_log (
    id INTEGER PRIMARY KEY,

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

-- Restore valid federation_proof_sync_log data.
-- Only reinsert records that reference existing leaves in the universe_leaves table.
INSERT INTO federation_proof_sync_log
SELECT * FROM new_federation_proof_sync_log
WHERE proof_leaf_id IN (SELECT id FROM universe_leaves);

-- Clean up by dropping the temporary table.
DROP TABLE new_federation_proof_sync_log;

-- Re-create the unique index on table new_federation_proof_sync_log.
CREATE UNIQUE INDEX federation_proof_sync_log_unique_index_proof_leaf_id_servers_id
ON federation_proof_sync_log (
    sync_direction,
    proof_leaf_id,
    universe_root_id,
    servers_id
);
