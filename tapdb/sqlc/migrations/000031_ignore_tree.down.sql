-- Migration 30 Downgrade: Revert UNIQUE constraint on universe_leaves table.
-- =================================================================
--
-- OVERVIEW:
--
-- This downgrade script reverts the changes made in migration 30, rolling back
-- from a three-column UNIQUE constraint (minting_point, script_key_bytes, leaf_node_namespace)
-- to the original two-column constraint (minting_point, script_key_bytes).
--
-- DOWNGRADE STRATEGY:
--
-- Since the enhanced constraint allowed multiple entries with the same minting_point
-- and script_key_bytes (differing only by leaf_node_namespace), we need to be
-- selective about which rows to keep when reverting to the more restrictive constraint.
--
-- This script:
-- 1. Handles foreign key dependencies (backing up federation_proof_sync_log).
-- 2. Creates a new table with the original two-column constraint.
-- 3. Selectively migrates data (keeping only one row per minting_point/script_key_bytes pair).
-- 4. Replaces the current table with the downgraded version.
-- 5. Restores dependent tables with proper references.
--
-- NOTE: This downgrade will result in data loss where multiple universe entries
-- existed for the same asset across different universe trees.
--

-- ==== PHASE 1: HANDLE FOREIGN KEY DEPENDENCIES ====
-- Before we can drop the universe_leaves table, we need to temporarily remove
-- any foreign key references pointing to it.

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

-- ==== PHASE 2: CREATE NEW TABLE WITH ORIGINAL CONSTRAINT ====
-- Create a new table with the original two-column unique constraint.
CREATE TABLE old_universe_leaves (
    id INTEGER PRIMARY KEY,
    asset_genesis_id BIGINT NOT NULL REFERENCES genesis_assets(gen_asset_id),
    minting_point BLOB NOT NULL, 
    script_key_bytes BLOB NOT NULL CHECK(LENGTH(script_key_bytes) = 32),
    universe_root_id BIGINT NOT NULL REFERENCES universe_roots(id),
    leaf_node_key BLOB,
    leaf_node_namespace VARCHAR NOT NULL

    -- The original, more restrictive unique constraint was defined here.
);

-- Create the named unique index separately.
CREATE UNIQUE INDEX universe_leaves_unique_minting_script ON old_universe_leaves(minting_point, script_key_bytes);

-- ==== PHASE 3: SELECTIVE DATA MIGRATION ====
-- Copy data from the current table to the new one, but we must be selective
-- to avoid violating the more restrictive unique constraint.
-- For each (minting_point, script_key_bytes) group, we keep only the row with the lowest ID.
INSERT INTO old_universe_leaves (
    id,
    asset_genesis_id,
    minting_point,
    script_key_bytes,
    universe_root_id,
    leaf_node_key,
    leaf_node_namespace
)
SELECT ul.id,
       ul.asset_genesis_id,
       ul.minting_point,
       ul.script_key_bytes,
       ul.universe_root_id,
       ul.leaf_node_key,
       ul.leaf_node_namespace
FROM universe_leaves ul
JOIN (
    -- This subquery identifies the lowest ID for each unique combination
    -- of minting_point and script_key_bytes.
    SELECT minting_point, script_key_bytes, MIN(id) AS min_id
    FROM universe_leaves
    GROUP BY minting_point, script_key_bytes
) sub ON ul.id = sub.min_id;

-- ==== PHASE 4: TABLE REPLACEMENT ====
-- Remove the current table with the three-column constraint.
DROP TABLE universe_leaves;

-- Rename the new table to replace the existing one.
ALTER TABLE old_universe_leaves RENAME TO universe_leaves;

-- Recreate the indexes that existed on the original table.
CREATE INDEX IF NOT EXISTS universe_leaves_key_idx ON universe_leaves(leaf_node_key);
CREATE INDEX IF NOT EXISTS universe_leaves_namespace ON universe_leaves(leaf_node_namespace);

-- ==== PHASE 5: RESTORE DEPENDENT TABLES ====
-- Recreate the federation_proof_sync_log table with proper foreign key references.
CREATE TABLE federation_proof_sync_log (
    id INTEGER PRIMARY KEY,
    status TEXT NOT NULL CHECK(status IN ('pending', 'complete')),
    timestamp TIMESTAMP NOT NULL,
    attempt_counter BIGINT NOT NULL DEFAULT 0,
    sync_direction TEXT NOT NULL CHECK(sync_direction IN ('push', 'pull')),
    -- Now we can safely reference the new universe_leaves table.
    proof_leaf_id BIGINT NOT NULL REFERENCES universe_leaves(id),
    universe_root_id BIGINT NOT NULL REFERENCES universe_roots(id),
    servers_id BIGINT NOT NULL REFERENCES universe_servers(id)
);

-- Restore federation_proof_sync_log data, but only for leaves that still exist.
-- Some leaves may have been dropped during the selective migration process.
INSERT INTO federation_proof_sync_log
SELECT * FROM new_federation_proof_sync_log
WHERE proof_leaf_id IN (SELECT id FROM universe_leaves);

-- Clean up by dropping the temporary table.
DROP TABLE new_federation_proof_sync_log;
