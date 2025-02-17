-- ******************************************************************************************
-- UP MIGRATION: Expanding Allowed Proof Types with an Enum-Style Reference Column
--
-- In this migration, we expand the allowed values for the "proof_type" column in our
-- universe-related tables by introducing a new enum-like table ("proof_types").
--
-- Changes introduced:
--   1. Create a new table "proof_types" that stores valid proof type values:
--         'issuance', 'transfer', 'burn', 'ignore'.
--   2. For each affected table (universe_roots, federation_global_sync_config, 
--      federation_uni_sync_config):
--         a) Add a new column "proof_type_ext" with a NOT NULL constraint and a foreign 
--            key reference to proof_types(proof_type).
--         b) Copy the data from the existing "proof_type" column into "proof_type_ext".
--         c) Rename the original "proof_type" to "proof_type_old".
--         d) Rename "proof_type_ext" to "proof_type" so that the final column name remains 
--            unchanged.
--         e) Drop the temporary "proof_type_old" column.
--
-- This approach preserves existing data while allowing new rows to use the expanded set
-- of proof types. 
-- ******************************************************************************************

--------------------------------------------------------------------------------------------
-- Section 1: Drop Dependent Views
-- Drop the universe_stats view so that subsequent schema modifications on
-- columns referenced in the view do not cause errors.
--------------------------------------------------------------------------------------------
DROP VIEW IF EXISTS universe_stats;

--------------------------------------------------------------------------------------------
-- Section 2: Create Enum Table for Proof Types
-- Create a new table "proof_types" to hold the allowed values for the proof type field.
-- Insert the allowed values.
--------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS proof_types (
    proof_type TEXT PRIMARY KEY
);

INSERT INTO proof_types (proof_type) VALUES ('issuance');
INSERT INTO proof_types (proof_type) VALUES ('transfer');
INSERT INTO proof_types (proof_type) VALUES ('burn');
INSERT INTO proof_types (proof_type) VALUES ('ignore');

--------------------------------------------------------------------------------------------
-- Section 3: Update the universe_roots Table
-- a) Add a new column "proof_type_ext" that references proof_types.
-- b) Copy over existing data from proof_type.
-- c) Drop any composite index that depends on the old proof_type column.
-- d) Drop the old proof_type column, and rename proof_type_ext to proof_type.
-- e) Recreate the composite index.
--------------------------------------------------------------------------------------------
ALTER TABLE universe_roots 
    ADD COLUMN proof_type_ext TEXT REFERENCES proof_types(proof_type);
UPDATE universe_roots
    SET proof_type_ext = proof_type;

DROP INDEX IF EXISTS idx_universe_roots_composite;

ALTER TABLE universe_roots DROP COLUMN proof_type;
ALTER TABLE universe_roots RENAME COLUMN proof_type_ext TO proof_type;

CREATE INDEX idx_universe_roots_composite ON universe_roots(namespace_root, proof_type, asset_id);

--------------------------------------------------------------------------------------------
-- Section 4: Update the federation_global_sync_config Table
-- Since the proof_type column here is a primary key, we cannot drop it directly.
-- Therefore, we rename the existing table, create a new table with the updated schema,
-- copy the data over, and drop the old table.
--------------------------------------------------------------------------------------------
ALTER TABLE federation_global_sync_config RENAME TO federation_global_sync_config_old;

CREATE TABLE federation_global_sync_config (
    proof_type TEXT NOT NULL PRIMARY KEY REFERENCES proof_types(proof_type),
    allow_sync_insert BOOLEAN NOT NULL,
    allow_sync_export BOOLEAN NOT NULL
);

INSERT INTO federation_global_sync_config (proof_type, allow_sync_insert, allow_sync_export)
SELECT proof_type, allow_sync_insert, allow_sync_export
FROM federation_global_sync_config_old;

DROP TABLE federation_global_sync_config_old;

--------------------------------------------------------------------------------------------
-- Section 5: Update the federation_uni_sync_config Table
-- Add a new column ("proof_type_ext"), copy old data, then rename columns to finalize changes.
--------------------------------------------------------------------------------------------
ALTER TABLE federation_uni_sync_config 
    ADD COLUMN proof_type_ext TEXT REFERENCES proof_types(proof_type);
UPDATE federation_uni_sync_config
    SET proof_type_ext = proof_type;

ALTER TABLE federation_uni_sync_config RENAME COLUMN proof_type TO proof_type_old;
ALTER TABLE federation_uni_sync_config RENAME COLUMN proof_type_ext TO proof_type;
ALTER TABLE federation_uni_sync_config DROP COLUMN proof_type_old;

--------------------------------------------------------------------------------------------
-- Section 6: Re-create the universe_stats View 
-- Rebuild the view using the latest definition (from 000027_better_universe_stats.up.sql)
-- so that downstream queries see the updated schema for universe_roots.
--------------------------------------------------------------------------------------------
CREATE VIEW universe_stats AS
WITH sync_counts AS (
    SELECT universe_root_id, COUNT(*) AS count
    FROM universe_events
    WHERE event_type = 'SYNC'
    GROUP BY universe_root_id
), proof_counts AS (
    SELECT universe_root_id, event_type, COUNT(*) AS count
    FROM universe_events
    WHERE event_type = 'NEW_PROOF'
    GROUP BY universe_root_id, event_type
), aggregated AS (
    SELECT COALESCE(SUM(count), 0) as total_asset_syncs,
           0 AS total_asset_proofs,
           universe_root_id
    FROM sync_counts
    GROUP BY universe_root_id
    UNION ALL
    SELECT 0 AS total_asset_syncs,
           COALESCE(SUM(count), 0) as total_asset_proofs,
           universe_root_id
    FROM proof_counts
    GROUP BY universe_root_id
)
SELECT
    SUM(ag.total_asset_syncs) AS total_asset_syncs,
    SUM(ag.total_asset_proofs) AS total_asset_proofs,
    roots.asset_id,
    roots.group_key,
    roots.proof_type
FROM aggregated ag
JOIN universe_roots roots
    ON ag.universe_root_id = roots.id
GROUP BY roots.asset_id, roots.group_key, roots.proof_type
ORDER BY roots.asset_id, roots.group_key, roots.proof_type;
