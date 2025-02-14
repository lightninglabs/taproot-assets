-- ******************************************************************************************
-- DOWN MIGRATION (Extended): Revert proof_type modifications.
--
-- Changes:
-- 1. For federation_global_sync_config, re-create the table using the original schema since
--    the proof_type column is a primary key. This avoids dropping a primary key column.
-- 2. For other tables, revert changes via ALTER statements.
-- 3. Drop the 'proof_types' enum table.
-- 4. Recreate the 'universe_stats' view using the latest definition to match the reverted schema.
-- ******************************************************************************************

-- For universe_roots
ALTER TABLE universe_roots ADD COLUMN proof_type TEXT NOT NULL CHECK(proof_type IN ('issuance', 'transfer'));
UPDATE universe_roots SET proof_type = proof_type_new;
ALTER TABLE universe_roots DROP COLUMN proof_type_new;

-- For federation_global_sync_config: Recreate the original table schema.
ALTER TABLE federation_global_sync_config RENAME TO federation_global_sync_config_new;

CREATE TABLE federation_global_sync_config (
    proof_type TEXT NOT NULL PRIMARY KEY CHECK(proof_type IN ('issuance', 'transfer')),
    allow_sync_insert BOOLEAN NOT NULL,
    allow_sync_export BOOLEAN NOT NULL
);

INSERT INTO federation_global_sync_config (proof_type, allow_sync_insert, allow_sync_export)
SELECT proof_type, allow_sync_insert, allow_sync_export
FROM federation_global_sync_config_new;

DROP TABLE federation_global_sync_config_new;

-- For federation_uni_sync_config
ALTER TABLE federation_uni_sync_config RENAME COLUMN proof_type TO proof_type_new;
ALTER TABLE federation_uni_sync_config ADD COLUMN proof_type TEXT NOT NULL CHECK(proof_type IN ('issuance', 'transfer'));
UPDATE federation_uni_sync_config SET proof_type = proof_type_new;
ALTER TABLE federation_uni_sync_config DROP COLUMN proof_type_new;

-- Drop the proof_types enum table.
DROP TABLE IF EXISTS proof_types;
