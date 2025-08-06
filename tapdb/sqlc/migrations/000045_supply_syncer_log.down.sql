-- Drop the supply_syncer_log table and its index.
DROP INDEX IF EXISTS supply_syncer_log_group_key_idx;
DROP TABLE IF EXISTS supply_syncer_log;

DROP INDEX IF EXISTS supply_commitments_outpoint_uk;
DROP INDEX IF EXISTS supply_commitments_spent_commitment_idx;

ALTER TABLE supply_commitments
    DROP COLUMN spent_commitment;
