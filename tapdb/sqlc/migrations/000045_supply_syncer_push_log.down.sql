-- Drop the supply_syncer_push_log table and its indexes.
DROP INDEX IF EXISTS supply_syncer_push_log_server_address_idx;
DROP INDEX IF EXISTS supply_syncer_push_log_group_key_idx;
DROP TABLE IF EXISTS supply_syncer_push_log;

-- Drop supply_commitments changes.
DROP INDEX IF EXISTS supply_commitments_outpoint_uk;
DROP INDEX IF EXISTS supply_commitments_spent_commitment_idx;

ALTER TABLE supply_commitments
    DROP COLUMN spent_commitment;
