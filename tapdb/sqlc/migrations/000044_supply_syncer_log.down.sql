-- Drop the supply_syncer_log table and its index.
DROP INDEX IF EXISTS supply_syncer_log_group_key_idx;
DROP TABLE IF EXISTS supply_syncer_log;