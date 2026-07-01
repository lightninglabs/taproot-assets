-- Down-migrating past 62 is destructive: migration 63's backfill
-- physically deletes any legacy duplicate supply_update_events rows
-- to satisfy the unique index this migration adds. Dropping the
-- column and index here does not restore those rows. Re-upgrading
-- after a down-migration re-runs the (idempotent, but non-recovering)
-- backfill against whatever rows remain.
DROP INDEX IF EXISTS supply_update_events_event_key_idx;
ALTER TABLE supply_update_events DROP COLUMN event_key;
