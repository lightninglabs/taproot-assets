DROP INDEX IF EXISTS supply_update_events_event_key_idx;
ALTER TABLE supply_update_events DROP COLUMN event_key;
