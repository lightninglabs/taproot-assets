-- Add a content-hash column that uniquely identifies a supply update
-- event by group, type, and payload bytes. The hash is computed as
-- sha256(group_key || big_endian(update_type_id) || event_data); we
-- hash rather than indexing event_data directly because event_data
-- holds a serialized issuance proof which can exceed the Postgres
-- BTREE indexed-tuple size limit.
--
-- The column is nullable in this migration so it applies cleanly to
-- existing DBs. Migration 000062 backfills the rows that pre-date
-- this column (SQLite has no native SHA-256 so the backfill is a
-- programmatic step). New inserts must always provide a value.
ALTER TABLE supply_update_events
    ADD COLUMN event_key BLOB
        CHECK(event_key IS NULL OR length(event_key) = 32);

-- The unique index covers all rows, but SQLite and Postgres both
-- treat NULL as distinct from every other NULL in a UNIQUE index,
-- so pre-backfill rows do not collide with one another. After
-- migration 000062 every row holds a hash and the index enforces
-- dedup across the whole table.
CREATE UNIQUE INDEX IF NOT EXISTS supply_update_events_event_key_idx
    ON supply_update_events(event_key);
