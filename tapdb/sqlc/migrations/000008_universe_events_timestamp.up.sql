-- event_timestamp is the same as event_time but stored as a Unix timestamp
-- to allow us to do calculations in queries. This is added as a separate
-- field to make this change non-breaking.
ALTER TABLE universe_events ADD COLUMN event_timestamp BIGINT NOT NULL DEFAULT 0;
