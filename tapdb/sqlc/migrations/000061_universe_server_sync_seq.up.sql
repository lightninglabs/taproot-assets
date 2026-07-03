-- The delta sync cursor: the highest insertion sequence number of the
-- remote server's universe_leaves table that we have fully applied and
-- verified. Zero means no delta sync has completed yet, in which case
-- the next sync starts from the beginning (bootstrap).
ALTER TABLE universe_servers
    ADD COLUMN last_sync_seq BIGINT NOT NULL DEFAULT 0;
