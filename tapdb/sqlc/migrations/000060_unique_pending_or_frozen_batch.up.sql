-- Enforce that at most one minting batch is in a pre-broadcast state
-- (BatchStatePending = 0 or BatchStateFrozen = 1) at any time. This
-- matches the planter's in-memory model, which assumes a single
-- "current" pre-broadcast batch in flight. Older versions of the
-- planter could in some failure scenarios desync the in-memory slot
-- from disk and leave two pre-broadcast rows behind; this index
-- makes that state unrepresentable going forward.
--
-- The unique index targets the constant expression `(1)`, which
-- means "at most one row total" among rows matching the WHERE
-- filter. The syntax is dialect-agnostic across SQLite and
-- Postgres.
--
-- This is a deliberate design choice rather than a fundamental
-- limit. If multi-batch support is ever added to the planter,
-- drop this index and revisit the planter API and recovery loop
-- alongside that change.
CREATE UNIQUE INDEX IF NOT EXISTS
    asset_minting_batches_unique_pending_or_frozen
    ON asset_minting_batches ((1))
    WHERE batch_state IN (0, 1);
