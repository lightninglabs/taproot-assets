-- Enforce that at most one minting batch is in a pre-broadcast state
-- (BatchStatePending = 0 or BatchStateFrozen = 1) at any time. This
-- matches the planter's in-memory model, which assumes a single
-- "current" pre-broadcast batch in flight. Older versions of the
-- planter could in some failure scenarios desync the in-memory slot
-- from disk and leave two pre-broadcast rows behind; this migration
-- makes that state unrepresentable going forward.
--
-- Legacy databases may already violate the invariant. Rather than
-- fail here with an opaque unique-index error and force the operator
-- into a manual repair step, cancel all but the most recent
-- pre-broadcast batch first. The preserved row is the one with the
-- latest creation_time_unix (tie-broken by batch_id) so the outcome
-- is deterministic on identical timestamps. Cancelled rows move to
-- BatchStateSeedlingCancelled = 6, which leaves them and their
-- seedlings on disk for later inspection.
UPDATE asset_minting_batches
SET batch_state = 6
WHERE batch_state IN (0, 1)
  AND batch_id NOT IN (
      SELECT batch_id
      FROM asset_minting_batches
      WHERE batch_state IN (0, 1)
      ORDER BY creation_time_unix DESC, batch_id DESC
      LIMIT 1
  );

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
