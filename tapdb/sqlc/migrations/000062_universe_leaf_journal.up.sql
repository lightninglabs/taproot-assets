-- The universe leaf journal is the append-only insertion log that
-- cursor-based delta sync serves pages from. Its seq values are
-- assigned by the writer from the single-row tail allocator below,
-- inside the same transaction that inserts the leaves, so seq order
-- always equals commit order. A bare BIGSERIAL cannot provide that
-- guarantee on Postgres: sequence values are allocated at INSERT time
-- and are non-transactional, so a row with a higher id can commit
-- before a concurrent transaction holding lower ids does. A delta
-- reader observing such a schedule would advance its cursor past the
-- uncommitted rows and permanently skip them.
--
-- seq values may have gaps (rolled-back transactions, re-upserts of
-- already-journaled leaves); readers order by seq and tolerate gaps.
-- Only issuance and transfer leaves are journaled, matching the
-- domain of federation delta sync.
CREATE TABLE universe_leaf_journal (
    seq BIGINT PRIMARY KEY,

    leaf_id BIGINT NOT NULL UNIQUE REFERENCES universe_leaves(id)
        ON DELETE CASCADE
);

-- Backfill from the existing leaves, reusing each leaf's id as its
-- seq, so the delta also covers leaves inserted before the journal
-- existed.
INSERT INTO universe_leaf_journal (seq, leaf_id)
SELECT leaves.id, leaves.id
FROM universe_leaves AS leaves
JOIN universe_roots AS roots
    ON leaves.universe_root_id = roots.id
WHERE roots.proof_type IN ('issuance', 'transfer');

-- The tail allocator: writers reserve seq ranges by bumping the tail
-- in-transaction. The resulting row lock is held until commit, which
-- is exactly what serializes journal appends in commit order.
CREATE TABLE universe_leaf_journal_tail (
    id SMALLINT PRIMARY KEY,

    tail BIGINT NOT NULL
);

-- Seed the tail above every historic universe_leaves id, journaled or
-- not, so future seq values never collide with backfilled ones.
INSERT INTO universe_leaf_journal_tail (id, tail)
SELECT 1, COALESCE(MAX(id), 0) FROM universe_leaves;
