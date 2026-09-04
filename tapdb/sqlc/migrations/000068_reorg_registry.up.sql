-- The re-org watcher's registry: every act of staking local state on
-- a chain outcome is recorded here as an "anchoring", together with
-- the evidence sensed for it (candidate spends of its trigger
-- outpoints), its dependency edges to other anchorings, and the
-- outbox of external effects enqueued by site handlers.
--
-- Two phase columns per anchoring: (phase_code, phase_evidence) is
-- the sensed truth, derived from the chain view; (delivered_code,
-- delivered_evidence) is the last phase the owning site durably
-- acknowledged. The site is converged when the pairs are equal; the
-- difference between them is exactly the delivery work outstanding.
CREATE TABLE reorg_anchorings (
    id INTEGER PRIMARY KEY,

    -- The owning site's stable identifier.
    site_id TEXT NOT NULL,

    -- The confirmation depth at which this site considers an outcome
    -- final (act-confirmed) for this anchoring.
    threshold INTEGER NOT NULL CHECK(threshold > 0),

    -- Site-owned opaque predicate input, versioned.
    match_version SMALLINT NOT NULL,
    match_data BLOB NOT NULL,

    -- Site-owned opaque repair/finalize payload, versioned.
    payload_version SMALLINT NOT NULL,
    payload_data BLOB NOT NULL,

    -- Best height at registration time.
    created_height INTEGER NOT NULL,

    -- The sensed phase (code + encoded evidence).
    phase_code SMALLINT NOT NULL,
    phase_evidence BLOB NOT NULL,

    -- The delivered phase (code + encoded evidence).
    delivered_code SMALLINT NOT NULL,
    delivered_evidence BLOB NOT NULL,

    -- The current witness transaction hash, set exactly when the
    -- sensed phase is witnessed or buried; surfaced through the
    -- observability listing.
    witness_txid BLOB
        CHECK(witness_txid IS NULL OR length(witness_txid) = 32),

    -- Delivery bookkeeping. Failed deliveries increment attempts and
    -- back off via next_delivery_at (unix seconds); after enough
    -- failures the anchoring is flagged stuck, which is a delivery
    -- condition, not a phase -- sensing continues regardless.
    stuck BOOLEAN NOT NULL DEFAULT FALSE,
    delivery_attempts INTEGER NOT NULL DEFAULT 0,
    last_delivery_error TEXT,
    next_delivery_at BIGINT NOT NULL DEFAULT 0,

    -- Set (unix seconds) when a terminal phase is delivered. Terminal
    -- rows are retained for observability and post-mortem audit.
    terminal_at BIGINT
);

CREATE INDEX reorg_anchorings_phase_idx
    ON reorg_anchorings(phase_code);

CREATE INDEX reorg_anchorings_site_idx
    ON reorg_anchorings(site_id);

-- The stuck flag is the operator alarm surface; a partial index
-- keeps alarm-time listings from scanning a never-pruned table.
CREATE INDEX reorg_anchorings_stuck_idx
    ON reorg_anchorings(stuck) WHERE stuck = TRUE;

-- The trigger set: the outpoints whose spending constitutes (or
-- forecloses) each anchoring, with the script and height hint needed
-- to open spend subscriptions.
CREATE TABLE reorg_trigger_outpoints (
    id INTEGER PRIMARY KEY,

    anchoring_id BIGINT NOT NULL REFERENCES reorg_anchorings(id),

    outpoint_txid BLOB NOT NULL CHECK(length(outpoint_txid) = 32),
    outpoint_index INTEGER NOT NULL,

    pk_script BLOB NOT NULL,
    height_hint INTEGER NOT NULL
);

CREATE UNIQUE INDEX reorg_trigger_outpoints_uk
    ON reorg_trigger_outpoints(anchoring_id, outpoint_txid,
                               outpoint_index);

-- Dependency-edge derivation and spend routing both look up by
-- outpoint.
CREATE INDEX reorg_trigger_outpoints_op_idx
    ON reorg_trigger_outpoints(outpoint_txid, outpoint_index);

-- The chain view: every candidate spending transaction observed for
-- an anchoring. Candidates are never deleted -- one that re-orgs out
-- merely flips off-chain, since it may return. The verdict is the
-- owning site's pure judgment of the candidate, evaluated once
-- (NULL = not yet evaluated, which indicates a payload decode defect
-- and is surfaced loudly rather than derived from).
CREATE TABLE reorg_candidate_spends (
    id INTEGER PRIMARY KEY,

    anchoring_id BIGINT NOT NULL REFERENCES reorg_anchorings(id),

    spender_txid BLOB NOT NULL CHECK(length(spender_txid) = 32),
    raw_tx BLOB NOT NULL,

    verdict SMALLINT,

    on_chain BOOLEAN NOT NULL DEFAULT FALSE,
    block_hash BLOB CHECK(block_hash IS NULL OR length(block_hash) = 32),
    block_height INTEGER,
    tx_index INTEGER,

    -- Set when the chain notifier certified this candidate reaching
    -- the anchoring's threshold depth (a confirmation subscription
    -- registered at that depth fired). Act-tier phase derivation
    -- trusts only this certification, never depth arithmetic over a
    -- possibly-torn view. Sticky: never cleared by later re-orgs.
    act_certified BOOLEAN NOT NULL DEFAULT FALSE,

    -- Witness enrichment, captured from the confirmation event at
    -- sensing time: the header of the including block and the
    -- transaction's merkle inclusion proof. Site handlers rebuild
    -- proofs from these without any network access inside their
    -- transaction.
    block_header BLOB CHECK(
        block_header IS NULL OR length(block_header) = 80
    ),
    merkle_proof BLOB,

    -- The trigger outpoints this candidate spends, encoded as a
    -- concatenation of (txid || big-endian index) tuples.
    spent_outpoints BLOB NOT NULL
);

CREATE UNIQUE INDEX reorg_candidate_spends_uk
    ON reorg_candidate_spends(anchoring_id, spender_txid);

-- Dependency-edge derivation at registration looks candidates up by
-- spender.
CREATE INDEX reorg_candidate_spends_spender_idx
    ON reorg_candidate_spends(spender_txid);

-- Dependency edges: the child anchoring's trigger outpoints were
-- created by the parent anchoring's witness, pinned to the specific
-- witness transaction the child depends on. The edge is foreclosed
-- (reversibly, until the child's threshold is reached) when the
-- parent can no longer supply the outpoint; the staged foreclosing
-- evidence is an encoded witness of the foreclosing transaction.
CREATE TABLE reorg_dependencies (
    id INTEGER PRIMARY KEY,

    child_id BIGINT NOT NULL REFERENCES reorg_anchorings(id),
    parent_id BIGINT NOT NULL REFERENCES reorg_anchorings(id),

    parent_witness_txid BLOB NOT NULL
        CHECK(length(parent_witness_txid) = 32),

    foreclosing_evidence BLOB,
    foreclosing_on_chain BOOLEAN NOT NULL DEFAULT FALSE,

    -- Set when the notifier certified the foreclosing transaction
    -- reaching the child's threshold depth; only a certified
    -- foreclosure abandons the child.
    foreclosing_act_certified BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE UNIQUE INDEX reorg_dependencies_uk
    ON reorg_dependencies(child_id, parent_id);

CREATE INDEX reorg_dependencies_parent_idx
    ON reorg_dependencies(parent_id);

-- The outbox: external effects enqueued in the same transaction as
-- the registry advance that produced them, dispatched asynchronously
-- and idempotently. The registry never advances past an external
-- effect that was not at least durably enqueued.
CREATE TABLE reorg_outbox (
    id INTEGER PRIMARY KEY,

    -- Optionally ties the effect to the anchoring whose delivery
    -- enqueued it.
    anchoring_id BIGINT REFERENCES reorg_anchorings(id),

    -- Routes the effect to its dispatch handler.
    effect_kind TEXT NOT NULL,

    -- Site-owned opaque effect payload, versioned.
    payload_version SMALLINT NOT NULL,
    payload_data BLOB NOT NULL,

    -- Unix seconds.
    created_at BIGINT NOT NULL,

    -- Dispatch bookkeeping; dispatched_at (unix seconds) is set once
    -- the effect has been handed off successfully.
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    next_attempt_at BIGINT NOT NULL DEFAULT 0,
    dispatched_at BIGINT
);

CREATE INDEX reorg_outbox_pending_idx
    ON reorg_outbox(dispatched_at, next_attempt_at);
