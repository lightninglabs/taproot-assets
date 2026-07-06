-- Phase codes mirror tapreorg.PhaseCode: 0 unwitnessed, 1 witnessed,
-- 2 conflicted, 3 buried, 4 abandoned, 5 withdrawn. Codes >= 3 are
-- terminal. Verdict codes mirror tapreorg.Verdict: 0 satisfies, 1
-- foreign. The literals below must stay in sync with those enums.

-- name: InsertReorgAnchoring :one
INSERT INTO reorg_anchorings (
    site_id, threshold, match_version, match_data, payload_version,
    payload_data, created_height, phase_code, phase_evidence,
    delivered_code, delivered_evidence, next_delivery_at
) VALUES (
    @site_id, @threshold, @match_version, @match_data, @payload_version,
    @payload_data, @created_height, @phase_code, @phase_evidence,
    @delivered_code, @delivered_evidence, 0
)
RETURNING id;

-- name: InsertReorgTriggerOutpoint :exec
INSERT INTO reorg_trigger_outpoints (
    anchoring_id, outpoint_txid, outpoint_index, pk_script, height_hint
) VALUES (
    @anchoring_id, @outpoint_txid, @outpoint_index, @pk_script,
    @height_hint
);

-- name: FetchReorgAnchoring :one
SELECT *
FROM reorg_anchorings
WHERE id = @id;

-- name: FetchReorgTriggerOutpoints :many
SELECT *
FROM reorg_trigger_outpoints
WHERE anchoring_id = @anchoring_id
ORDER BY outpoint_txid, outpoint_index;

-- name: FetchReorgCandidateSpends :many
SELECT *
FROM reorg_candidate_spends
WHERE anchoring_id = @anchoring_id
ORDER BY spender_txid;

-- name: ListLiveReorgAnchorings :many
SELECT *
FROM reorg_anchorings
WHERE phase_code < 3
ORDER BY id;

-- name: ListReorgAnchorings :many
SELECT *
FROM reorg_anchorings
ORDER BY id;

-- name: UpsertReorgCandidateSpend :exec
INSERT INTO reorg_candidate_spends (
    anchoring_id, spender_txid, raw_tx, verdict, on_chain, block_hash,
    block_height, tx_index, spent_outpoints
) VALUES (
    @anchoring_id, @spender_txid, @raw_tx, @verdict, @on_chain,
    @block_hash, @block_height, @tx_index, @spent_outpoints
)
ON CONFLICT (anchoring_id, spender_txid)
DO UPDATE SET
    raw_tx = EXCLUDED.raw_tx,
    verdict = EXCLUDED.verdict,
    on_chain = EXCLUDED.on_chain,
    block_hash = EXCLUDED.block_hash,
    block_height = EXCLUDED.block_height,
    tx_index = EXCLUDED.tx_index,
    spent_outpoints = EXCLUDED.spent_outpoints;

-- name: SetReorgAnchoringPhase :execrows
-- A newly sensed phase is a new delivery objective, so the failure
-- bookkeeping of the previous objective (backoff, attempts, stuck)
-- resets with it; a systematically failing handler re-sticks after
-- the usual number of attempts. Terminal phases are absorbing at the
-- row level: a write racing another writer's terminal transition
-- (a site-initiated withdrawal, most likely) matches no rows, and
-- the caller observes the refusal via the row count.
UPDATE reorg_anchorings
SET phase_code = @phase_code,
    phase_evidence = @phase_evidence,
    witness_txid = @witness_txid,
    delivery_attempts = 0,
    stuck = FALSE,
    last_delivery_error = NULL,
    next_delivery_at = 0
WHERE id = @id
  AND phase_code < 3;

-- name: MarkReorgAnchoringDelivered :exec
UPDATE reorg_anchorings
SET delivered_code = @delivered_code,
    delivered_evidence = @delivered_evidence,
    stuck = FALSE,
    delivery_attempts = 0,
    last_delivery_error = NULL,
    next_delivery_at = 0,
    terminal_at = @terminal_at
WHERE id = @id;

-- name: RecordReorgDeliveryFailure :exec
UPDATE reorg_anchorings
SET delivery_attempts = delivery_attempts + 1,
    last_delivery_error = @last_delivery_error,
    next_delivery_at = @next_delivery_at,
    stuck = @stuck
WHERE id = @id;

-- name: ListReorgPendingDeliveries :many
SELECT *
FROM reorg_anchorings
WHERE (phase_code != delivered_code
       OR phase_evidence != delivered_evidence)
  AND next_delivery_at <= @now
ORDER BY id;

-- name: FetchLiveReorgParentsByCandidate :many
-- The live anchorings for which the given transaction is a recorded
-- satisfying candidate. Candidate rows are the durable record of
-- every form in which an anchoring has ever been observed satisfied,
-- so matching them (rather than the current witness) lets a child's
-- registration find its parent whichever form the parent currently
-- holds — witnessed, conflicted, or reorged back out entirely.
SELECT a.id
FROM reorg_anchorings a
JOIN reorg_candidate_spends c
  ON c.anchoring_id = a.id
WHERE c.spender_txid = @spender_txid
  AND c.verdict = 0
  AND a.phase_code < 3
ORDER BY a.id;

-- name: FetchLiveReorgDependentsByTrigger :many
-- The live anchorings whose trigger set references the given
-- transaction: used when a satisfying candidate in that form is first
-- recorded, to derive edges for children registered before their
-- parent's transaction had ever been observed.
SELECT DISTINCT t.anchoring_id
FROM reorg_trigger_outpoints t
JOIN reorg_anchorings child
  ON child.id = t.anchoring_id
WHERE t.outpoint_txid = @outpoint_txid
  AND child.phase_code < 3
ORDER BY t.anchoring_id;

-- name: UpsertReorgDependency :exec
-- Edge creation is idempotent: registration-time and candidate-time
-- derivation can discover the same edge, and the first write wins.
INSERT INTO reorg_dependencies (
    child_id, parent_id, parent_witness_txid
) VALUES (
    @child_id, @parent_id, @parent_witness_txid
)
ON CONFLICT (child_id, parent_id) DO NOTHING;

-- name: FetchReorgDependencyEdgesByParent :many
SELECT d.*
FROM reorg_dependencies d
JOIN reorg_anchorings child
  ON child.id = d.child_id
WHERE d.parent_id = @parent_id
  AND child.phase_code < 3
ORDER BY d.id;

-- name: FetchReorgDependencyEdgesByChild :many
SELECT *
FROM reorg_dependencies
WHERE child_id = @child_id
ORDER BY id;

-- name: UpdateReorgDependencyForeclosure :exec
UPDATE reorg_dependencies
SET foreclosing_evidence = @foreclosing_evidence,
    foreclosing_on_chain = @foreclosing_on_chain
WHERE child_id = @child_id
  AND parent_id = @parent_id;

-- name: ClearReorgDependencyForeclosure :exec
UPDATE reorg_dependencies
SET foreclosing_evidence = NULL,
    foreclosing_on_chain = FALSE
WHERE child_id = @child_id
  AND parent_id = @parent_id;

-- name: CountLiveReorgDependents :one
SELECT COUNT(*)
FROM reorg_dependencies d
JOIN reorg_anchorings child
  ON child.id = d.child_id
WHERE d.parent_id = @parent_id
  AND child.phase_code < 3;

-- name: InsertReorgEffect :one
INSERT INTO reorg_outbox (
    anchoring_id, effect_kind, payload_version, payload_data,
    created_at, next_attempt_at
) VALUES (
    @anchoring_id, @effect_kind, @payload_version, @payload_data,
    @created_at, 0
)
RETURNING id;

-- name: ListReorgPendingEffects :many
SELECT *
FROM reorg_outbox
WHERE dispatched_at IS NULL
  AND next_attempt_at <= @now
ORDER BY id
LIMIT @max_effects;

-- name: MarkReorgEffectDispatched :exec
UPDATE reorg_outbox
SET dispatched_at = @dispatched_at
WHERE id = @id;

-- name: RecordReorgEffectFailure :exec
UPDATE reorg_outbox
SET attempts = attempts + 1,
    last_error = @last_error,
    next_attempt_at = @next_attempt_at
WHERE id = @id;
