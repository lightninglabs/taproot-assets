-- name: UpsertSupplyCommitStateMachine :one
WITH target_state AS (
    -- Select the ID for the provided state name, if it exists.
    SELECT id
    FROM supply_commit_states s1
    WHERE s1.state_name = sqlc.narg('state_name')
), default_state AS (
    -- Select the ID for the 'DefaultState'.
    SELECT id
    FROM supply_commit_states s2
    WHERE s2.state_name = 'DefaultState'
)
INSERT INTO supply_commit_state_machines (
    group_key, current_state_id, latest_commitment_id
) VALUES (
    @group_key,
    -- Use the target state ID if found, otherwise use the default state ID.
    coalesce((SELECT id FROM target_state), (SELECT id FROM default_state)),
    sqlc.narg('latest_commitment_id')
)
ON CONFLICT (group_key)
DO UPDATE SET
    -- Update state ID only if a target state ID was found, otherwise keep existing.
    current_state_id = coalesce((SELECT id FROM target_state), supply_commit_state_machines.current_state_id),
    latest_commitment_id = coalesce(sqlc.narg('latest_commitment_id'), supply_commit_state_machines.latest_commitment_id)
-- Return the ID of the state that was actually set (either inserted or updated),
-- and the latest commitment ID that was set.
RETURNING current_state_id, latest_commitment_id;

-- name: InsertSupplyCommitment :one
INSERT INTO supply_commitments (
    group_key, chain_txn_id,
    output_index, internal_key_id, output_key, spent_commitment, -- Core fields
    block_height, block_header, merkle_proof, -- Nullable chain details
    supply_root_hash, supply_root_sum -- Nullable root details
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
) RETURNING commit_id;

-- name: UpdateSupplyCommitmentChainDetails :exec
UPDATE supply_commitments
SET merkle_proof = @merkle_proof,
    output_index = @output_index,
    block_header = @block_header,
    chain_txn_id = @chain_txn_id,
    block_height = @block_height
WHERE commit_id = @commit_id;

-- name: UpdateSupplyCommitmentRoot :exec
UPDATE supply_commitments
SET supply_root_hash = @supply_root_hash,
    supply_root_sum = @supply_root_sum
WHERE commit_id = @commit_id;

-- name: InsertSupplyCommitTransition :one
INSERT INTO supply_commit_transitions (
    state_machine_group_key, old_commitment_id, new_commitment_id,
    pending_commit_txn_id, finalized, frozen, creation_time
) VALUES (
    $1, $2, $3, $4, $5, $6, $7
) RETURNING transition_id;

-- name: FinalizeSupplyCommitTransition :exec
UPDATE supply_commit_transitions
SET finalized = TRUE
WHERE transition_id = @transition_id;

-- name: InsertSupplyUpdateEvent :exec
INSERT INTO supply_update_events (
    group_key, transition_id, update_type_id, event_data
) VALUES (
    $1, $2, $3, $4
);

-- name: QuerySupplyCommitStateMachine :one
SELECT
    sm.group_key,
    sm.current_state_id,
    states.state_name,
    sm.latest_commitment_id
FROM supply_commit_state_machines sm
JOIN supply_commit_states states
    ON sm.current_state_id = states.id
WHERE sm.group_key = @group_key;

-- name: QueryPendingSupplyCommitTransition :one
WITH target_machine AS (
    SELECT group_key
    FROM supply_commit_state_machines
    WHERE group_key = @group_key
)
SELECT sqlc.embed(t)
FROM supply_commit_transitions t
JOIN target_machine tm
    ON t.state_machine_group_key = tm.group_key
WHERE t.finalized = FALSE
ORDER BY t.creation_time DESC
LIMIT 1;

-- name: FreezePendingTransition :exec
UPDATE supply_commit_transitions
SET frozen = TRUE
WHERE state_machine_group_key = @group_key AND finalized = FALSE;

-- name: QuerySupplyUpdateEvents :many
SELECT
    ue.event_id,
    ue.transition_id,
    ue.update_type_id,
    types.update_type_name,
    ue.event_data
FROM supply_update_events ue
JOIN supply_commit_update_types types
    ON ue.update_type_id = types.id
WHERE ue.transition_id = @transition_id
ORDER BY ue.event_id ASC;

-- name: QueryDanglingSupplyUpdateEvents :many
SELECT
    ue.event_id,
    ue.transition_id,
    ue.update_type_id,
    types.update_type_name,
    ue.event_data
FROM supply_update_events ue
JOIN supply_commit_update_types types
    ON ue.update_type_id = types.id
WHERE ue.group_key = @group_key AND ue.transition_id IS NULL
ORDER BY ue.event_id ASC;

-- name: LinkDanglingSupplyUpdateEvents :exec
UPDATE supply_update_events
SET transition_id = @transition_id
WHERE group_key = @group_key AND transition_id IS NULL;

-- name: QuerySupplyCommitment :one
SELECT sqlc.embed(sc), ct.tx_index
FROM supply_commitments AS sc
JOIN chain_txns AS ct
    ON sc.chain_txn_id = ct.txn_id
WHERE commit_id = @commit_id;

-- name: QuerySupplyCommitmentByOutpoint :one
SELECT sqlc.embed(sc), ct.tx_index
FROM supply_commitments AS sc
JOIN chain_txns AS ct
    ON sc.chain_txn_id = ct.txn_id
WHERE sc.group_key = @group_key AND
    sc.output_index = @output_index AND
    ct.txid = @txid;

-- name: QuerySupplyCommitmentBySpentOutpoint :one
WITH spent_commitment AS (
    SELECT ssc.commit_id
    FROM supply_commitments AS ssc
        JOIN chain_txns AS ct
        ON ssc.chain_txn_id = ct.txn_id
    WHERE ssc.group_key = @group_key AND
        ssc.output_index = @output_index AND
        ct.txid = @txid
)
SELECT sqlc.embed(sc), ct.tx_index
FROM supply_commitments AS sc
    JOIN chain_txns AS ct
    ON sc.chain_txn_id = ct.txn_id
WHERE sc.spent_commitment = (SELECT commit_id FROM spent_commitment);

-- name: QueryStartingSupplyCommitment :one
SELECT sqlc.embed(sc), ct.tx_index
FROM supply_commitments AS sc
    JOIN chain_txns AS ct
    ON sc.chain_txn_id = ct.txn_id
WHERE sc.spent_commitment IS NULL AND
    sc.group_key = @group_key;

-- name: QuerySupplyCommitmentOutpoint :one
SELECT ct.txid, sc.output_index
FROM supply_commitments AS sc
    JOIN chain_txns AS ct
    ON sc.chain_txn_id = ct.txn_id
WHERE sc.commit_id = @commit_id;

-- name: UpdateSupplyCommitTransitionCommitment :exec
UPDATE supply_commit_transitions
SET new_commitment_id = @new_commitment_id,
    pending_commit_txn_id = @pending_commit_txn_id
WHERE transition_id = @transition_id;

-- name: DeleteSupplyCommitTransition :exec
DELETE FROM supply_commit_transitions
WHERE transition_id = @transition_id;

-- name: DeleteSupplyUpdateEvents :exec
DELETE FROM supply_update_events
WHERE transition_id = @transition_id;

-- name: FetchUnspentPrecommits :many
-- Fetch unspent pre-commitment outputs. A pre-commitment output is a mint
-- anchor transaction output which relates to the supply commitment feature.
SELECT
    mac.tx_output_index,
    sqlc.embed(ik),
    mac.group_key,
    mint_txn.block_height,
    mint_txn.raw_tx
FROM mint_anchor_uni_commitments mac
JOIN asset_minting_batches amb ON mac.batch_id = amb.batch_id
JOIN genesis_points gp ON amb.genesis_id = gp.genesis_id
JOIN chain_txns mint_txn ON gp.anchor_tx_id = mint_txn.txn_id
JOIN internal_keys ik ON mac.taproot_internal_key_id = ik.key_id
LEFT JOIN supply_commitments sc ON mac.spent_by = sc.commit_id
LEFT JOIN chain_txns commit_txn ON sc.chain_txn_id = commit_txn.txn_id
WHERE
    mac.group_key = @group_key AND
    (mac.spent_by IS NULL OR commit_txn.block_hash IS NULL);

-- name: MarkPreCommitmentSpentByOutpoint :exec
-- Mark a specific pre-commitment output as spent by its outpoint.
UPDATE mint_anchor_uni_commitments
SET spent_by = @spent_by_commit_id
WHERE outpoint = @outpoint
    AND spent_by IS NULL;

-- name: FetchSupplyCommit :one
SELECT
    sqlc.embed(sc), txn.tx_index
FROM supply_commit_state_machines sm
JOIN supply_commitments sc
    ON sm.latest_commitment_id = sc.commit_id
JOIN chain_txns txn
    ON sc.chain_txn_id = txn.txn_id
JOIN internal_keys ik
    ON sc.internal_key_id = ik.key_id
WHERE
    sm.group_key = @group_key AND
    txn.block_hash IS NOT NULL;

-- name: QueryExistingPendingTransition :one
-- Find the ID of an existing non-finalized transition for the group key
SELECT transition_id
FROM supply_commit_transitions sct
WHERE sct.state_machine_group_key = @group_key AND finalized = FALSE
LIMIT 1;

-- name: FetchInternalKeyByID :one
SELECT raw_key, key_family, key_index
FROM internal_keys
WHERE key_id = @key_id;

-- name: FetchChainTxByID :one
SELECT raw_tx, block_height -- Include block_height needed by FetchState
FROM chain_txns
WHERE txn_id = @txn_id;
