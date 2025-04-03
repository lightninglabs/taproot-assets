-- name: InsertAssetTransfer :one
WITH target_txn(txn_id) AS (
    SELECT txn_id
    FROM chain_txns
    WHERE txid = @anchor_txid
)
INSERT INTO asset_transfers (
    height_hint, anchor_txn_id, transfer_time_unix, label
) VALUES (
    @height_hint, (SELECT txn_id FROM target_txn), @transfer_time_unix, @label
) RETURNING id;

-- name: InsertAssetTransferInput :exec
INSERT INTO asset_transfer_inputs (
    transfer_id, anchor_point, asset_id, script_key, amount
) VALUES (
    $1, $2, $3, $4, $5
);

-- name: InsertAssetTransferOutput :exec
INSERT INTO asset_transfer_outputs (
    transfer_id, anchor_utxo, script_key, script_key_local,
    amount, serialized_witnesses, split_commitment_root_hash,
    split_commitment_root_value, proof_suffix, num_passive_assets,
    output_type, proof_courier_addr, asset_version, lock_time,
    relative_lock_time, proof_delivery_complete, position
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17
);

-- name: SetTransferOutputProofDeliveryStatus :exec
WITH target(output_id) AS (
    SELECT output_id
    FROM asset_transfer_outputs output
    JOIN managed_utxos
      ON output.anchor_utxo = managed_utxos.utxo_id
    WHERE managed_utxos.outpoint = @serialized_anchor_outpoint
      AND output.position = @position
)
UPDATE asset_transfer_outputs
SET proof_delivery_complete = @delivery_complete
WHERE output_id = (SELECT output_id FROM target);

-- name: QueryAssetTransfers :many
SELECT
    id, height_hint, txns.txid, txns.block_hash AS anchor_tx_block_hash,
    transfer_time_unix, transfers.label
FROM asset_transfers transfers
JOIN chain_txns txns
    ON txns.txn_id = transfers.anchor_txn_id
WHERE
    -- Optionally filter on a given anchor_tx_hash.
    (txns.txid = sqlc.narg('anchor_tx_hash')
        OR sqlc.narg('anchor_tx_hash') IS NULL)

    -- Filter for pending transfers only if requested.
    AND (
        @pending_transfers_only = true AND
        (
            txns.block_hash IS NULL
                OR EXISTS (
                    SELECT 1
                    FROM asset_transfer_outputs outputs
                    WHERE outputs.transfer_id = transfers.id
                      AND outputs.proof_delivery_complete = false
                )
        )
        OR @pending_transfers_only = false OR @pending_transfers_only IS NULL
    )
ORDER BY transfer_time_unix;

-- name: FetchTransferInputs :many
SELECT input_id, anchor_point, asset_id, script_key, amount
FROM asset_transfer_inputs inputs
WHERE transfer_id = $1
ORDER BY input_id;

-- name: FetchTransferOutputs :many
SELECT
    output_id, proof_suffix, amount, serialized_witnesses, script_key_local,
    split_commitment_root_hash, split_commitment_root_value, num_passive_assets,
    output_type, proof_courier_addr, proof_delivery_complete, position,
    asset_version, lock_time, relative_lock_time,
    utxos.utxo_id AS anchor_utxo_id,
    utxos.outpoint AS anchor_outpoint,
    utxos.amt_sats AS anchor_value,
    utxos.merkle_root AS anchor_merkle_root,
    utxos.taproot_asset_root AS anchor_taproot_asset_root,
    utxos.tapscript_sibling AS anchor_tapscript_sibling,
    utxos.root_version AS anchor_commitment_version,
    utxo_internal_keys.raw_key AS internal_key_raw_key_bytes,
    utxo_internal_keys.key_family AS internal_key_family,
    utxo_internal_keys.key_index AS internal_key_index,
    sqlc.embed(script_keys),
    sqlc.embed(script_internal_keys)
FROM asset_transfer_outputs outputs
JOIN managed_utxos utxos
  ON outputs.anchor_utxo = utxos.utxo_id
JOIN script_keys
  ON outputs.script_key = script_keys.script_key_id
JOIN internal_keys script_internal_keys
  ON script_keys.internal_key_id = script_internal_keys.key_id
JOIN internal_keys utxo_internal_keys
  ON utxos.internal_key_id = utxo_internal_keys.key_id
WHERE transfer_id = $1
ORDER BY output_id;

-- name: ApplyPendingOutput :one
WITH spent_asset AS (
    SELECT genesis_id, asset_group_witness_id, script_version
    FROM assets
    WHERE assets.asset_id = @spent_asset_id
)
INSERT INTO assets (
    genesis_id, version, asset_group_witness_id, script_version, lock_time,
    relative_lock_time, script_key_id, anchor_utxo_id, amount,
    split_commitment_root_hash, split_commitment_root_value, spent
) VALUES (
    (SELECT genesis_id FROM spent_asset),
    @asset_version,
    (SELECT asset_group_witness_id FROM spent_asset),
    (SELECT script_version FROM spent_asset),
    @lock_time, @relative_lock_time, @script_key_id, @anchor_utxo_id, @amount,
    @split_commitment_root_hash, @split_commitment_root_value, @spent
)
ON CONFLICT (genesis_id, script_key_id, anchor_utxo_id)
    -- This is a NOP, anchor_utxo_id is one of the unique fields that caused the
    -- conflict.
    DO UPDATE SET anchor_utxo_id = EXCLUDED.anchor_utxo_id
RETURNING asset_id;

-- name: ReAnchorPassiveAssets :exec
UPDATE assets
SET anchor_utxo_id = @new_anchor_utxo_id,
    -- The following fields need to be the same fields we reset in
    -- Asset.CopySpendTemplate.
    split_commitment_root_hash = NULL,
    split_commitment_root_value = NULL,
    lock_time = 0,
    relative_lock_time = 0
WHERE asset_id = @asset_id;

-- name: DeleteAssetWitnesses :exec
DELETE FROM asset_witnesses
WHERE asset_id = $1;

-- name: LogProofTransferAttempt :exec
INSERT INTO proof_transfer_log (
    transfer_type, proof_locator_hash, time_unix
) VALUES (
    @transfer_type, @proof_locator_hash, @time_unix
);

-- name: QueryProofTransferAttempts :many
SELECT time_unix
FROM proof_transfer_log
WHERE proof_locator_hash = @proof_locator_hash
    AND transfer_type = @transfer_type
ORDER BY time_unix DESC;

-- name: InsertPassiveAsset :exec
WITH target_asset(asset_id) AS (
    SELECT assets.asset_id
    FROM assets
        JOIN genesis_assets
            ON assets.genesis_id = genesis_assets.gen_asset_id
        JOIN managed_utxos utxos
            ON assets.anchor_utxo_id = utxos.utxo_id
        JOIN script_keys
            ON assets.script_key_id = script_keys.script_key_id
    WHERE genesis_assets.asset_id = @asset_genesis_id
        AND utxos.outpoint = @prev_outpoint
        AND script_keys.tweaked_script_key = @script_key
)
INSERT INTO passive_assets (
    asset_id, transfer_id, new_anchor_utxo, script_key, new_witness_stack,
    new_proof, asset_version
) VALUES (
    (SELECT asset_id FROM target_asset), @transfer_id, @new_anchor_utxo,
    @script_key, @new_witness_stack, @new_proof, @asset_version
);

-- name: QueryPassiveAssets :many
SELECT passive.asset_id, passive.new_anchor_utxo, passive.script_key,
       passive.new_witness_stack, passive.new_proof,
       genesis_assets.asset_id AS genesis_id, passive.asset_version,
       utxos.outpoint
FROM passive_assets as passive
    JOIN assets
        ON passive.asset_id = assets.asset_id
    JOIN genesis_assets
        ON assets.genesis_id = genesis_assets.gen_asset_id
    JOIN managed_utxos utxos
        ON passive.new_anchor_utxo = utxos.utxo_id
WHERE passive.transfer_id = @transfer_id;

-- name: InsertBurn :one
INSERT INTO asset_burn_transfers (
    transfer_id, note, asset_id, group_key, amount
)
VALUES (
    @transfer_id, @note, @asset_id, @group_key, @amount
)
RETURNING burn_id;

-- name: QueryBurns :many
SELECT
    abt.note,
    abt.asset_id,
    abt.group_key,
    abt.amount,
    ct.txid AS anchor_txid -- Retrieving the txid from chain_txns.
FROM asset_burn_transfers abt
JOIN asset_transfers at ON abt.transfer_id = at.id
JOIN chain_txns ct ON at.anchor_txn_id = ct.txn_id
WHERE
    -- Optionally filter by asset_id.
    (abt.asset_id = @asset_id OR @asset_id IS NULL)

    -- Optionally filter by group_key.
    AND (abt.group_key = @group_key OR @group_key IS NULL)

    -- Optionally filter by anchor_txid in chain_txns.txid.
    AND (ct.txid = @anchor_txid OR @anchor_txid IS NULL)
ORDER BY abt.burn_id;
