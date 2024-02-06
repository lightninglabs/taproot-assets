-- name: InsertAssetTransfer :one
WITH target_txn(txn_id) AS (
    SELECT txn_id
    FROM chain_txns
    WHERE txid = @anchor_txid
)
INSERT INTO asset_transfers (
    height_hint, anchor_txn_id, transfer_time_unix
) VALUES (
    @height_hint, (SELECT txn_id FROM target_txn), @transfer_time_unix
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
    output_type, proof_courier_addr, asset_version
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13
);

-- name: QueryAssetTransfers :many
SELECT
    id, height_hint, txns.txid, transfer_time_unix
FROM asset_transfers transfers
JOIN chain_txns txns
    ON transfers.anchor_txn_id = txns.txn_id
-- We'll use this clause to filter out for only transfers that are
-- unconfirmed. But only if the unconf_only field is set.
WHERE (@unconf_only = false OR @unconf_only IS NULL OR
    (CASE WHEN txns.block_hash IS NULL THEN true ELSE false END) = @unconf_only)

-- Here we have another optional query clause to select a given transfer
-- based on the anchor_tx_hash, but only if it's specified.
AND (txns.txid = sqlc.narg('anchor_tx_hash') OR
    sqlc.narg('anchor_tx_hash') IS NULL)
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
    output_type, proof_courier_addr, asset_version,
    utxos.utxo_id AS anchor_utxo_id,
    utxos.outpoint AS anchor_outpoint,
    utxos.amt_sats AS anchor_value,
    utxos.merkle_root AS anchor_merkle_root,
    utxos.taproot_asset_root AS anchor_taproot_asset_root,
    utxos.tapscript_sibling AS anchor_tapscript_sibling,
    utxo_internal_keys.raw_key AS internal_key_raw_key_bytes,
    utxo_internal_keys.key_family AS internal_key_family,
    utxo_internal_keys.key_index AS internal_key_index,
    script_keys.tweaked_script_key AS script_key_bytes,
    script_keys.tweak AS script_key_tweak,
    script_key AS script_key_id,
    script_internal_keys.raw_key AS script_key_raw_key_bytes,
    script_internal_keys.key_family AS script_key_family,
    script_internal_keys.key_index AS script_key_index
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
    SELECT genesis_id, asset_group_witness_id, script_version, lock_time,
           relative_lock_time
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
    (SELECT lock_time FROM spent_asset),
    (SELECT relative_lock_time FROM spent_asset),
    @script_key_id, @anchor_utxo_id, @amount, @split_commitment_root_hash,
    @split_commitment_root_value, @spent
)
RETURNING asset_id;

-- name: ReAnchorPassiveAssets :exec
UPDATE assets
SET anchor_utxo_id = @new_anchor_utxo_id,
    split_commitment_root_hash = NULL,
    split_commitment_root_value = NULL
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
