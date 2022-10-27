-- name: InsertAssetTransfer :one
INSERT INTO asset_transfers (
    old_anchor_point, new_internal_key, new_anchor_utxo, height_hint, transfer_time_unix
) VALUES (
    $1, $2, $3, $4, $5
) RETURNING id;

-- name: InsertAssetDelta :exec
INSERT INTO asset_deltas (
    old_script_key, new_amt, new_script_key, serialized_witnesses, transfer_id,
    proof_id, split_commitment_root_hash, split_commitment_root_value
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8
);

-- name: InsertSpendProofs :one
INSERT INTO transfer_proofs (
   transfer_id, sender_proof, receiver_proof 
) VALUES (
    $1, $2, $3
) RETURNING proof_id;

-- name: QueryAssetTransfers :many
SELECT 
    asset_transfers.old_anchor_point, utxos.outpoint AS new_anchor_point,
    utxos.taro_root, utxos.tapscript_sibling,
    utxos.utxo_id AS new_anchor_utxo_id, txns.raw_tx AS anchor_tx_bytes,
    txns.txid AS anchor_txid, txns.txn_id AS anchor_tx_primary_key,
    txns.chain_fees, transfer_time_unix, keys.raw_key AS internal_key_bytes,
    keys.key_family AS internal_key_fam, keys.key_index AS internal_key_index,
    id AS transfer_id, height_hint, transfer_time_unix
FROM asset_transfers
JOIN internal_keys keys
    ON asset_transfers.new_internal_key = keys.key_id
JOIN managed_utxos utxos
    ON asset_transfers.new_anchor_utxo = utxos.utxo_id
JOIN chain_txns txns
    ON utxos.utxo_id = txns.txn_id
WHERE (
    -- We'll use this clause to filter out for only transfers that are
    -- unconfirmed. But only if the unconf_only field is set.
    -- TODO(roasbeef): just do the confirmed bit,
    (@unconf_only = false OR @unconf_only IS NULL OR
      (CASE WHEN txns.block_hash IS NULL THEN true ELSE false END) = @unconf_only)

    AND
    
    -- Here we have another optional query clause to select a given transfer
    -- based on the new_anchor_point, but only if it's specified.
    (utxos.outpoint = sqlc.narg('new_anchor_point') OR
       sqlc.narg('new_anchor_point') IS NULL)
);

-- name: FetchAssetDeltas :many
SELECT  
    deltas.old_script_key, deltas.new_amt, 
    script_keys.tweaked_script_key AS new_script_key_bytes,
    script_keys.tweak AS script_key_tweak,
    deltas.new_script_key AS new_script_key_id, 
    internal_keys.raw_key AS new_raw_script_key_bytes,
    internal_keys.key_family AS new_script_key_family, 
    internal_keys.key_index AS new_script_key_index,
    deltas.serialized_witnesses, split_commitment_root_hash, 
    split_commitment_root_value
FROM asset_deltas deltas
JOIN script_keys
    ON deltas.new_script_key = script_keys.script_key_id
JOIN internal_keys 
    ON script_keys.internal_key_id = internal_keys.key_id
WHERE transfer_id = $1;

-- name: FetchAssetDeltasWithProofs :many
SELECT  
    deltas.old_script_key, deltas.new_amt, 
    script_keys.tweaked_script_key AS new_script_key_bytes,
    script_keys.tweak AS script_key_tweak,
    deltas.new_script_key AS new_script_key_id, 
    internal_keys.raw_key AS new_raw_script_key_bytes,
    internal_keys.key_family AS new_script_key_family, 
    internal_keys.key_index AS new_script_key_index,
    deltas.serialized_witnesses, deltas.split_commitment_root_hash, 
    deltas.split_commitment_root_value, transfer_proofs.sender_proof,
    transfer_proofs.receiver_proof
FROM asset_deltas deltas
JOIN script_keys
    ON deltas.new_script_key = script_keys.script_key_id
JOIN internal_keys 
    ON script_keys.internal_key_id = internal_keys.key_id
JOIN transfer_proofs
    ON deltas.proof_id = transfer_proofs.proof_id
WHERE deltas.transfer_id = $1;

-- name: FetchSpendProofs :one
SELECT sender_proof, receiver_proof
FROM transfer_proofs
WHERE transfer_id = $1;

-- name: ReanchorAssets :exec
WITH assets_to_update AS (
    SELECT asset_id
    FROM assets
    JOIN managed_utxos utxos
        ON assets.anchor_utxo_id = utxos.utxo_id
    WHERE utxos.outpoint = sqlc.arg('old_outpoint')
)
UPDATE assets
SET anchor_utxo_id = sqlc.arg('new_outpoint_utxo_id')
WHERE asset_id IN (SELECT asset_id FROM assets_to_update);

-- name: ApplySpendDelta :one
WITH old_script_key_id AS (
    SELECT script_key_id
    FROM script_keys
    WHERE tweaked_script_key = @old_script_key
)
UPDATE assets
SET amount = @new_amount, script_key_id = @new_script_key_id, 
    split_commitment_root_hash = @split_commitment_root_hash,
    split_commitment_root_value = @split_commitment_root_value
WHERE script_key_id in (SELECT script_key_id FROM old_script_key_id)
RETURNING asset_id;

-- name: DeleteAssetWitnesses :exec
DELETE FROM asset_witnesses
WHERE asset_id = $1;

-- name: DeleteSpendProofs :exec
DELETE FROM transfer_proofs
WHERE transfer_id = $1;
