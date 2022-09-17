-- name: InsertAssetTransfer :one
INSERT INTO asset_transfers (
    old_anchor_point, new_internal_key, new_anchor_utxo, transfer_time_unix
) VALUES (
    ?, ?, ?, ?
) RETURNING id;

-- name: InsertAssetDelta :exec
INSERT INTO asset_deltas (
    old_script_key, new_amt, new_script_key, serialized_witnesses, transfer_id
) VALUES (
    ?, ?, ?, ?, ?
);

-- name: QueryAssetTransfers :many
SELECT 
    asset_transfers.old_anchor_point, utxos.outpoint AS new_anchor_point,
    utxos.taro_root, utxos.tapscript_sibling, utxos.utxo_id AS new_anchor_utxo_id,
    txns.raw_tx AS anchor_tx_bytes, txns.txid AS anchor_txid,
    txns.txn_id AS anchor_tx_primary_key, transfer_time_unix, 
    keys.raw_key AS internal_key_bytes, keys.key_family AS internal_key_fam,
    keys.key_index AS internal_key_index, id AS transfer_id
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
    ((@unconf_only == 0 OR @unconf_only IS NULL)
        OR
    ((@unconf_only == 1) == (length(hex(txns.block_hash)) == 0)))

    AND
    
    -- Here we have another optional query clause to select a given transfer
    -- based on the new_anchor_point, but only if it's specified.
    (length(hex(sqlc.narg('new_anchor_point'))) == 0 OR 
        utxos.outpoint = sqlc.narg('new_anchor_point'))
);

-- name: FetchAssetDeltas :many
SELECT  
    deltas.old_script_key, deltas.new_amt, 
    deltas.new_script_key AS new_script_key_id, 
    new_keys.raw_key AS new_script_key_bytes, 
    new_keys.key_family AS new_script_key_family, 
    new_keys.key_index AS new_script_key_index,
    deltas.serialized_witnesses
FROM asset_deltas deltas
JOIN internal_keys new_keys
    ON deltas.new_script_key = new_keys.key_id
WHERE transfer_id = ?;

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
    SELECT key_id
    FROM internal_keys
    WHERE raw_key = @old_script_key
)
UPDATE assets
SET amount = @new_amount, script_key_id = @new_script_key_id
WHERE script_key_id in (SELECT key_id FROM old_script_key_id)
RETURNING asset_id;

-- name: DeleteAssetWitnesses :exec
DELETE FROM asset_witnesses
WHERE asset_id = ?;
