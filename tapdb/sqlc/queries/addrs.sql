-- name: UpsertAddr :one
INSERT INTO addrs (
    version,
    asset_version,
    genesis_asset_id,
    group_key,
    script_key_id,
    taproot_key_id,
    tapscript_sibling,
    taproot_output_key,
    amount,
    asset_type,
    creation_time,
    proof_courier_addr
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
) 
ON CONFLICT (taproot_output_key) DO UPDATE
SET
    -- If the WHERE clause below is true (exact match on all other fields,
    -- except for creation_time), we set taproot_output_key to its current
    -- conflicting value. This is a no-op in terms of data change but allows
    -- RETURNING id to work on the existing row.
    taproot_output_key = excluded.taproot_output_key
WHERE 
    addrs.version = excluded.version
    AND addrs.asset_version = excluded.asset_version
    AND addrs.genesis_asset_id = excluded.genesis_asset_id
    AND (
        (addrs.group_key IS NULL AND excluded.group_key IS NULL)
        OR addrs.group_key = excluded.group_key
    )
    AND addrs.script_key_id = excluded.script_key_id
    AND addrs.taproot_key_id = excluded.taproot_key_id
    AND (
        (addrs.tapscript_sibling IS NULL AND excluded.tapscript_sibling IS NULL)
        OR addrs.tapscript_sibling = excluded.tapscript_sibling
    )
    AND addrs.amount = excluded.amount
    AND addrs.asset_type = excluded.asset_type
    AND addrs.proof_courier_addr = excluded.proof_courier_addr
RETURNING id;

-- name: FetchAddrs :many
SELECT 
    version, asset_version, genesis_asset_id, group_key, tapscript_sibling,
    taproot_output_key, amount, asset_type, creation_time, managed_from,
    proof_courier_addr,
    sqlc.embed(script_keys),
    sqlc.embed(raw_script_keys),
    taproot_keys.raw_key AS raw_taproot_key, 
    taproot_keys.key_family AS taproot_key_family,
    taproot_keys.key_index AS taproot_key_index
FROM addrs
JOIN script_keys
    ON addrs.script_key_id = script_keys.script_key_id
JOIN internal_keys raw_script_keys
    ON script_keys.internal_key_id = raw_script_keys.key_id
JOIN internal_keys taproot_keys
    ON addrs.taproot_key_id = taproot_keys.key_id
WHERE creation_time >= @created_after
    AND creation_time <= @created_before
    AND (@unmanaged_only = false OR
         (CASE WHEN managed_from IS NULL THEN true ELSE false END) = @unmanaged_only)
ORDER BY addrs.creation_time
LIMIT @num_limit OFFSET @num_offset;

-- name: QueryAddr :one
SELECT
    sqlc.embed(addrs),
    sqlc.embed(script_keys),
    sqlc.embed(raw_script_keys),
    sqlc.embed(taproot_keys)
FROM addrs
JOIN script_keys
  ON addrs.script_key_id = script_keys.script_key_id
JOIN internal_keys raw_script_keys
  ON script_keys.internal_key_id = raw_script_keys.key_id
JOIN internal_keys taproot_keys
  ON addrs.taproot_key_id = taproot_keys.key_id
WHERE
    (addrs.taproot_output_key = sqlc.narg('taproot_output_key') OR
      sqlc.narg('taproot_output_key') IS NULL)
    AND (addrs.version = sqlc.narg('version') OR
      sqlc.narg('version') IS NULL)
    AND (substr(script_keys.tweaked_script_key, 2) = sqlc.narg('x_only_script_key') OR
      sqlc.narg('x_only_script_key') IS NULL);

-- name: SetAddrManaged :exec
WITH target_addr(addr_id) AS (
    SELECT id
    FROM addrs
    WHERE addrs.taproot_output_key = $1
)
UPDATE addrs
SET managed_from = $2
WHERE id = (SELECT addr_id FROM target_addr);

-- name: UpsertAddrEvent :one
WITH target_addr(addr_id) AS (
    SELECT id
    FROM addrs
    WHERE addrs.taproot_output_key = $1
), target_chain_txn(txn_id) AS (
    SELECT txn_id
    FROM chain_txns
    WHERE chain_txns.txid = $2
)
INSERT INTO addr_events (
    creation_time, addr_id, status, chain_txn_id, chain_txn_output_index,
    managed_utxo_id, asset_proof_id, asset_id
) VALUES (
    $3, (SELECT addr_id FROM target_addr), $4,
    (SELECT txn_id FROM target_chain_txn), $5, $6, $7, $8
)
ON CONFLICT (addr_id, chain_txn_id, chain_txn_output_index)
    DO UPDATE SET status = EXCLUDED.status,
                  asset_proof_id = COALESCE(EXCLUDED.asset_proof_id, addr_events.asset_proof_id),
                  asset_id = COALESCE(EXCLUDED.asset_id, addr_events.asset_id)
RETURNING id;

-- name: FetchAddrEvent :one
SELECT
    creation_time, status, asset_proof_id, asset_id,
    chain_txns.txid as txid,
    chain_txns.block_height as confirmation_height,
    chain_txn_output_index as output_index,
    managed_utxos.amt_sats as amt_sats,
    managed_utxos.tapscript_sibling as tapscript_sibling,
    internal_keys.raw_key as internal_key
FROM addr_events
LEFT JOIN chain_txns
       ON addr_events.chain_txn_id = chain_txns.txn_id
LEFT JOIN managed_utxos
       ON addr_events.managed_utxo_id = managed_utxos.utxo_id
LEFT JOIN internal_keys
       ON managed_utxos.internal_key_id = internal_keys.key_id
WHERE id = $1;

-- name: FetchAddrEventByAddrKeyAndOutpoint :one
WITH target_addr(addr_id) AS (
    SELECT id
    FROM addrs
    WHERE addrs.taproot_output_key = $1
)
SELECT
    addr_events.id, creation_time, status, asset_proof_id, asset_id,
    chain_txns.txid as txid,
    chain_txns.block_height as confirmation_height,
    chain_txn_output_index as output_index,
    managed_utxos.amt_sats as amt_sats,
    managed_utxos.tapscript_sibling as tapscript_sibling,
    internal_keys.raw_key as internal_key
FROM addr_events
JOIN target_addr
  ON addr_events.addr_id = target_addr.addr_id
LEFT JOIN chain_txns
       ON addr_events.chain_txn_id = chain_txns.txn_id
LEFT JOIN managed_utxos
       ON addr_events.managed_utxo_id = managed_utxos.utxo_id
LEFT JOIN internal_keys
       ON managed_utxos.internal_key_id = internal_keys.key_id
WHERE chain_txns.txid = $2
  AND chain_txn_output_index = $3;

-- name: QueryEventIDs :many
SELECT
    addr_events.id as event_id, addrs.taproot_output_key as taproot_output_key
FROM addr_events
JOIN addrs
  ON addr_events.addr_id = addrs.id
WHERE addr_events.status >= @status_from 
  AND addr_events.status <= @status_to
  AND COALESCE(@addr_taproot_key, addrs.taproot_output_key) = addrs.taproot_output_key
  AND addr_events.creation_time >= @created_after
ORDER by addr_events.creation_time;
