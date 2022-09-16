-- name: InsertAddr :one
INSERT INTO addrs (
    version, asset_id, fam_key, script_key_id, taproot_key_id,
    taproot_output_key, amount, asset_type, creation_time
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id;

-- name: FetchAddrs :many
SELECT 
    version, asset_id, fam_key, taproot_output_key, amount, asset_type,
    creation_time,
    script_keys.tweaked_script_key,
    script_keys.tweak AS script_key_tweak,
    raw_script_keys.raw_key AS raw_script_key,
    raw_script_keys.key_family AS script_key_family,
    raw_script_keys.key_index AS script_key_index,
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
ORDER BY addrs.creation_time
LIMIT @num_limit OFFSET @num_offset;

-- name: FetchAddrByTaprootOutputKey :one
SELECT
    version, asset_id, fam_key, taproot_output_key, amount, asset_type,
    creation_time,
    script_keys.tweaked_script_key,
    script_keys.tweak AS script_key_tweak,
    raw_script_keys.raw_key as raw_script_key,
    raw_script_keys.key_family AS script_key_family,
    raw_script_keys.key_index AS script_key_index,
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
WHERE taproot_output_key = ?;
