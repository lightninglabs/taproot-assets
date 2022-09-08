-- name: InsertAddr :one
INSERT INTO addrs (
    version, asset_id, fam_key, script_key_id, taproot_key_id, amount, 
    asset_type, creation_time
) VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING id;

-- name: FetchAddrs :many
SELECT 
    version, asset_id, fam_key, amount, asset_type, creation_time,
    script_keys.raw_key as raw_script_key,
    script_keys.tweak as script_key_tweak,
    script_keys.key_family AS script_key_family,
    script_keys.key_index AS script_key_index,
    taproot_keys.raw_key AS raw_taproot_key, 
    taproot_keys.key_family AS taproot_key_family,
    taproot_keys.key_index AS taproot_key_index
FROM addrs
JOIN internal_keys script_keys
    ON addrs.script_key_id = script_keys.key_id
JOIN internal_keys taproot_keys
    ON addrs.taproot_key_id = taproot_keys.key_id
WHERE creation_time >= @created_after
    AND creation_time <= @created_before
ORDER BY addrs.creation_time
LIMIT @num_limit OFFSET @num_offset;
