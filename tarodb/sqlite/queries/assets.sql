-- name: UpsertInternalKey :one
INSERT INTO internal_keys (
    raw_key, tweak, key_family, key_index
) VALUES (
    ?, ?, ?, ?
) ON CONFLICT (raw_key)
    -- This is a NOP, raw_key is the unique field that caused the conflict.
    DO UPDATE SET raw_key = EXCLUDED.raw_key
RETURNING key_id;

-- name: NewMintingBatch :exec
INSERT INTO asset_minting_batches (
    batch_state, batch_id, creation_time_unix
) VALUES (0, ?, ?);

-- name: FetchMintingBatch :one
SELECT *
FROM asset_minting_batches batches
JOIN internal_keys keys
    ON batches.batch_id = keys.key_id
WHERE keys.raw_key = ?;

-- name: FetchMintingBatchesByState :many
SELECT *
FROM asset_minting_batches batches
JOIN internal_keys keys
    ON batches.batch_id = keys.key_id
WHERE batches.batch_state = ?;

-- name: FetchMintingBatchesByInverseState :many
SELECT *
FROM asset_minting_batches batches
JOIN internal_keys keys
    ON batches.batch_id = keys.key_id
WHERE batches.batch_state != ?;

-- name: UpdateMintingBatchState :exec
WITH target_batch AS (
    -- This CTE is used to fetch the ID of a batch, based on the serialized
    -- internal key associated with the batch. This internal key is as the
    -- actual Taproot internal key to ultimately mint the batch. This pattern
    -- is used in several other queries.
    SELECT batch_id
    FROM asset_minting_batches batches
    JOIN internal_keys keys
        ON batches.batch_id = keys.key_id
    WHERE keys.raw_key = ?
)
UPDATE asset_minting_batches 
SET batch_state = ? 
WHERE batch_id in (SELECT batch_id FROM target_batch);

-- name: InsertAssetSeedling :exec
INSERT INTO asset_seedlings (
    asset_name, asset_type, asset_supply, asset_meta,
    emission_enabled, batch_id
) VALUES (
    ?, ?, ?, ?, ?, ?
);

-- name: AllInternalKeys :many
SELECT * 
FROM internal_keys;

-- name: AllMintingBatches :many
SELECT * 
FROM asset_minting_batches
JOIN internal_keys 
ON asset_minting_batches.batch_id = internal_keys.key_id;

-- name: InsertAssetSeedlingIntoBatch :exec
WITH target_key_id AS (
    -- We use this CTE to fetch the key_id of the internal key that's
    -- associated with a given batch. This can only return one value in
    -- practice since raw_key is a unique field. We then use this value below
    -- to insert the seedling and point to the proper batch_id, which is a
    -- foreign key that references the key_id of the internal key.
    SELECT key_id 
    FROM internal_keys keys
    WHERE keys.raw_key = ?
)
INSERT INTO asset_seedlings(
    asset_name, asset_type, asset_supply, asset_meta,
    emission_enabled, batch_id
) VALUES (
    ?, ?, ?, ?, ?, (SELECT key_id FROM target_key_id)
);

-- name: FetchSeedlingsForBatch :many
WITH target_batch(batch_id) AS (
    SELECT batch_id
    FROM asset_minting_batches batches
    JOIN internal_keys keys
        ON batches.batch_id = keys.key_id
    WHERE keys.raw_key = ?
)
SELECT seedling_id, asset_name, asset_type, asset_supply, asset_meta,
    emission_enabled, asset_id, batch_id
FROM asset_seedlings 
WHERE asset_seedlings.batch_id in (SELECT batch_id FROM target_batch);

-- name: UpsertGenesisPoint :one
INSERT INTO genesis_points(
    prev_out
) VALUES (
    ?
) ON CONFLICT (prev_out)
    -- This is a NOP, prev_out is the unique field that caused the conflict.
    DO UPDATE SET prev_out = EXCLUDED.prev_out
RETURNING genesis_id;

-- name: UpsertAssetFamilyKey :one
INSERT INTO asset_families (
    tweaked_fam_key, internal_key_id, genesis_point_id 
) VALUES (
    ?, ?, ?
) ON CONFLICT (tweaked_fam_key)
    -- This is not a NOP, update the genesis point ID in case it wasn't set
    -- before.
    DO UPDATE SET genesis_point_id = EXCLUDED.genesis_point_id
RETURNING family_id;

-- name: InsertAssetFamilySig :one
INSERT INTO asset_family_sigs (
    genesis_sig, gen_asset_id, key_fam_id
) VALUES (
    ?, ?, ?
) RETURNING sig_id;

-- name: InsertGenesisAsset :one
INSERT INTO genesis_assets (
    asset_id, asset_tag, meta_data, output_index, asset_type, genesis_point_id
) VALUES (
    ?, ?, ?, ?, ?, ?
) RETURNING gen_asset_id;

-- name: InsertNewAsset :one
INSERT INTO assets (
    version, script_key_id, asset_id, asset_family_sig_id, script_version, 
    amount, lock_time, relative_lock_time, anchor_utxo_id
) VALUES (
    ?, ?, ?, ?, ?, ?, ?, ?, ?
) RETURNING asset_id;

-- name: FetchAssetsForBatch :many
WITH genesis_info AS (
    -- This CTE is used to fetch the base asset information from disk based on
    -- the raw key of the batch that will ultimately create this set of assets.
    -- To do so, we'll need to traverse a few tables to join the set of assets
    -- with the genesis points, then with the batches that reference this
    -- points, to the internal key that reference the batch, then restricted
    -- for internal keys that match our main batch key.
    SELECT
        gen_asset_id, asset_id, asset_tag, meta_data, output_index, asset_type,
        genesis_points.prev_out prev_out
    FROM genesis_assets
    JOIN genesis_points
        ON genesis_assets.genesis_point_id = genesis_points.genesis_id
    JOIN asset_minting_batches batches
        ON genesis_points.genesis_id = batches.genesis_id
    JOIN internal_keys keys
        ON keys.key_id = batches.batch_id
    WHERE keys.raw_key = ?
), key_fam_info AS (
    -- This CTE is used to perform a series of joins that allow us to extract
    -- the family key information, as well as the family sigs for the series of
    -- assets we care about. We obtain only the assets found in the batch
    -- above, with the WHERE query at the bottom.
    SELECT 
        sig_id, gen_asset_id, genesis_sig, tweaked_fam_key, raw_key, key_index, key_family
    FROM asset_family_sigs sigs
    JOIN asset_families fams
        ON sigs.key_fam_id = fams.family_id
    JOIN internal_keys keys
        ON keys.key_id = fams.internal_key_id
    -- TODO(roasbeef): or can join do this below?
    WHERE sigs.gen_asset_id IN (SELECT gen_asset_id FROM genesis_info)
)
SELECT 
    version, internal_keys.raw_key AS script_key_raw, 
    internal_keys.tweak AS script_key_tweak,
    internal_keys.key_family AS script_key_fam,
    internal_keys.key_index AS script_key_index, key_fam_info.genesis_sig, 
    key_fam_info.tweaked_fam_key, key_fam_info.raw_key AS fam_key_raw,
    key_fam_info.key_family AS fam_key_family, key_fam_info.key_index AS fam_key_index,
    script_version, amount, lock_time, relative_lock_time, 
    genesis_info.asset_id, genesis_info.asset_tag, genesis_info.meta_data, 
    genesis_info.output_index AS genesis_output_index, genesis_info.asset_type,
    genesis_info.prev_out AS genesis_prev_out
FROM assets
JOIN genesis_info
    ON assets.asset_id = genesis_info.gen_asset_id
-- We use a LEFT JOIN here as not every asset has a family key, so this'll
-- generate rows that have NULL values for the faily key fields if an asset
-- doesn't have a family key. See the comment in fetchAssetSprouts for a work
-- around that needs to be used with this query until a sqlc bug is fixed.
LEFT JOIN key_fam_info
    ON assets.asset_id = key_fam_info.gen_asset_id
JOIN internal_keys
    ON assets.script_key_id = internal_keys.key_id;

-- name: QueryAssets :many
WITH genesis_info AS (
    -- This CTE is used to fetch the base asset information from disk based on
    -- the raw key of the batch that will ultimately create this set of assets.
    -- To do so, we'll need to traverse a few tables to join the set of assets
    -- with the genesis points, then with the batches that reference this
    -- points, to the internal key that reference the batch, then restricted
    -- for internal keys that match our main batch key.
    SELECT
        gen_asset_id, asset_id, asset_tag, meta_data, output_index, asset_type,
        genesis_points.prev_out prev_out
    FROM genesis_assets
    JOIN genesis_points
        ON genesis_assets.genesis_point_id = genesis_points.genesis_id
    -- This filter only runs if the asset_id_filter arg was passed in. This
    -- lets us fetch only the assets for this particular asset ID.
    WHERE length(hex(sqlc.narg('asset_id_filter'))) == 0 OR genesis_assets.asset_id = sqlc.narg('asset_id_filter')
), key_fam_info AS (
    -- This CTE is used to perform a series of joins that allow us to extract
    -- the family key information, as well as the family sigs for the series of
    -- assets we care about. We obtain only the assets found in the batch
    -- above, with the WHERE query at the bottom.
    SELECT 
        sig_id, gen_asset_id, genesis_sig, tweaked_fam_key, raw_key, key_index, key_family
    FROM asset_family_sigs sigs
    JOIN asset_families fams
        ON sigs.key_fam_id = fams.family_id
    JOIN internal_keys keys
        ON keys.key_id = fams.internal_key_id
    -- TODO(roasbeef): or can join do this below?
    WHERE sigs.gen_asset_id IN (SELECT gen_asset_id FROM genesis_info) AND
        -- This filter only runs if the asset_id_filter arg was passed in. This
        -- lets us fetch only the assets for this particular key family.
       (length(hex(sqlc.narg('key_fam_filter'))) == 0 OR fams.tweaked_fam_key = sqlc.narg('key_fam_filter'))
)
SELECT 
    assets.asset_id, version, internal_keys.raw_key AS script_key_raw,
    internal_keys.tweak AS script_key_tweak,
    internal_keys.key_family AS script_key_fam,
    internal_keys.key_index AS script_key_index, key_fam_info.genesis_sig, 
    key_fam_info.tweaked_fam_key, key_fam_info.raw_key AS fam_key_raw,
    key_fam_info.key_family AS fam_key_family, key_fam_info.key_index AS fam_key_index,
    script_version, amount, lock_time, relative_lock_time, 
    genesis_info.asset_id, genesis_info.asset_tag, genesis_info.meta_data, 
    genesis_info.output_index AS genesis_output_index, genesis_info.asset_type,
    genesis_info.prev_out AS genesis_prev_out,
    txns.raw_tx AS anchor_tx, txns.txid AS anchor_txid, txns.block_hash AS anchor_block_hash,
    utxos.outpoint AS anchor_outpoint
FROM assets
JOIN genesis_info
    ON assets.asset_id = genesis_info.gen_asset_id
-- We use a LEFT JOIN here as not every asset has a family key, so this'll
-- generate rows that have NULL values for the family key fields if an asset
-- doesn't have a family key. See the comment in fetchAssetSprouts for a work
-- around that needs to be used with this query until a sqlc bug is fixed.
LEFT JOIN key_fam_info
    ON assets.asset_id = key_fam_info.gen_asset_id
JOIN internal_keys
    ON assets.script_key_id = internal_keys.key_id
JOIN managed_utxos utxos
    ON assets.anchor_utxo_id = utxos.utxo_id AND
        (length(hex(sqlc.narg('anchor_point'))) == 0 OR utxos.outpoint = sqlc.narg('anchor_point'))
JOIN chain_txns txns
    ON utxos.txn_id = txns.txn_id
-- This clause is used to select specific assets for a asset ID, general
-- channel balances, and also coin selection. We use the sqlc.narg feature to
-- make the entire statement evaluate to true, if none of these extra args are
-- specified.
WHERE (
    assets.amount >= COALESCE(sqlc.narg('min_amt'), assets.amount)
);

-- TODO(roasbeef): join on managed utxo ID
-- * group by asset_id

-- name: AllAssets :many
SELECT * 
FROM assets;

-- name: AssetsInBatch :many
SELECT
    gen_asset_id, asset_id, asset_tag, meta_data, output_index, asset_type,
    genesis_points.prev_out prev_out
FROM genesis_assets
JOIN genesis_points
    ON genesis_assets.genesis_point_id = genesis_points.genesis_id
JOIN asset_minting_batches batches
    ON genesis_points.genesis_id = batches.genesis_id
JOIN internal_keys keys
    ON keys.key_id = batches.batch_id
WHERE keys.raw_key = ?;

-- name: BindMintingBatchWithTx :exec
WITH target_batch AS (
    SELECT batch_id
    FROM asset_minting_batches batches
    JOIN internal_keys keys
        ON batches.batch_id = keys.key_id
    WHERE keys.raw_key = ?
)
UPDATE asset_minting_batches 
SET minting_tx_psbt = ?, minting_output_index = ?, genesis_id = ?
WHERE batch_id IN (SELECT batch_id FROM target_batch);

-- name: UpdateBatchGenesisTx :exec
WITH target_batch AS (
    SELECT batch_id
    FROM asset_minting_batches batches
    JOIN internal_keys keys
        ON batches.batch_id = keys.key_id
    WHERE keys.raw_key = ?
)
UPDATE asset_minting_batches
SET minting_tx_psbt = ?
WHERE batch_id in (SELECT batch_id FROM target_batch);

-- name: UpsertChainTx :one
INSERT INTO chain_txns (
    txid, raw_tx, block_height, block_hash, tx_index
) VALUES (
    ?, ?, sqlc.narg('block_height'), sqlc.narg('block_hash'),
    sqlc.narg('tx_index')
) ON CONFLICT (txid)
    -- Not a NOP but instead update any nullable fields that aren't null in the
    -- args.
    DO UPDATE SET block_height = IFNULL(EXCLUDED.block_height, block_height),
                  block_hash = IFNULL(EXCLUDED.block_hash, block_hash),
                  tx_index = IFNULL(EXCLUDED.tx_index, tx_index)
RETURNING txn_id;

-- name: FetchChainTx :one
SELECT *
FROM chain_txns
WHERE txid = ?;

-- name: UpsertManagedUTXO :one
WITH target_key(key_id) AS (
    SELECT key_id
    FROM internal_keys
    WHERE raw_key = ?
)
INSERT INTO managed_utxos (
    outpoint, amt_sats, internal_key_id, tapscript_sibling, taro_root, txn_id
) VALUES (
    ?, ?, (SELECT key_id FROM target_key), ?, ?, ?
) ON CONFLICT (outpoint)
   -- Not a NOP but instead update any nullable fields that aren't null in the
   -- args.
   DO UPDATE SET tapscript_sibling = IFNULL(EXCLUDED.tapscript_sibling, tapscript_sibling)
RETURNING utxo_id;

-- name: FetchManagedUTXO :one
SELECT *
FROM managed_utxos utxos
JOIN internal_keys keys
    ON utxos.internal_key_id = keys.key_id
WHERE (
    txn_id = COALESCE(sqlc.narg('txn_id'), txn_id) AND
    (length(hex(sqlc.narg('outpoint'))) == 0 OR utxos.outpoint = sqlc.narg('outpoint'))
);

-- name: AnchorPendingAssets :exec
WITH assets_to_update AS (
    SELECT script_key_id
    FROM assets 
    JOIN genesis_assets 
        ON assets.asset_id = genesis_assets.gen_asset_id
    JOIN genesis_points
        ON genesis_points.genesis_id = genesis_assets.genesis_point_id
    WHERE prev_out = ?
)
UPDATE assets
SET anchor_utxo_id = ?
WHERE script_key_id in (SELECT script_key_id FROM assets_to_update);

-- name: AssetsByGenesisPoint :many
SELECT *
FROM assets 
JOIN genesis_assets 
    ON assets.asset_id = genesis_assets.gen_asset_id
JOIN genesis_points
    ON genesis_points.genesis_id = genesis_assets.genesis_point_id
WHERE prev_out = ?;

-- name: GenesisAssets :many
SELECT * 
FROM genesis_assets;

-- name: GenesisPoints :many
SELECT * 
FROM genesis_points;

-- name: FetchAssetsByAnchorTx :many
SELECT *
FROM assets
WHERE anchor_utxo_id = ?;

-- name: AnchorGenesisPoint :exec
WITH target_point(genesis_id) AS (
    SELECT genesis_id
    FROM genesis_points
    WHERE genesis_points.prev_out = ?
)
UPDATE genesis_points
SET anchor_tx_id = ?
WHERE genesis_id in (SELECT genesis_id FROM target_point);

-- name: FetchGenesisPointByAnchorTx :one
SELECT * 
FROM genesis_points
WHERE anchor_tx_id = ?;

-- name: ConfirmChainTx :exec
WITH target_txn(txn_id) AS (
    SELECT anchor_tx_id
    FROM genesis_points points
    JOIN asset_minting_batches batches
        ON batches.genesis_id = points.genesis_id
    JOIN internal_keys keys
        ON batches.batch_id = keys.key_id
    WHERE keys.raw_key = ?
)
UPDATE chain_txns
SET block_height = ?, block_hash = ?, tx_index = ?
WHERE txn_id in (SELECT txn_id FROm target_txn);

-- name: UpsertAssetProof :exec
WITH target_asset(asset_id) AS (
    SELECT asset_id
    FROM assets
    JOIN internal_keys keys
        ON keys.key_id = assets.script_key_id
    WHERE keys.raw_key = ?
)
INSERT INTO asset_proofs (
    asset_id, proof_file
) VALUES (
    (SELECT asset_id FROM target_asset), ?
) ON CONFLICT (asset_id)
    -- This is not a NOP, update the proof file in case it wasn't set before.
    DO UPDATE SET proof_file = EXCLUDED.proof_file;

-- name: FetchAssetProofs :many
WITH asset_info AS (
    SELECT assets.asset_id, keys.raw_key
    FROM assets
    JOIN internal_keys keys
        ON keys.key_id = assets.script_key_id
)
SELECT asset_info.raw_key AS script_key, asset_proofs.proof_file
FROM asset_proofs
JOIN asset_info
    ON asset_info.asset_id = asset_proofs.asset_id;

-- name: FetchAssetProof :one
WITH asset_info AS (
    SELECT assets.asset_id, keys.raw_key
    FROM assets
    JOIN internal_keys keys
        ON keys.key_id = assets.script_key_id
    WHERE keys.raw_key = ?
)
SELECT asset_info.raw_key AS script_key, asset_proofs.proof_file
FROM asset_proofs
JOIN asset_info
    ON asset_info.asset_id = asset_proofs.asset_id;

-- name: InsertAssetWitness :exec
INSERT INTO asset_witnesses (
    asset_id, prev_out_point, prev_asset_id, prev_script_key, witness_stack,
    split_commitment_proof
) VALUES (
    ?, ?, ?, ?, ?, ?
);

-- name: FetchAssetWitnesses :many
SELECT 
    assets.asset_id, prev_out_point, prev_asset_id, prev_script_key, 
    witness_stack, split_commitment_proof
FROM asset_witnesses
JOIN assets
    ON asset_witnesses.asset_id = assets.asset_id
WHERE (
    (assets.asset_id = sqlc.narg('asset_id')) OR (sqlc.narg('asset_id') IS NULL)
);
