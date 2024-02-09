-- name: UpsertInternalKey :one
INSERT INTO internal_keys (
    raw_key,  key_family, key_index
) VALUES (
    $1, $2, $3
) ON CONFLICT (raw_key)
    -- This is a NOP, raw_key is the unique field that caused the conflict.
    DO UPDATE SET raw_key = EXCLUDED.raw_key
RETURNING key_id;

-- name: NewMintingBatch :exec
INSERT INTO asset_minting_batches (
    batch_state, batch_id, height_hint, creation_time_unix
) VALUES (0, $1, $2, $3);

-- name: FetchMintingBatchesByInverseState :many
SELECT *
FROM asset_minting_batches batches
JOIN internal_keys keys
    ON batches.batch_id = keys.key_id
WHERE batches.batch_state != $1;

-- name: FetchMintingBatch :one
WITH target_batch AS (
    -- This CTE is used to fetch the ID of a batch, based on the serialized
    -- internal key associated with the batch. This internal key is used as the
    -- actual Taproot internal key to ultimately mint the batch. This pattern
    -- is used in several other queries.
    SELECT batch_id
    FROM asset_minting_batches batches
    JOIN internal_keys keys
        ON batches.batch_id = keys.key_id
    WHERE keys.raw_key = $1
)
SELECT *
FROM asset_minting_batches batches
JOIN internal_keys keys
    ON batches.batch_id = keys.key_id
WHERE batch_id in (SELECT batch_id FROM target_batch);

-- name: UpdateMintingBatchState :exec
WITH target_batch AS (
    -- This CTE is used to fetch the ID of a batch, based on the serialized
    -- internal key associated with the batch. This internal key is used as the
    -- actual Taproot internal key to ultimately mint the batch. This pattern
    -- is used in several other queries.
    SELECT batch_id
    FROM asset_minting_batches batches
    JOIN internal_keys keys
        ON batches.batch_id = keys.key_id
    WHERE keys.raw_key = $1
)
UPDATE asset_minting_batches 
SET batch_state = $2
WHERE batch_id in (SELECT batch_id FROM target_batch);

-- name: InsertAssetSeedling :exec
INSERT INTO asset_seedlings (
    asset_name, asset_type, asset_version, asset_supply, asset_meta_id,
    emission_enabled, batch_id, group_genesis_id, group_anchor_id
) VALUES (
   $1, $2, $3, $4, $5, $6, $7,
   sqlc.narg('group_genesis_id'), sqlc.narg('group_anchor_id')
);

-- name: FetchSeedlingID :one
WITH target_key_id AS (
    -- We use this CTE to fetch the key_id of the internal key that's
    -- associated with a given batch. This can only return one value in
    -- practice since raw_key is a unique field. We then use this value below
    -- to select only from seedlings in the specified batch.
    SELECT key_id
    FROM internal_keys keys
    WHERE keys.raw_key = @batch_key
)
SELECT seedling_id
FROM asset_seedlings
WHERE (
    asset_seedlings.batch_id in (SELECT key_id FROM target_key_id) AND
    asset_seedlings.asset_name = @seedling_name
);

-- name: FetchSeedlingByID :one
SELECT *
FROM asset_seedlings
WHERE seedling_id = @seedling_id;

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
    WHERE keys.raw_key = $1
)
INSERT INTO asset_seedlings(
    asset_name, asset_type, asset_version, asset_supply, asset_meta_id,
    emission_enabled, batch_id, group_genesis_id, group_anchor_id
) VALUES (
    $2, $3, $4, $5, $6, $7,
    (SELECT key_id FROM target_key_id),
    sqlc.narg('group_genesis_id'), sqlc.narg('group_anchor_id')
);

-- name: FetchSeedlingsForBatch :many
WITH target_batch(batch_id) AS (
    SELECT batch_id
    FROM asset_minting_batches batches
    JOIN internal_keys keys
        ON batches.batch_id = keys.key_id
    WHERE keys.raw_key = $1
)
SELECT seedling_id, asset_name, asset_type, asset_version, asset_supply, 
    assets_meta.meta_data_hash, assets_meta.meta_data_type, 
    assets_meta.meta_data_blob, emission_enabled, batch_id, 
    group_genesis_id, group_anchor_id
FROM asset_seedlings 
LEFT JOIN assets_meta
    ON asset_seedlings.asset_meta_id = assets_meta.meta_id
WHERE asset_seedlings.batch_id in (SELECT batch_id FROM target_batch);

-- name: UpsertGenesisPoint :one
INSERT INTO genesis_points(
    prev_out
) VALUES (
    $1
) ON CONFLICT (prev_out)
    -- This is a NOP, prev_out is the unique field that caused the conflict.
    DO UPDATE SET prev_out = EXCLUDED.prev_out
RETURNING genesis_id;

-- name: UpsertAssetGroupKey :one
INSERT INTO asset_groups (
    tweaked_group_key, tapscript_root, internal_key_id, genesis_point_id 
) VALUES (
    $1, $2, $3, $4
) ON CONFLICT (tweaked_group_key)
    -- This is not a NOP, update the genesis point ID in case it wasn't set
    -- before.
    DO UPDATE SET genesis_point_id = EXCLUDED.genesis_point_id
RETURNING group_id;

-- name: UpsertAssetGroupWitness :one
INSERT INTO asset_group_witnesses (
    witness_stack, gen_asset_id, group_key_id
) VALUES (
    $1, $2, $3
) ON CONFLICT (gen_asset_id)
    -- This is a NOP, gen_asset_id is the unique field that caused the conflict.
    DO UPDATE SET gen_asset_id = EXCLUDED.gen_asset_id
RETURNING witness_id;

-- name: UpsertGenesisAsset :one
WITH target_meta_id AS (
    SELECT meta_id
    FROM assets_meta
    WHERE meta_data_hash = $1
)
INSERT INTO genesis_assets (
    asset_id, asset_tag, meta_data_id, output_index, asset_type, genesis_point_id
) VALUES (
    $2, $3, (SELECT meta_id FROM target_meta_id), $4, $5, $6
) ON CONFLICT (asset_id)
    -- This is a NOP, asset_id is the unique field that caused the conflict.
    DO UPDATE SET asset_id = EXCLUDED.asset_id
RETURNING gen_asset_id;

-- name: InsertNewAsset :one
INSERT INTO assets (
    genesis_id, version, script_key_id, asset_group_witness_id, script_version, 
    amount, lock_time, relative_lock_time, anchor_utxo_id, spent
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10
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
        gen_asset_id, asset_id, asset_tag, output_index, asset_type,
        genesis_points.prev_out prev_out, 
        assets_meta.meta_data_hash meta_hash, assets_meta.meta_data_type meta_type,
        assets_meta.meta_data_blob meta_blob
    FROM genesis_assets
    LEFT JOIN assets_meta
        ON genesis_assets.meta_data_id = assets_meta.meta_id
    JOIN genesis_points
        ON genesis_assets.genesis_point_id = genesis_points.genesis_id
    JOIN asset_minting_batches batches
        ON genesis_points.genesis_id = batches.genesis_id
    JOIN internal_keys keys
        ON keys.key_id = batches.batch_id
    WHERE keys.raw_key = $1
), key_group_info AS (
    -- This CTE is used to perform a series of joins that allow us to extract
    -- the group key information, as well as the group sigs for the series of
    -- assets we care about. We obtain only the assets found in the batch
    -- above, with the WHERE query at the bottom.
    SELECT 
        witness_id, gen_asset_id, witness_stack, tapscript_root,
        tweaked_group_key, raw_key, key_index, key_family
    FROM asset_group_witnesses wit
    JOIN asset_groups groups
        ON wit.group_key_id = groups.group_id
    JOIN internal_keys keys
        ON keys.key_id = groups.internal_key_id
    -- TODO(roasbeef): or can join do this below?
    WHERE wit.gen_asset_id IN (SELECT gen_asset_id FROM genesis_info)
)
SELECT 
    version, script_keys.tweak, script_keys.tweaked_script_key, 
    internal_keys.raw_key AS script_key_raw,
    internal_keys.key_family AS script_key_fam,
    internal_keys.key_index AS script_key_index,
    key_group_info.tapscript_root, 
    key_group_info.witness_stack, 
    key_group_info.tweaked_group_key,
    key_group_info.raw_key AS group_key_raw,
    key_group_info.key_family AS group_key_family,
    key_group_info.key_index AS group_key_index,
    script_version, amount, lock_time, relative_lock_time, spent,
    genesis_info.asset_id, genesis_info.asset_tag, genesis_info.meta_hash, 
    genesis_info.meta_type, genesis_info.meta_blob, 
    genesis_info.output_index AS genesis_output_index, genesis_info.asset_type,
    genesis_info.prev_out AS genesis_prev_out
FROM assets
JOIN genesis_info
    ON assets.genesis_id = genesis_info.gen_asset_id
-- We use a LEFT JOIN here as not every asset has a group key, so this'll
-- generate rows that have NULL values for the faily key fields if an asset
-- doesn't have a group key. See the comment in fetchAssetSprouts for a work
-- around that needs to be used with this query until a sqlc bug is fixed.
LEFT JOIN key_group_info
    ON assets.genesis_id = key_group_info.gen_asset_id
JOIN script_keys
    on assets.script_key_id = script_keys.script_key_id
JOIN internal_keys
    ON script_keys.internal_key_id = internal_keys.key_id;

-- name: SetAssetSpent :one
WITH target_asset(asset_id) AS (
    SELECT assets.asset_id
    FROM assets
    JOIN script_keys
      ON assets.script_key_id = script_keys.script_key_id
    JOIN genesis_assets
      ON assets.genesis_id = genesis_assets.gen_asset_id
    WHERE script_keys.tweaked_script_key = @script_key
     AND genesis_assets.asset_id = @gen_asset_id
    -- TODO(guggero): Fix this by disallowing multiple assets with the same
    -- script key!
    LIMIT 1
)
UPDATE assets
SET spent = TRUE
WHERE asset_id = (SELECT asset_id FROM target_asset)
RETURNING assets.asset_id;

-- name: QueryAssetBalancesByAsset :many
SELECT
    genesis_info_view.asset_id, version, SUM(amount) balance,
    genesis_info_view.asset_tag, genesis_info_view.meta_hash,
    genesis_info_view.asset_type, genesis_info_view.output_index,
    genesis_info_view.prev_out AS genesis_point
FROM assets
JOIN genesis_info_view
    ON assets.genesis_id = genesis_info_view.gen_asset_id AND
      (genesis_info_view.asset_id = sqlc.narg('asset_id_filter') OR
        sqlc.narg('asset_id_filter') IS NULL)
-- We use a LEFT JOIN here as not every asset has a group key, so this'll
-- generate rows that have NULL values for the group key fields if an asset
-- doesn't have a group key. See the comment in fetchAssetSprouts for a work
-- around that needs to be used with this query until a sqlc bug is fixed.
LEFT JOIN key_group_info_view
    ON assets.genesis_id = key_group_info_view.gen_asset_id
WHERE spent = FALSE
GROUP BY assets.genesis_id, genesis_info_view.asset_id,
         version, genesis_info_view.asset_tag, genesis_info_view.meta_hash,
         genesis_info_view.asset_type, genesis_info_view.output_index,
         genesis_info_view.prev_out;

-- name: QueryAssetBalancesByGroup :many
SELECT
    key_group_info_view.tweaked_group_key, SUM(amount) balance
FROM assets
JOIN key_group_info_view
    ON assets.genesis_id = key_group_info_view.gen_asset_id AND
      (key_group_info_view.tweaked_group_key = sqlc.narg('key_group_filter') OR
        sqlc.narg('key_group_filter') IS NULL)
WHERE spent = FALSE
GROUP BY key_group_info_view.tweaked_group_key;

-- name: FetchGroupedAssets :many
SELECT
    assets.asset_id AS asset_primary_key,
    amount, lock_time, relative_lock_time, spent, 
    genesis_info_view.asset_id AS asset_id,
    genesis_info_view.asset_tag,
    genesis_info_view.meta_Hash, 
    genesis_info_view.asset_type,
    key_group_info_view.tweaked_group_key,
    version AS asset_version
FROM assets
JOIN genesis_info_view
    ON assets.genesis_id = genesis_info_view.gen_asset_id
JOIN key_group_info_view
    ON assets.genesis_id = key_group_info_view.gen_asset_id
WHERE spent = false;

-- name: FetchGroupByGroupKey :one
SELECT 
    key_group_info_view.gen_asset_id AS gen_asset_id,
    key_group_info_view.raw_key AS raw_key,
    key_group_info_view.key_index AS key_index,
    key_group_info_view.key_family AS key_family,
    key_group_info_view.tapscript_root AS tapscript_root,
    key_group_info_view.witness_stack AS witness_stack
FROM key_group_info_view
WHERE (
    key_group_info_view.tweaked_group_key = @group_key
)
-- Sort and limit to return the genesis ID for initial genesis of the group.
ORDER BY key_group_info_view.witness_id
LIMIT 1;

-- name: FetchGroupByGenesis :one
SELECT
    key_group_info_view.tweaked_group_key AS tweaked_group_key,
    key_group_info_view.raw_key AS raw_key,
    key_group_info_view.key_index AS key_index,
    key_group_info_view.key_family AS key_family,
    key_group_info_view.tapscript_root AS tapscript_root,
    key_group_info_view.witness_stack AS witness_stack
FROM key_group_info_view
WHERE (
    key_group_info_view.gen_asset_id = @genesis_id
);

-- name: QueryAssets :many
SELECT
    assets.asset_id AS asset_primary_key, assets.genesis_id, version, spent,
    script_keys.tweak AS script_key_tweak, 
    script_keys.tweaked_script_key, 
    internal_keys.raw_key AS script_key_raw,
    internal_keys.key_family AS script_key_fam,
    internal_keys.key_index AS script_key_index,
    key_group_info_view.tapscript_root, 
    key_group_info_view.witness_stack, 
    key_group_info_view.tweaked_group_key,
    key_group_info_view.raw_key AS group_key_raw,
    key_group_info_view.key_family AS group_key_family,
    key_group_info_view.key_index AS group_key_index,
    script_version, amount, lock_time, relative_lock_time, 
    genesis_info_view.asset_id AS asset_id,
    genesis_info_view.asset_tag,
    genesis_info_view.meta_hash, 
    genesis_info_view.output_index AS genesis_output_index,
    genesis_info_view.asset_type,
    genesis_info_view.prev_out AS genesis_prev_out,
    txns.raw_tx AS anchor_tx,
    txns.txid AS anchor_txid,
    txns.block_hash AS anchor_block_hash,
    txns.block_height AS anchor_block_height,
    utxos.outpoint AS anchor_outpoint,
    utxos.tapscript_sibling AS anchor_tapscript_sibling,
    utxos.merkle_root AS anchor_merkle_root,
    utxos.taproot_asset_root AS anchor_taproot_asset_root,
    utxos.lease_owner AS anchor_lease_owner,
    utxos.lease_expiry AS anchor_lease_expiry,
    utxo_internal_keys.raw_key AS anchor_internal_key,
    split_commitment_root_hash, split_commitment_root_value
FROM assets
JOIN genesis_info_view
    ON assets.genesis_id = genesis_info_view.gen_asset_id AND
      (genesis_info_view.asset_id = sqlc.narg('asset_id_filter') OR
        sqlc.narg('asset_id_filter') IS NULL)
-- We use a LEFT JOIN here as not every asset has a group key, so this'll
-- generate rows that have NULL values for the group key fields if an asset
-- doesn't have a group key. See the comment in fetchAssetSprouts for a work
-- around that needs to be used with this query until a sqlc bug is fixed.
LEFT JOIN key_group_info_view
    ON assets.genesis_id = key_group_info_view.gen_asset_id
JOIN script_keys
    ON assets.script_key_id = script_keys.script_key_id AND
      (script_keys.tweaked_script_key = sqlc.narg('tweaked_script_key') OR
       sqlc.narg('tweaked_script_key') IS NULL)
JOIN internal_keys
    ON script_keys.internal_key_id = internal_keys.key_id
JOIN managed_utxos utxos
    ON assets.anchor_utxo_id = utxos.utxo_id AND
      (utxos.outpoint = sqlc.narg('anchor_point') OR
       sqlc.narg('anchor_point') IS NULL) AND
       CASE
           WHEN sqlc.narg('leased') = true THEN
               (utxos.lease_owner IS NOT NULL AND utxos.lease_expiry > @now)
           WHEN sqlc.narg('leased') = false THEN
               (utxos.lease_owner IS NULL OR 
                utxos.lease_expiry IS NULL OR
                utxos.lease_expiry <= @now)
           ELSE TRUE
       END
JOIN internal_keys utxo_internal_keys
    ON utxos.internal_key_id = utxo_internal_keys.key_id
JOIN chain_txns txns
    ON utxos.txn_id = txns.txn_id AND
      COALESCE(txns.block_height, 0) >= COALESCE(sqlc.narg('min_anchor_height'), txns.block_height, 0)
-- This clause is used to select specific assets for a asset ID, general
-- channel balances, and also coin selection. We use the sqlc.narg feature to
-- make the entire statement evaluate to true, if none of these extra args are
-- specified.
WHERE (
    assets.amount >= COALESCE(sqlc.narg('min_amt'), assets.amount) AND
    assets.spent = COALESCE(sqlc.narg('spent'), assets.spent) AND
    (key_group_info_view.tweaked_group_key = sqlc.narg('key_group_filter') OR
      sqlc.narg('key_group_filter') IS NULL) AND
    assets.anchor_utxo_id = COALESCE(sqlc.narg('anchor_utxo_id'), assets.anchor_utxo_id) AND
    assets.genesis_id = COALESCE(sqlc.narg('genesis_id'), assets.genesis_id) AND
    assets.script_key_id = COALESCE(sqlc.narg('script_key_id'), assets.script_key_id)
);

-- name: AllAssets :many
SELECT * 
FROM assets;

-- name: AssetsInBatch :many
SELECT
    gen_asset_id, asset_id, asset_tag, assets_meta.meta_data_hash, 
    output_index, asset_type, genesis_points.prev_out prev_out
FROM genesis_assets
LEFT JOIN assets_meta
    ON genesis_assets.meta_data_id = assets_meta.meta_id
JOIN genesis_points
    ON genesis_assets.genesis_point_id = genesis_points.genesis_id
JOIN asset_minting_batches batches
    ON genesis_points.genesis_id = batches.genesis_id
JOIN internal_keys keys
    ON keys.key_id = batches.batch_id
WHERE keys.raw_key = $1;

-- name: BindMintingBatchWithTx :exec
WITH target_batch AS (
    SELECT batch_id
    FROM asset_minting_batches batches
    JOIN internal_keys keys
        ON batches.batch_id = keys.key_id
    WHERE keys.raw_key = $1
)
UPDATE asset_minting_batches 
SET minting_tx_psbt = $2, change_output_index = $3, genesis_id = $4
WHERE batch_id IN (SELECT batch_id FROM target_batch);

-- name: BindMintingBatchWithTapSibling :exec
WITH target_batch AS (
    SELECT batch_id
    FROM asset_minting_batches batches
    JOIN internal_keys keys
        ON batches.batch_id = keys.key_id
    WHERE keys.raw_key = $1
)
UPDATE asset_minting_batches
SET tapscript_sibling = $2
WHERE batch_id IN (SELECT batch_id FROM target_batch);

-- name: UpdateBatchGenesisTx :exec
WITH target_batch AS (
    SELECT batch_id
    FROM asset_minting_batches batches
    JOIN internal_keys keys
        ON batches.batch_id = keys.key_id
    WHERE keys.raw_key = $1
)
UPDATE asset_minting_batches
SET minting_tx_psbt = $2
WHERE batch_id in (SELECT batch_id FROM target_batch);

-- name: UpsertChainTx :one
INSERT INTO chain_txns (
    txid, raw_tx, chain_fees, block_height, block_hash, tx_index
) VALUES (
    $1, $2, $3, sqlc.narg('block_height'), sqlc.narg('block_hash'),
    sqlc.narg('tx_index')
) ON CONFLICT (txid)
    -- Not a NOP but instead update any nullable fields that aren't null in the
    -- args.
    DO UPDATE SET block_height = COALESCE(EXCLUDED.block_height, chain_txns.block_height),
                  block_hash = COALESCE(EXCLUDED.block_hash, chain_txns.block_hash),
                  tx_index = COALESCE(EXCLUDED.tx_index, chain_txns.tx_index)
RETURNING txn_id;

-- name: FetchChainTx :one
SELECT *
FROM chain_txns
WHERE txid = $1;

-- name: UpsertManagedUTXO :one
WITH target_key(key_id) AS (
    SELECT key_id
    FROM internal_keys
    WHERE raw_key = $1
)
INSERT INTO managed_utxos (
    outpoint, amt_sats, internal_key_id, tapscript_sibling, merkle_root, txn_id,
    taproot_asset_root
) VALUES (
    $2, $3, (SELECT key_id FROM target_key), $4, $5, $6, $7
) ON CONFLICT (outpoint)
   -- Not a NOP but instead update any nullable fields that aren't null in the
   -- args.
   DO UPDATE SET tapscript_sibling = COALESCE(EXCLUDED.tapscript_sibling, managed_utxos.tapscript_sibling)
RETURNING utxo_id;

-- name: FetchManagedUTXO :one
SELECT *
FROM managed_utxos utxos
JOIN internal_keys keys
    ON utxos.internal_key_id = keys.key_id
WHERE (
    (txn_id = sqlc.narg('txn_id') OR sqlc.narg('txn_id') IS NULL) AND
    (utxos.outpoint = sqlc.narg('outpoint') OR sqlc.narg('outpoint') IS NULL)
);

-- name: FetchManagedUTXOs :many
SELECT *
FROM managed_utxos utxos
JOIN internal_keys keys
    ON utxos.internal_key_id = keys.key_id;

-- name: AnchorPendingAssets :exec
WITH assets_to_update AS (
    SELECT script_key_id
    FROM assets 
    JOIN genesis_assets 
        ON assets.genesis_id = genesis_assets.gen_asset_id
    JOIN genesis_points
        ON genesis_points.genesis_id = genesis_assets.genesis_point_id
    WHERE prev_out = $1
)
UPDATE assets
SET anchor_utxo_id = $2
WHERE script_key_id in (SELECT script_key_id FROM assets_to_update);

-- name: AssetsByGenesisPoint :many
SELECT *
FROM assets 
JOIN genesis_assets 
    ON assets.genesis_id = genesis_assets.gen_asset_id
JOIN genesis_points
    ON genesis_points.genesis_id = genesis_assets.genesis_point_id
WHERE prev_out = $1;

-- name: GenesisAssets :many
SELECT * 
FROM genesis_assets;

-- name: GenesisPoints :many
SELECT *
FROM genesis_points;

-- name: FetchGenesisID :one
WITH target_point(genesis_id) AS (
    SELECT genesis_id
    FROM genesis_points
    WHERE genesis_points.prev_out = @prev_out
)
SELECT gen_asset_id
FROM genesis_assets
LEFT JOIN assets_meta   
    ON genesis_assets.meta_data_id = assets_meta.meta_id
WHERE (
    genesis_assets.genesis_point_id IN (SELECT genesis_id FROM target_point) AND
    genesis_assets.asset_id = @asset_id AND
    genesis_assets.asset_tag = @asset_tag AND
    assets_meta.meta_data_hash = @meta_hash AND
    genesis_assets.output_index = @output_index AND
    genesis_assets.asset_type = @asset_type
);

-- name: FetchAssetsByAnchorTx :many
SELECT *
FROM assets
WHERE anchor_utxo_id = $1;

-- name: AnchorGenesisPoint :exec
WITH target_point(genesis_id) AS (
    SELECT genesis_id
    FROM genesis_points
    WHERE genesis_points.prev_out = $1
)
UPDATE genesis_points
SET anchor_tx_id = $2
WHERE genesis_id in (SELECT genesis_id FROM target_point);

-- name: FetchGenesisPointByAnchorTx :one
SELECT * 
FROM genesis_points
WHERE anchor_tx_id = $1;

-- name: FetchGenesisByID :one
SELECT
    asset_id, asset_tag, assets_meta.meta_data_hash, output_index, asset_type,
    genesis_points.prev_out prev_out
FROM genesis_assets
LEFT JOIN assets_meta
    ON genesis_assets.meta_data_id = assets_meta.meta_id
JOIN genesis_points
  ON genesis_assets.genesis_point_id = genesis_points.genesis_id
WHERE gen_asset_id = $1;

-- name: ConfirmChainTx :exec
WITH target_txn(txn_id) AS (
    SELECT anchor_tx_id
    FROM genesis_points points
    JOIN asset_minting_batches batches
        ON batches.genesis_id = points.genesis_id
    JOIN internal_keys keys
        ON batches.batch_id = keys.key_id
    WHERE keys.raw_key = $1
)
UPDATE chain_txns
SET block_height = $2, block_hash = $3, tx_index = $4
WHERE txn_id in (SELECT txn_id FROM target_txn);

-- name: UpsertAssetProof :exec
WITH target_asset(asset_id) AS (
    SELECT asset_id
    FROM assets
    JOIN script_keys 
        ON assets.script_key_id = script_keys.script_key_id
    JOIN managed_utxos utxos
        ON assets.anchor_utxo_id = utxos.utxo_id
    WHERE
        (script_keys.tweaked_script_key = sqlc.narg('tweaked_script_key')
            OR sqlc.narg('tweaked_script_key') IS NULL)
        AND (utxos.outpoint = sqlc.narg('outpoint')
            OR sqlc.narg('outpoint') IS NULL)
)
INSERT INTO asset_proofs (
    asset_id, proof_file
) VALUES (
    (SELECT asset_id FROM target_asset), @proof_file
) ON CONFLICT (asset_id)
    -- This is not a NOP, we always overwrite the proof with the new one.
    DO UPDATE SET proof_file = EXCLUDED.proof_file;

-- name: UpsertAssetProofByID :exec
INSERT INTO asset_proofs (
    asset_id, proof_file
) VALUES (
    @asset_id, @proof_file
) ON CONFLICT (asset_id)
    -- This is not a NOP, we always overwrite the proof with the new one.
    DO UPDATE SET proof_file = EXCLUDED.proof_file;

-- name: FetchAssetProofs :many
WITH asset_info AS (
    SELECT assets.asset_id, script_keys.tweaked_script_key
    FROM assets
    JOIN script_keys
        ON assets.script_key_id = script_keys.script_key_id
)
SELECT asset_info.tweaked_script_key AS script_key, asset_proofs.proof_file
FROM asset_proofs
JOIN asset_info
    ON asset_info.asset_id = asset_proofs.asset_id;

-- name: FetchAssetProofsByAssetID :many
WITH asset_info AS (
    SELECT assets.asset_id, script_keys.tweaked_script_key
    FROM assets
    JOIN script_keys
        ON assets.script_key_id = script_keys.script_key_id
    JOIN genesis_assets gen
        ON assets.genesis_id = gen.gen_asset_id
    WHERE gen.asset_id = $1
)
SELECT asset_info.tweaked_script_key AS script_key, asset_proofs.proof_file
FROM asset_proofs
JOIN asset_info
    ON asset_info.asset_id = asset_proofs.asset_id;

-- name: FetchAssetProof :many
WITH asset_info AS (
    SELECT assets.asset_id, script_keys.tweaked_script_key, utxos.outpoint
    FROM assets
    JOIN script_keys
        ON assets.script_key_id = script_keys.script_key_id
    JOIN managed_utxos utxos
        ON assets.anchor_utxo_id = utxos.utxo_id
   WHERE script_keys.tweaked_script_key = $1
     AND (utxos.outpoint = sqlc.narg('outpoint') OR sqlc.narg('outpoint') IS NULL)
)
SELECT asset_info.tweaked_script_key AS script_key, asset_proofs.proof_file,
       asset_info.asset_id as asset_id, asset_proofs.proof_id as proof_id,
       asset_info.outpoint as outpoint
FROM asset_proofs
JOIN asset_info
  ON asset_info.asset_id = asset_proofs.asset_id;

-- name: HasAssetProof :one
WITH asset_info AS (
    SELECT assets.asset_id
    FROM assets
    JOIN script_keys
        ON assets.script_key_id = script_keys.script_key_id
    WHERE script_keys.tweaked_script_key = $1
)
SELECT COUNT(asset_info.asset_id) > 0 as has_proof
FROM asset_proofs
JOIN asset_info
    ON asset_info.asset_id = asset_proofs.asset_id;

-- name: UpsertAssetWitness :exec
INSERT INTO asset_witnesses (
    asset_id, prev_out_point, prev_asset_id, prev_script_key, witness_stack,
    split_commitment_proof, witness_index
) VALUES (
    $1, $2, $3, $4, $5, $6, $7
)  ON CONFLICT (asset_id, witness_index)
    -- We overwrite the witness with the new one.
    DO UPDATE SET prev_out_point = EXCLUDED.prev_out_point,
                  prev_asset_id = EXCLUDED.prev_asset_id,
                  prev_script_key = EXCLUDED.prev_script_key,
                  witness_stack = EXCLUDED.witness_stack,
                  split_commitment_proof = EXCLUDED.split_commitment_proof;

-- name: FetchAssetWitnesses :many
SELECT 
    assets.asset_id, prev_out_point, prev_asset_id, prev_script_key, 
    witness_stack, split_commitment_proof
FROM asset_witnesses
JOIN assets
    ON asset_witnesses.asset_id = assets.asset_id
WHERE (
    (assets.asset_id = sqlc.narg('asset_id')) OR (sqlc.narg('asset_id') IS NULL)
)
ORDER BY witness_index;

-- name: DeleteManagedUTXO :exec
DELETE FROM managed_utxos
WHERE outpoint = $1;

-- name: UpdateUTXOLease :exec
UPDATE managed_utxos
SET lease_owner = @lease_owner, lease_expiry = @lease_expiry
WHERE outpoint = @outpoint;

-- name: DeleteUTXOLease :exec
UPDATE managed_utxos
SET lease_owner = NULL, lease_expiry = NULL
WHERE outpoint = @outpoint;

-- name: DeleteExpiredUTXOLeases :exec
UPDATE managed_utxos
SET lease_owner = NULL, lease_expiry = NULL
WHERE lease_owner IS NOT NULL AND
      lease_expiry IS NOT NULL AND
      lease_expiry < @now;

-- name: ConfirmChainAnchorTx :exec
UPDATE chain_txns
SET block_height = $2, block_hash = $3, tx_index = $4
WHERE txid = $1;

-- name: UpsertScriptKey :one
INSERT INTO script_keys (
    internal_key_id, tweaked_script_key, tweak
) VALUES (
    $1, $2, $3
)  ON CONFLICT (tweaked_script_key)
    -- As a NOP, we just set the script key to the one that triggered the
    -- conflict.
    DO UPDATE SET tweaked_script_key = EXCLUDED.tweaked_script_key
RETURNING script_key_id;

-- name: FetchScriptKeyIDByTweakedKey :one
SELECT script_key_id
FROM script_keys
WHERE tweaked_script_key = $1;

-- name: FetchScriptKeyByTweakedKey :one
SELECT tweak, raw_key, key_family, key_index
FROM script_keys
JOIN internal_keys
  ON script_keys.internal_key_id = internal_keys.key_id
WHERE script_keys.tweaked_script_key = $1;

-- name: FetchInternalKeyLocator :one
SELECT key_family, key_index
FROM internal_keys
WHERE raw_key = $1;

-- name: UpsertTapscriptTreeRootHash :one
INSERT INTO tapscript_roots (
    root_hash, branch_only
) VALUES (
    $1, $2
) ON CONFLICT (root_hash)
    -- This is a NOP, the root_hash is the unique field that caused the
    -- conflict. The tree should be deleted before switching between branch and
    -- leaf storage for the same root hash.
    DO UPDATE SET root_hash = EXCLUDED.root_hash
RETURNING root_id;

-- name: UpsertTapscriptTreeNode :one
INSERT INTO tapscript_nodes (
    raw_node
) VALUES (
    $1
) ON CONFLICT (raw_node)
    -- This is a NOP, raw_node is the unique field that caused the conflict.
    DO UPDATE SET raw_node = EXCLUDED.raw_node
RETURNING node_id;

-- name: UpsertTapscriptTreeEdge :one
INSERT INTO tapscript_edges (
    root_hash_id, node_index, raw_node_id
) VALUES (
    $1, $2, $3
) ON CONFLICT (root_hash_id, node_index, raw_node_id)
    -- This is a NOP, root_hash_id, node_index, and raw_node_id are the unique
    -- fields that caused the conflict.
    DO UPDATE SET root_hash_id = EXCLUDED.root_hash_id,
    node_index = EXCLUDED.node_index, raw_node_id = EXCLUDED.raw_node_id
RETURNING edge_id;

-- name: FetchTapscriptTree :many
WITH tree_info AS (
    -- This CTE is used to fetch all edges that link the given tapscript tree
    -- root hash to child nodes. Each edge also contains the index of the child
    -- node in the tapscript tree.
    SELECT tapscript_roots.branch_only, tapscript_edges.raw_node_id,
        tapscript_edges.node_index
    FROM tapscript_roots
    JOIN tapscript_edges
        ON tapscript_roots.root_id = tapscript_edges.root_hash_id
    WHERE tapscript_roots.root_hash = @root_hash
)
SELECT tree_info.branch_only, tapscript_nodes.raw_node
FROM tapscript_nodes
JOIN tree_info
    ON tree_info.raw_node_id = tapscript_nodes.node_id
-- Sort the nodes by node_index here instead of returning the indices.
ORDER BY tree_info.node_index ASC;

-- name: DeleteTapscriptTreeEdges :exec
WITH tree_info AS (
    -- This CTE is used to fetch all edges that link the given tapscript tree
    -- root hash to child nodes.
    SELECT tapscript_edges.edge_id
    FROM tapscript_edges
    JOIN tapscript_roots
        ON tapscript_edges.root_hash_id = tapscript_roots.root_id
    WHERE tapscript_roots.root_hash = @root_hash
)
DELETE FROM tapscript_edges
WHERE edge_id IN (SELECT edge_id FROM tree_info);

-- name: DeleteTapscriptTreeNodes :exec
DELETE FROM tapscript_nodes
WHERE NOT EXISTS (
    SELECT 1
        FROM tapscript_edges
        -- Delete any node that is not referenced by any edge.
        WHERE tapscript_edges.raw_node_id = tapscript_nodes.node_id
);

-- name: DeleteTapscriptTreeRoot :exec
DELETE FROM tapscript_roots
WHERE root_hash = @root_hash;

-- name: FetchGenesisByAssetID :one
SELECT * 
FROM genesis_info_view
WHERE asset_id = $1;

-- name: UpsertAssetMeta :one
INSERT INTO assets_meta (
    meta_data_hash, meta_data_blob, meta_data_type
) VALUES (
    $1, $2, $3 
) ON CONFLICT (meta_data_hash)
    -- In this case, we may be inserting the data+type for an existing blob. So
    -- we'll set both of those values. At this layer we assume the meta hash
    -- has been validated elsewhere.
    DO UPDATE SET meta_data_blob = COALESCE(EXCLUDED.meta_data_blob, assets_meta.meta_data_blob), 
                  meta_data_type = COALESCE(EXCLUDED.meta_data_type, assets_meta.meta_data_type)
        
RETURNING meta_id;

-- name: FetchAssetMeta :one
SELECT meta_data_hash, meta_data_blob, meta_data_type
FROM assets_meta
WHERE meta_id = $1;

-- name: FetchAssetMetaByHash :one
SELECT meta_data_hash, meta_data_blob, meta_data_type
FROM assets_meta
WHERE meta_data_hash = $1;

-- name: FetchAssetMetaForAsset :one
SELECT meta_data_hash, meta_data_blob, meta_data_type
FROM genesis_assets assets
JOIN assets_meta
    ON assets.meta_data_id = assets_meta.meta_id
WHERE assets.asset_id = $1;
