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
    WHERE keys.raw_key = $1
)
UPDATE asset_minting_batches 
SET batch_state = $2
WHERE batch_id in (SELECT batch_id FROM target_batch);

-- name: InsertAssetSeedling :exec
INSERT INTO asset_seedlings (
    asset_name, asset_type, asset_supply, asset_meta,
    emission_enabled, batch_id, group_genesis_id
) VALUES (
   $1, $2, $3, $4, $5, $6, sqlc.narg('group_genesis_id')
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
    WHERE keys.raw_key = $1
)
INSERT INTO asset_seedlings(
    asset_name, asset_type, asset_supply, asset_meta,
    emission_enabled, batch_id, group_genesis_id
) VALUES (
    $2, $3, $4, $5, $6,
    (SELECT key_id FROM target_key_id), sqlc.narg('group_genesis_id')
);

-- name: FetchSeedlingsForBatch :many
WITH target_batch(batch_id) AS (
    SELECT batch_id
    FROM asset_minting_batches batches
    JOIN internal_keys keys
        ON batches.batch_id = keys.key_id
    WHERE keys.raw_key = $1
)
SELECT seedling_id, asset_name, asset_type, asset_supply, asset_meta,
    emission_enabled, batch_id, group_genesis_id
FROM asset_seedlings 
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
    tweaked_group_key, internal_key_id, genesis_point_id 
) VALUES (
    $1, $2, $3
) ON CONFLICT (tweaked_group_key)
    -- This is not a NOP, update the genesis point ID in case it wasn't set
    -- before.
    DO UPDATE SET genesis_point_id = EXCLUDED.genesis_point_id
RETURNING group_id;

-- name: UpsertAssetGroupSig :one
INSERT INTO asset_group_sigs (
    genesis_sig, gen_asset_id, group_key_id
) VALUES (
    $1, $2, $3
) ON CONFLICT (gen_asset_id)
    DO UPDATE SET gen_asset_id = EXCLUDED.gen_asset_id
RETURNING sig_id;

-- name: UpsertGenesisAsset :one
INSERT INTO genesis_assets (
    asset_id, asset_tag, meta_data, output_index, asset_type, genesis_point_id
) VALUES (
    $1, $2, $3, $4, $5, $6
) ON CONFLICT (asset_tag)
    -- This is a NOP, asset_tag is the unique field that caused the conflict.
    DO UPDATE SET asset_tag = EXCLUDED.asset_tag
RETURNING gen_asset_id;

-- name: InsertNewAsset :one
INSERT INTO assets (
    genesis_id, version, script_key_id, asset_group_sig_id, script_version, 
    amount, lock_time, relative_lock_time, anchor_utxo_id
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9
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
    WHERE keys.raw_key = $1
), key_group_info AS (
    -- This CTE is used to perform a series of joins that allow us to extract
    -- the group key information, as well as the group sigs for the series of
    -- assets we care about. We obtain only the assets found in the batch
    -- above, with the WHERE query at the bottom.
    SELECT 
        sig_id, gen_asset_id, genesis_sig, tweaked_group_key, raw_key, key_index, key_family
    FROM asset_group_sigs sigs
    JOIN asset_groups groups
        ON sigs.group_key_id = groups.group_id
    JOIN internal_keys keys
        ON keys.key_id = groups.internal_key_id
    -- TODO(roasbeef): or can join do this below?
    WHERE sigs.gen_asset_id IN (SELECT gen_asset_id FROM genesis_info)
)
SELECT 
    version, script_keys.tweak, script_keys.tweaked_script_key, 
    internal_keys.raw_key AS script_key_raw, internal_keys.key_family AS script_key_fam,
    internal_keys.key_index AS script_key_index, key_group_info.genesis_sig, 
    key_group_info.tweaked_group_key, key_group_info.raw_key AS group_key_raw,
    key_group_info.key_family AS group_key_family, key_group_info.key_index AS group_key_index,
    script_version, amount, lock_time, relative_lock_time, 
    genesis_info.asset_id, genesis_info.asset_tag, genesis_info.meta_data, 
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

-- name: QueryAssetBalancesByAsset :many
SELECT
    genesis_info_view.asset_id, version, SUM(amount) balance,
    genesis_info_view.asset_tag, genesis_info_view.meta_data,
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
GROUP BY assets.genesis_id, genesis_info_view.asset_id,
         version, genesis_info_view.asset_tag, genesis_info_view.meta_data,
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
GROUP BY key_group_info_view.tweaked_group_key;

-- name: FetchGroupedAssets :many
SELECT
    assets.asset_id AS asset_primary_key, amount, lock_time, relative_lock_time, 
    genesis_info_view.asset_id AS asset_id,
    genesis_info_view.asset_tag,
    genesis_info_view.meta_data, 
    genesis_info_view.asset_type,
    key_group_info_view.tweaked_group_key
FROM assets
JOIN genesis_info_view
    ON assets.genesis_id = genesis_info_view.gen_asset_id
JOIN key_group_info_view
    ON assets.genesis_id = key_group_info_view.gen_asset_id;

-- name: FetchGroupByGroupKey :one
SELECT 
    key_group_info_view.gen_asset_id AS gen_asset_id,
    key_group_info_view.raw_key AS raw_key,
    key_group_info_view.key_index AS key_index,
    key_group_info_view.key_family AS key_family
FROM key_group_info_view
WHERE (
    key_group_info_view.tweaked_group_key = @group_key
)
-- Sort and limit to return the genesis ID for initial genesis of the group.
ORDER BY key_group_info_view.sig_id
LIMIT 1;

-- name: FetchGroupByGenesis :one
SELECT
    key_group_info_view.tweaked_group_key AS tweaked_group_key,
    key_group_info_view.raw_key AS raw_key,
    key_group_info_view.key_index AS key_index,
    key_group_info_view.key_family AS key_family
FROM key_group_info_view
WHERE (
    key_group_info_view.gen_asset_id = @genesis_id
);

-- name: QueryAssets :many
SELECT
    assets.asset_id AS asset_primary_key, assets.genesis_id, version,
    script_keys.tweak AS script_key_tweak, 
    script_keys.tweaked_script_key, 
    internal_keys.raw_key AS script_key_raw,
    internal_keys.key_family AS script_key_fam,
    internal_keys.key_index AS script_key_index,
    key_group_info_view.genesis_sig, 
    key_group_info_view.tweaked_group_key,
    key_group_info_view.raw_key AS group_key_raw,
    key_group_info_view.key_family AS group_key_family,
    key_group_info_view.key_index AS group_key_index,
    script_version, amount, lock_time, relative_lock_time, 
    genesis_info_view.asset_id AS asset_id,
    genesis_info_view.asset_tag,
    genesis_info_view.meta_data, 
    genesis_info_view.output_index AS genesis_output_index,
    genesis_info_view.asset_type,
    genesis_info_view.prev_out AS genesis_prev_out,
    txns.raw_tx AS anchor_tx,
    txns.txid AS anchor_txid,
    txns.block_hash AS anchor_block_hash,
    utxos.outpoint AS anchor_outpoint,
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
       sqlc.narg('anchor_point') IS NULL)
JOIN internal_keys utxo_internal_keys
    ON utxos.internal_key_id = utxo_internal_keys.key_id
JOIN chain_txns txns
    ON utxos.txn_id = txns.txn_id
-- This clause is used to select specific assets for a asset ID, general
-- channel balances, and also coin selection. We use the sqlc.narg feature to
-- make the entire statement evaluate to true, if none of these extra args are
-- specified.
WHERE (
    assets.amount >= COALESCE(sqlc.narg('min_amt'), assets.amount) AND
    (key_group_info_view.tweaked_group_key = sqlc.narg('key_group_filter') OR
      sqlc.narg('key_group_filter') IS NULL)
);

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
    outpoint, amt_sats, internal_key_id, tapscript_sibling, taro_root, txn_id
) VALUES (
    $2, $3, (SELECT key_id FROM target_key), $4, $5, $6
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
WHERE (
    genesis_assets.genesis_point_id IN (SELECT genesis_id FROM target_point) AND
    genesis_assets.asset_id = @asset_id AND
    genesis_assets.asset_tag = @asset_tag AND
    genesis_assets.meta_data = @meta_data AND
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
    asset_id, asset_tag, meta_data, output_index, asset_type,
    genesis_points.prev_out prev_out
FROM genesis_assets
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
    WHERE script_keys.tweaked_script_key = $1
    -- TODO(guggero): Fix this by disallowing multiple assets with the same
    -- script key!
    LIMIT 1
)
INSERT INTO asset_proofs (
    asset_id, proof_file
) VALUES (
    (SELECT asset_id FROM target_asset), $2
) ON CONFLICT (asset_id)
    -- This is not a NOP, update the proof file in case it wasn't set before.
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

-- name: FetchAssetProof :one
WITH asset_info AS (
    SELECT assets.asset_id, script_keys.tweaked_script_key
    FROM assets
    JOIN script_keys
        ON assets.script_key_id = script_keys.script_key_id
    WHERE script_keys.tweaked_script_key = $1
)
SELECT asset_info.tweaked_script_key AS script_key, asset_proofs.proof_file,
       asset_info.asset_id as asset_id, asset_proofs.proof_id as proof_id
FROM asset_proofs
JOIN asset_info
    ON asset_info.asset_id = asset_proofs.asset_id;

-- name: InsertAssetWitness :exec
INSERT INTO asset_witnesses (
    asset_id, prev_out_point, prev_asset_id, prev_script_key, witness_stack,
    split_commitment_proof
) VALUES (
    $1, $2, $3, $4, $5, $6
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

-- name: DeleteManagedUTXO :exec
DELETE FROM managed_utxos
WHERE outpoint = $1;

-- name: ConfirmChainAnchorTx :exec
WITH target_txn(txn_id) AS (
    SELECT chain_txns.txn_id
    FROM chain_txns
    JOIN managed_utxos utxos
        ON utxos.txn_id = chain_txns.txn_id
    WHERE utxos.outpoint = $1
)
UPDATE chain_txns
SET block_height = $2, block_hash = $3, tx_index = $4
WHERE txn_id in (SELECT txn_id FROM target_txn);

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
