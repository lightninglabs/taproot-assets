DROP VIEW IF EXISTS key_group_info_view;
DROP VIEW IF EXISTS genesis_info_view;

-- This view is used to fetch the base asset information from disk based on
-- the raw key of the batch that will ultimately create this set of assets.
-- To do so, we'll need to traverse a few tables to join the set of assets
-- with the genesis points, then with the batches that reference this
-- points, to the internal key that reference the batch, then restricted
-- for internal keys that match our main batch key.
CREATE VIEW genesis_info_view AS
SELECT
    genesis_assets.gen_asset_id,
    genesis_assets.asset_id,
    genesis_assets.asset_tag,
    assets_meta.meta_data_hash AS meta_hash,
    genesis_assets.output_index,
    genesis_assets.asset_type,
    genesis_points.prev_out,
    chain_txns.txid AS anchor_txid,
    chain_txns.block_height
FROM genesis_assets
-- We do a LEFT JOIN here, as not every asset has a set of
-- metadata that matches the asset.
LEFT JOIN assets_meta
    ON genesis_assets.meta_data_id = assets_meta.meta_id
JOIN genesis_points
    ON genesis_assets.genesis_point_id = genesis_points.genesis_id
LEFT JOIN chain_txns
    ON genesis_points.anchor_tx_id = chain_txns.txn_id;

-- This view is used to perform a series of joins that allow us to extract
-- the group key information, as well as the group sigs for the series of
-- assets we care about. We obtain only the assets found in the batch
-- above, with the WHERE query at the bottom.
CREATE VIEW key_group_info_view AS
SELECT
    wit.witness_id,
    wit.gen_asset_id,
    wit.witness_stack,
    grp.tapscript_root,
    grp.tweaked_group_key,
    keys.raw_key,
    keys.key_index,
    keys.key_family,
    substr(grp.tweaked_group_key, 2) AS x_only_group_key
FROM asset_group_witnesses AS wit
JOIN asset_groups AS grp
    ON wit.group_key_id = grp.group_id
JOIN internal_keys AS keys
    ON grp.internal_key_id = keys.key_id
WHERE wit.gen_asset_id IN (
    SELECT giv.gen_asset_id FROM genesis_info_view AS giv
);
