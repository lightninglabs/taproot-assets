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
        gen_asset_id, asset_id, asset_tag, assets_meta.meta_data_hash meta_hash,
        output_index, asset_type, genesis_points.prev_out prev_out,
        chain_txns.txid anchor_txid, block_height
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
        witness_id, gen_asset_id, witness_stack, tapscript_root,
        tweaked_group_key, raw_key, key_index, key_family,
        substr(tweaked_group_key, 2) AS x_only_group_key
    FROM asset_group_witnesses wit
    JOIN asset_groups groups
        ON wit.group_key_id = groups.group_id
    JOIN internal_keys keys
        ON keys.key_id = groups.internal_key_id
    WHERE wit.gen_asset_id IN (SELECT gen_asset_id FROM genesis_info_view);