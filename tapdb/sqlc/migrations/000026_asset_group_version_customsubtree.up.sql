-- Add version field to table asset_groups.
ALTER TABLE asset_groups ADD COLUMN version INTEGER NOT NULL DEFAULT 0;

-- Add custom_subtree_root field to the table asset_groups. This optional field
-- is used to store the root of the custom subtree for the asset group. The
-- custom subtree, if provided, represents a subtree of the final tapscript
-- tree.
ALTER TABLE asset_groups ADD COLUMN custom_subtree_root BLOB;

-- We're going to recreate key_group_info_view to include the new columns.
-- Therefore, we need to drop the existing view.
DROP VIEW IF EXISTS key_group_info_view;

-- Recreate the key_group_info_view to include the new columns.
--
-- This view is used to perform a series of joins that allow us to extract
-- the group key information, as well as the group sigs for the series of
-- assets we care about. We obtain only the assets found in the batch
-- above, with the WHERE query at the bottom.
CREATE VIEW key_group_info_view AS
SELECT
    groups.version, witness_id, gen_asset_id, witness_stack, tapscript_root,
    tweaked_group_key, raw_key, key_index, key_family,
    substr(tweaked_group_key, 2) AS x_only_group_key,
    groups.custom_subtree_root
FROM asset_group_witnesses wit
         JOIN asset_groups groups
              ON wit.group_key_id = groups.group_id
         JOIN internal_keys keys
              ON keys.key_id = groups.internal_key_id
WHERE wit.gen_asset_id IN (SELECT gen_asset_id FROM genesis_info_view);
