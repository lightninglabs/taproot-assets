-- Remove the `key_group_info_view` view which includes the new columns. Later,
-- we will recreate the previous version of this view which does not include the
-- new columns.
DROP VIEW IF EXISTS key_group_info_view;

-- Remove the `version` column from the `asset_groups` table.
ALTER TABLE asset_groups DROP COLUMN version;

-- Remove the custom_subtree_root_id column from the asset_groups table.
ALTER TABLE asset_groups DROP COLUMN custom_subtree_root_id;

-- Recreate the previous view.
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