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
