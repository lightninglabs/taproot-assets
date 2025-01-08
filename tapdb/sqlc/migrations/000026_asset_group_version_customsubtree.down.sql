-- Remove the `version` column from the `asset_groups` table.
ALTER TABLE asset_groups DROP COLUMN version;

-- Remove the `custom_subtree_root` column from the `asset_groups` table.
ALTER TABLE asset_groups DROP COLUMN custom_subtree_root;