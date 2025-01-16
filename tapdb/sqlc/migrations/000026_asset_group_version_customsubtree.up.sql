-- Add version field to table asset_groups.
ALTER TABLE asset_groups ADD COLUMN version INTEGER NOT NULL DEFAULT 0;

-- Add the custom_subtree_root_id column to the asset_groups table. This
-- optional column references a row in the tapscript_roots table, linking a
-- custom tapscript subtree to the asset group. The subtree includes
-- user-defined asset group key scripts.
ALTER TABLE asset_groups
ADD COLUMN custom_subtree_root_id INTEGER
REFERENCES tapscript_roots(root_id);

-- We're going to recreate key_group_info_view to include the new columns.
-- Therefore, we need to drop the existing view.
DROP VIEW IF EXISTS key_group_info_view;

-- Recreate the key_group_info_view to include the new columns.
--
-- This view is useful for including group key information via joins.
CREATE VIEW key_group_info_view AS
SELECT
    groups.version, witness_id, gen_asset_id, witness_stack, tapscript_root,
    tweaked_group_key, raw_key, key_index, key_family,
    substr(tweaked_group_key, 2) AS x_only_group_key,
    tapscript_roots.root_hash AS custom_subtree_root
FROM asset_group_witnesses wit
         JOIN asset_groups groups
              ON wit.group_key_id = groups.group_id
         JOIN internal_keys keys
              ON keys.key_id = groups.internal_key_id

         -- Include the tapscript root hash for the custom subtree. Here we use
         -- a LEFT JOIN to allow for the case where a group does not have a
         -- custom subtree in which case the custom_subtree_root will be NULL.
         LEFT JOIN tapscript_roots
                   ON groups.custom_subtree_root_id = tapscript_roots.root_id
WHERE wit.gen_asset_id IN (SELECT gen_asset_id FROM genesis_info_view);
