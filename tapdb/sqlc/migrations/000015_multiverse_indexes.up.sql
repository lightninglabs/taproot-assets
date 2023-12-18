CREATE INDEX IF NOT EXISTS mssmt_nodes_key_idx ON mssmt_nodes(key);

CREATE INDEX IF NOT EXISTS multiverse_roots_namespace_root_idx ON multiverse_roots(namespace_root);
CREATE INDEX IF NOT EXISTS multiverse_roots_proof_type_idx ON multiverse_roots(proof_type);

CREATE INDEX IF NOT EXISTS multiverse_leaves_multiverse_root_id_idx ON multiverse_leaves(multiverse_root_id);

CREATE INDEX IF NOT EXISTS multiverse_leaves_asset_id_idx ON multiverse_leaves(asset_id);
CREATE INDEX IF NOT EXISTS multiverse_leaves_group_key_idx ON multiverse_leaves(group_key);
