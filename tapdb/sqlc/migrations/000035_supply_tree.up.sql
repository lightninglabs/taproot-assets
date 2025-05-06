-- Ensure the required proof types for supply sub-trees exist.
-- Note: 'issuance' is assumed to exist from previous migrations.
INSERT INTO proof_types (proof_type) VALUES ('burn'), ('ignore'), ('mint_supply')
    ON CONFLICT (proof_type) DO NOTHING;

-- Table representing the root of a supply tree for a specific asset group.
CREATE TABLE universe_supply_roots (
    id INTEGER PRIMARY KEY,

    -- The namespace root of the MS-SMT representing this supply tree.
    -- We set the foreign key constraint evaluation to be deferred until after
    -- the database transaction ends. Otherwise, if the root of the SMT is
    -- deleted temporarily before inserting a new root, then this constraint
    -- is violated.
    namespace_root VARCHAR UNIQUE NOT NULL REFERENCES mssmt_roots(namespace) DEFERRABLE INITIALLY DEFERRED,

    -- The tweaked group key identifying the asset group this supply tree belongs to.
    group_key BLOB UNIQUE NOT NULL CHECK(length(group_key) = 33)
);

-- Table representing the leaves within a root supply tree.
-- Each leaf corresponds to the root of a sub-tree (mint, burn, ignore).
CREATE TABLE universe_supply_leaves (
    id INTEGER PRIMARY KEY,

    -- Reference to the root supply tree this leaf belongs to.
    supply_root_id BIGINT NOT NULL REFERENCES universe_supply_roots(id) ON DELETE CASCADE,

    -- The type of sub-tree this leaf represents (issuance, burn, ignore).
    sub_tree_type TEXT NOT NULL REFERENCES proof_types(proof_type),

    -- The key used for this leaf within the root supply tree's MS-SMT.
    -- This typically corresponds to a hash identifying the sub-tree type.
    leaf_node_key BLOB NOT NULL,

    -- The namespace within mssmt_nodes where the actual sub-tree root node resides.
    leaf_node_namespace VARCHAR NOT NULL,

    -- Ensure each supply root has only one leaf per sub-tree type.
    UNIQUE(supply_root_id, sub_tree_type)
);

-- Add indexes for frequent lookups.
CREATE INDEX universe_supply_roots_group_key_idx ON universe_supply_roots(group_key);
CREATE INDEX universe_supply_leaves_supply_root_id_idx ON universe_supply_leaves(supply_root_id);
CREATE INDEX universe_supply_leaves_supply_root_id_type_idx ON universe_supply_leaves(supply_root_id, sub_tree_type);
