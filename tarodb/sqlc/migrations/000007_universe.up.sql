CREATE TABLE IF NOT EXISTS universe_roots (
    id INTEGER PRIMARY KEY,

    -- TOOD(roasbeef): need namespace here too?
    root_node_id INTEGER NOT NULL REFERENCES mssmt_roots(id),

    asset_id BLOB,

    group_key BLOB
);

CREATE TABLE IF NOT EXISTS universe_leaves (
    id INTEGER PRIMARY KEY,

    asset_genesis_id INTEGER NOT NULL REFERENCES asset_genesis(id),

    universe_root_id INTEGER NOT NULL REFERENCES universe_roots(id),

    UNIQUE(asset_genesis_id, universe_root_id),

    leaf_node_id BLOB NOT NULL REFERENCES mssmt_nodes(key)

    -- TOOD(roasbeef): need an amt too?
);
