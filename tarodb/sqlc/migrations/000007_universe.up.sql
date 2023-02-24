CREATE TABLE IF NOT EXISTS universe_roots (
    id INTEGER PRIMARY KEY,

    namespace_root VARCHAR NOT NULL REFERENCES mssmt_roots(namespace) UNIQUE,

    asset_id BLOB,

    group_key BLOB
);

CREATE TABLE IF NOT EXISTS universe_leaves (
    id INTEGER PRIMARY KEY,

    asset_genesis_id INTEGER NOT NULL REFERENCES genesis_assets(gen_asset_id),

    minting_point BLOB NOT NULL, 

    script_key_bytes BLOB NOT NULL,

    universe_root_id INTEGER NOT NULL REFERENCES universe_roots(id),

    leaf_node_key BLOB,
    
    leaf_node_namespace VARCHAR NOT NULL,

    UNIQUE(asset_genesis_id, universe_root_id)
);
