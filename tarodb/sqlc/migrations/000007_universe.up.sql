CREATE TABLE IF NOT EXISTS universe_roots (
    id INTEGER PRIMARY KEY,

    -- For the namespace root, we set the foreign key constraint evaluation to
    -- be deferred until after the database transaction ends. Otherwise, if the
    -- root of the SMT is deleted temporarily before inserting a new root, then
    -- this constraint is violated as there's no longer a root that this
    -- universe tree can point to.
    namespace_root VARCHAR UNIQUE NOT NULL REFERENCES mssmt_roots(namespace) DEFERRABLE INITIALLY DEFERRED,

    asset_id BLOB,

    -- We use the 32 byte schnorr key here as this is what's used to derive the
    -- top-level Taro commitment key.
    group_key BLOB CHECK(LENGTH(group_key) = 32)
);

CREATE TABLE IF NOT EXISTS universe_leaves (
    id INTEGER PRIMARY KEY,

    asset_genesis_id INTEGER NOT NULL REFERENCES genesis_assets(gen_asset_id),

    minting_point BLOB NOT NULL, 

    script_key_bytes BLOB NOT NULL CHECK(LENGTH(script_key_bytes) = 32),

    universe_root_id INTEGER NOT NULL REFERENCES universe_roots(id),

    leaf_node_key BLOB,
    
    leaf_node_namespace VARCHAR NOT NULL,

    UNIQUE(minting_point, script_key_bytes)
);
