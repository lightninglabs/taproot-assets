-- Re-insert universe leaf after CASCADE delete for the
-- post-migration insert test in TestMigration54.

INSERT INTO universe_leaves (
    id, asset_genesis_id, minting_point, script_key_bytes,
    universe_root_id, leaf_node_key, leaf_node_namespace
) VALUES (
    1, 1, X'0a0b0c',
    X'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
    1, X'aa', 'ns1'
);
