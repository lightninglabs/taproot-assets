-- Dummy data for migration 53 (federation_proof_sync_log CASCADE).
--
-- Sets up the FK chain needed to populate federation_proof_sync_log:
--   chain_txns -> genesis_points -> genesis_assets
--   mssmt_nodes -> mssmt_roots -> universe_roots
--   universe_leaves (refs genesis_assets, universe_roots)
--   universe_servers
--   federation_proof_sync_log (refs universe_leaves, universe_roots,
--                              universe_servers)

-- chain_txns
INSERT INTO chain_txns VALUES(
    1,
    X'aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233',
    100, X'01020304', NULL, NULL, NULL
);

-- genesis_points
INSERT INTO genesis_points VALUES(1, X'01010101010101010101010101010101', 1);

-- genesis_assets
INSERT INTO genesis_assets VALUES(
    1,
    X'abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef',
    'test_asset', NULL, 0, 1, 1
);

-- mssmt_nodes
INSERT INTO mssmt_nodes VALUES(
    X'1111111111111111111111111111111111111111111111111111111111111111',
    NULL, NULL, X'00', X'00', 0, 'ns1'
);

-- mssmt_roots
INSERT INTO mssmt_roots VALUES(
    'ns1',
    X'1111111111111111111111111111111111111111111111111111111111111111'
);

-- universe_roots
INSERT INTO universe_roots VALUES(
    1, 'ns1', NULL,
    X'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
    'issuance'
);

-- universe_leaves
INSERT INTO universe_leaves (
    id, asset_genesis_id, minting_point, script_key_bytes,
    universe_root_id, leaf_node_key, leaf_node_namespace
) VALUES (
    1, 1, X'0a0b0c',
    X'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
    1, X'aa', 'ns1'
);

-- universe_servers
INSERT INTO universe_servers VALUES(1, 'localhost:10029', '2024-01-01');

-- federation_proof_sync_log (references leaves, roots, servers)
INSERT INTO federation_proof_sync_log VALUES(
    1, 'complete', '2024-01-01', 1, 'push', 1, 1, 1
);
INSERT INTO federation_proof_sync_log VALUES(
    2, 'pending', '2024-01-01', 0, 'pull', 1, 1, 1
);
