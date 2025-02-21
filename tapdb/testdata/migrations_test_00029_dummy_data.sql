-- Insert a dummy row into mssmt_nodes to satisfy the foreign key constraint
-- for mssmt_roots. The mssmt_roots row will reference this dummy row.
INSERT INTO mssmt_nodes 
    (hash_key, l_hash_key, r_hash_key, key, value, sum, namespace)
VALUES 
    (
      X'abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef',
      NULL, NULL, X'00', X'00', 0, 'n1'
    );

-- Minimal dummy data for migration 29 (pre-migration state).

-- Insert into mssmt_roots to satisfy foreign key constraints.
INSERT INTO mssmt_roots (namespace, root_hash)
VALUES ('n1', X'abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef');

-- Insert into universe_roots with the original schema.
INSERT INTO universe_roots (id, namespace_root, asset_id, group_key, proof_type)
VALUES (1, 'n1', NULL, X'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', 'issuance');

-- Insert into federation_global_sync_config.
INSERT INTO federation_global_sync_config (proof_type, allow_sync_insert, allow_sync_export)
VALUES ('transfer', true, false);

-- Insert into federation_uni_sync_config.
-- Provide a default value for the new NOT NULL column "namespace".
INSERT INTO federation_uni_sync_config (namespace, group_key, proof_type, allow_sync_insert, allow_sync_export)
VALUES ('default', X'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f21', 'issuance', true, true);
