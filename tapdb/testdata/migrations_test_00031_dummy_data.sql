-- Insert required rows for FK constraints.

-- Chain transaction (for genesis_points).
INSERT INTO chain_txns VALUES(
  1,
  X'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789',
  1000,
  X'01020304',
  NULL,
  NULL,
  NULL
);

-- Genesis point (required by genesis_assets).
INSERT INTO genesis_points VALUES(
  1,
  X'01010101010101010101010101010101',
  1
);

-- Genesis asset (referenced by universe_leaves).
INSERT INTO genesis_assets VALUES(
  1,
  X'abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef',
  'dummy_tag',
  NULL,
  0,
  1,
  1
);

-- An mssmt node (required by mssmt_roots).
INSERT INTO mssmt_nodes VALUES(
  X'00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff',
  NULL, NULL, X'00', X'00', 0, 'dummy'
);

-- An mssmt root. Its primary key ‘namespace’ is referenced by universe_roots.
INSERT INTO mssmt_roots VALUES(
  'dummy',
  X'00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff'
);

-- Insert a universe root (FK for universe_leaves).
INSERT INTO universe_roots VALUES(
  999,
  'dummy',
  NULL,
  X'00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff',
  'issuance'
);

-- Dummy row for universe_leaves. Note this row uses the old unique constraint.
INSERT INTO universe_leaves (
    id, asset_genesis_id, minting_point, script_key_bytes,
    universe_root_id, leaf_node_key, leaf_node_namespace
) VALUES (
    100, 1, X'0a0b0c',
    X'00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff',
    999, X'aa', 'old_ns'
);
