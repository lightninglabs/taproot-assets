CREATE TABLE IF NOT EXISTS mssmt_nodes (
    -- hash_key is the hash key by which we reference all nodes.
    hash_key BLOB PRIMARY KEY,
 
    -- l_hash_key is the hash key of the left child or NULL. If this is a
    -- branch then either l_hash_key or r_hash_key is not NULL.
    l_hash_key BLOB,
  
    -- r_hash_key is the hash key of the right child or NULL. If this is a
    -- branch then either l_hash_key or r_hash_key is not NULL.
    r_hash_key BLOB,
  
    -- key is the leaf key if this is a compacted leaf node.
    key BLOB,
  
    -- value is the leaf value if this is a leaf node.
    value BLOB,

    -- sum is the sum of the node.
    sum BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS mssmt_nodes_l_hash_key_idx ON mssmt_nodes (l_hash_key);
CREATE INDEX IF NOT EXISTS mssmt_nodes_r_hash_key_idx ON mssmt_nodes (r_hash_key);

