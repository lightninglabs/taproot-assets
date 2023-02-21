-- name: FetchUniverseRoot :one
SELECT asset_id, group_key, mssmt_nodes.hash_key root_hash, 
       mssmt_nodes.sum root_sum
FROM universe_roots
JOIN mssmt_roots 
    ON universe_roots.root_node_id = mssmt_roots.id
JOIN mssmt_nodes 
    ON mssmt_nodes.hash_key = mssmt_roots.hash_key AND
       mssmt_nodes.namespace = mssmt_roots.namespace
WHERE mssmt_nodes.namespace = @namespace;

-- name: InsertUniverseRoot :one
INSERT INTO universe_roots (
    root_node_id, asset_id, group_key
) VALUES (
    @root_node_id, @asset_id, @group_key
) RETURNING id;

-- name: InsertUniverseLeaf :exec
INSERT INTO universe_leaves (
    asset_genesis_id, universe_root_id, leaf_node_id
) VALUES (
    @asset_genesis_id, @universe_root_id, @leaf_node_id
);
