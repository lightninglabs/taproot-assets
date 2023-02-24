-- name: FetchUniverseRoot :one
SELECT asset_id, group_key, mssmt_nodes.hash_key root_hash, 
       mssmt_nodes.sum root_sum
FROM universe_roots
JOIN mssmt_roots 
    ON universe_roots.namespace_root = mssmt_roots.namespace
JOIN mssmt_nodes 
    ON mssmt_nodes.hash_key = mssmt_roots.root_hash AND
       mssmt_nodes.namespace = mssmt_roots.namespace
WHERE mssmt_nodes.namespace = @namespace;

-- name: UpsertUniverseRoot :one
INSERT INTO universe_roots (
    namespace_root, asset_id, group_key
) VALUES (
    @namespace_root, @asset_id, @group_key
) ON CONFLICT (namespace_root)
    DO UPDATE SET namespace_root = @namespace_root
RETURNING id;

-- name: InsertUniverseLeaf :exec
INSERT INTO universe_leaves (
    asset_genesis_id, script_key_bytes, universe_root_id, leaf_node_key, 
    leaf_node_namespace, minting_point
) VALUES (
    @asset_genesis_id, @script_key_bytes, @universe_root_id, @leaf_node_key,
    @leaf_node_namespace, @minting_point
);

-- name: QueryUniverseLeaves :many
SELECT leaves.script_key_bytes, gen.gen_asset_id, nodes.value genesis_proof, 
       nodes.sum sum_amt
FROM universe_leaves leaves
JOIN mssmt_nodes nodes
    ON leaves.leaf_node_key = nodes.key AND
        leaves.leaf_node_namespace = nodes.namespace
JOIN genesis_info_view gen
    ON leaves.asset_genesis_id = gen.gen_asset_id
WHERE leaves.leaf_node_namespace = @namespace 
        AND 
    (leaves.minting_point = sqlc.narg('minting_point_bytes') OR 
        sqlc.narg('minting_point_bytes') IS NULL) 
        AND
    (leaves.script_key_bytes = sqlc.narg('script_key_bytes') OR 
        sqlc.narg('script_key_bytes') IS NULL);

-- name: FetchUniverseKeys :many
SELECT leaves.minting_point, leaves.script_key_bytes
FROM universe_leaves leaves
WHERE leaves.leaf_node_namespace = @namespace;

-- name: UniverseLeaves :many
SELECT * FROM universe_leaves;
