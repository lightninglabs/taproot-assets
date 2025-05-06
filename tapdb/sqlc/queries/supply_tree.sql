-- name: UpsertUniverseSupplyRoot :one
INSERT INTO universe_supply_roots (namespace_root, group_key)
VALUES (@namespace_root, @group_key)
ON CONFLICT (namespace_root)
    -- This is a no-op to allow returning the ID.
    DO UPDATE SET namespace_root = EXCLUDED.namespace_root
RETURNING id;

-- name: FetchUniverseSupplyRoot :one
SELECT r.group_key, n.hash_key as root_hash, n.sum as root_sum
FROM universe_supply_roots r
JOIN mssmt_roots m
    ON r.namespace_root = m.namespace
JOIN mssmt_nodes n
    ON m.root_hash = n.hash_key AND
       m.namespace = n.namespace
WHERE r.namespace_root = @namespace_root;

-- name: UpsertUniverseSupplyLeaf :one
INSERT INTO universe_supply_leaves (
    supply_root_id, sub_tree_type, leaf_node_key, leaf_node_namespace
) VALUES (
    @supply_root_id, @sub_tree_type, @leaf_node_key, @leaf_node_namespace
)
ON CONFLICT (supply_root_id, sub_tree_type)
    -- This is a no-op to allow returning the ID.
    DO UPDATE SET leaf_node_key = EXCLUDED.leaf_node_key,
                  leaf_node_namespace = EXCLUDED.leaf_node_namespace
RETURNING id;

-- name: DeleteUniverseSupplyLeaf :exec
DELETE FROM universe_supply_leaves
WHERE leaf_node_namespace = @namespace AND leaf_node_key = @leaf_node_key;

-- name: QueryUniverseSupplyLeaves :many
SELECT r.group_key, l.sub_tree_type,
       smt_nodes.value AS sub_tree_root_hash, smt_nodes.sum AS sub_tree_root_sum
FROM universe_supply_leaves l
JOIN mssmt_nodes smt_nodes
  ON l.leaf_node_key = smt_nodes.key AND
     l.leaf_node_namespace = smt_nodes.namespace
JOIN universe_supply_roots r
  ON l.supply_root_id = r.id
WHERE r.id = @supply_root_id AND
      (l.sub_tree_type = sqlc.narg('sub_tree_type') OR sqlc.narg('sub_tree_type') IS NULL);

-- name: DeleteUniverseSupplyLeaves :exec
DELETE FROM universe_supply_leaves
WHERE supply_root_id = (
    SELECT id FROM universe_supply_roots WHERE namespace_root = @namespace_root
);

-- name: DeleteUniverseSupplyRoot :exec
DELETE FROM universe_supply_roots
WHERE namespace_root = @namespace_root;
