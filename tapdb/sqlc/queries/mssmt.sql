-- name: InsertBranch :exec
INSERT INTO mssmt_nodes (
    hash_key, l_hash_key, r_hash_key, key, value, sum, namespace
) VALUES ($1, $2, $3, NULL, NULL, $4, $5)
ON CONFLICT (hash_key, namespace) DO NOTHING;

-- name: InsertLeaf :exec
INSERT INTO mssmt_nodes (
    hash_key, l_hash_key, r_hash_key, key, value, sum, namespace
) VALUES ($1, NULL, NULL, NULL, $2, $3, $4)
ON CONFLICT (hash_key, namespace) DO NOTHING;

-- name: InsertCompactedLeaf :exec
INSERT INTO mssmt_nodes (
    hash_key, l_hash_key, r_hash_key, key, value, sum, namespace
) VALUES ($1, NULL, NULL, $2, $3, $4, $5)
ON CONFLICT (hash_key, namespace) DO NOTHING;

-- name: FetchChildren :many
-- Returns the node with the given hash key alongside its direct children, in
-- no particular order. Each row is a primary key lookup, so the cost is
-- independent of the size of the subtree beneath the node.
SELECT n.hash_key, n.l_hash_key, n.r_hash_key, n.key, n.value, n.sum,
       n.namespace
FROM mssmt_nodes p
JOIN mssmt_nodes n
    ON n.namespace = p.namespace
    AND n.hash_key IN (p.hash_key, p.l_hash_key, p.r_hash_key)
WHERE p.hash_key = $1 AND p.namespace = $2;


-- name: FetchChildrenSelfJoin :many
WITH subtree_cte (
    hash_key, l_hash_key, r_hash_key, key, value, sum, namespace, depth
) AS (
  SELECT r.hash_key, r.l_hash_key, r.r_hash_key, r.key, r.value, r.sum, r.namespace, 0 as depth
  FROM mssmt_nodes r
  WHERE r.hash_key = $1 AND r.namespace = $2
  UNION ALL
    SELECT c.hash_key, c.l_hash_key, c.r_hash_key, c.key, c.value, c.sum, c.namespace, depth+1
    FROM mssmt_nodes c
    INNER JOIN subtree_cte r ON r.l_hash_key=c.hash_key OR r.r_hash_key=c.hash_key
) SELECT * from subtree_cte WHERE depth < 3;

-- name: DeleteNode :execrows
DELETE FROM mssmt_nodes WHERE hash_key = $1 AND namespace = $2; 

-- name: DeleteAllNodes :execrows
DELETE FROM mssmt_nodes WHERE namespace = $1;

-- name: DeleteRoot :execrows
DELETE FROM mssmt_roots WHERE namespace = $1;

-- name: FetchRootNode :one
SELECT nodes.*
FROM mssmt_nodes nodes
JOIN mssmt_roots roots
    ON roots.root_hash = nodes.hash_key AND
        roots.namespace = $1;

-- name: UpsertRootNode :exec
INSERT INTO mssmt_roots (
    root_hash, namespace
) VALUES (
    $1, $2
) ON CONFLICT (namespace)
    -- Not a NOP, we always overwrite the root hash.
    DO UPDATE SET root_hash = EXCLUDED.root_hash;

-- name: FetchAllNodes :many
SELECT * FROM mssmt_nodes;
