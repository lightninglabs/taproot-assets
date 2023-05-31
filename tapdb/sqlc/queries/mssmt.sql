-- name: InsertBranch :exec
INSERT INTO mssmt_nodes (
    hash_key, l_hash_key, r_hash_key, key, value, sum, namespace
) VALUES ($1, $2, $3, NULL, NULL, $4, $5);

-- name: InsertLeaf :exec
INSERT INTO mssmt_nodes (
    hash_key, l_hash_key, r_hash_key, key, value, sum, namespace
) VALUES ($1, NULL, NULL, NULL, $2, $3, $4);

-- name: InsertCompactedLeaf :exec
INSERT INTO mssmt_nodes (
    hash_key, l_hash_key, r_hash_key, key, value, sum, namespace
) VALUES ($1, NULL, NULL, $2, $3, $4, $5);

-- name: FetchChildren :many
WITH RECURSIVE mssmt_branches_cte (
    hash_key, l_hash_key, r_hash_key, key, value, sum, namespace, depth
)
AS (
    SELECT r.hash_key, r.l_hash_key, r.r_hash_key, r.key, r.value, r.sum, r.namespace, 0 as depth
    FROM mssmt_nodes r
    WHERE r.hash_key = $1 AND r.namespace = $2
    UNION ALL
        SELECT n.hash_key, n.l_hash_key, n.r_hash_key, n.key, n.value, n.sum, n.namespace, depth+1
        FROM mssmt_nodes n, mssmt_branches_cte b
        WHERE n.namespace=b.namespace AND (n.hash_key=b.l_hash_key OR n.hash_key=b.r_hash_key)
    /*
    Limit the result set to 3 items. The first is always the root node, while
    the following 0, 1 or 2 nodes represent children of the root node. These
    children can either be the next level children, or one next level and one
    from the level after that. In the future we may use this limit to fetch
    entire subtrees too.
    */
) SELECT * FROM mssmt_branches_cte WHERE depth < 3;


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
