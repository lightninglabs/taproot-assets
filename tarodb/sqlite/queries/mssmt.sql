-- name: InsertBranch :exec
INSERT INTO mssmt_nodes (
    hash_key, l_hash_key, r_hash_key, key, value, sum, namespace
) VALUES (?, ?, ?, NULL, NULL, ?, ?);

-- name: InsertLeaf :exec
INSERT INTO mssmt_nodes (
    hash_key, l_hash_key, r_hash_key, key, value, sum, namespace
) VALUES (?, NULL, NULL, NULL, ?, ?, ?);

-- name: InsertCompactedLeaf :exec
INSERT INTO mssmt_nodes (
    hash_key, l_hash_key, r_hash_key, key, value, sum, namespace
) VALUES (?, NULL, NULL, ?, ?, ?, ?);

-- name: FetchChildren :many
WITH RECURSIVE mssmt_branches_cte (
    hash_key, l_hash_key, r_hash_key, key, value, sum, namespace
)
AS (
    SELECT r.hash_key, r.l_hash_key, r.r_hash_key, r.key, r.value, r.sum, r.namespace
    FROM mssmt_nodes r
    WHERE r.hash_key=? AND r.namespace=?
    UNION ALL
        SELECT n.hash_key, n.l_hash_key, n.r_hash_key, n.key, n.value, n.sum, n.namespace
        FROM mssmt_nodes n, mssmt_branches_cte b
        WHERE n.namespace=b.namespace AND (n.hash_key=b.l_hash_key OR n.hash_key=b.r_hash_key)
    /*
    Limit the result set to 3 items. The first is always the root node, while
    the following 0, 1 or 2 nodes represent children of the root node. These
    children can either be the next level children, or one next level and one
    from the level after that. In the future we may use this limit to fetch
    entire subtrees too.
    */
    LIMIT 3
) SELECT * FROM mssmt_branches_cte;


-- name: FetchChildrenSelfJoin :many
WITH subtree AS (
  SELECT * FROM mssmt_nodes r
  WHERE r.hash_key=? AND r.namespace = ?
  UNION ALL
    SELECT c.* FROM mssmt_nodes c
    INNER JOIN subtree r ON r.l_hash_key=c.hash_key OR r.r_hash_key=c.hash_key
) SELECT * from subtree LIMIT 3;

-- name: DeleteNode :execrows
DELETE FROM mssmt_nodes WHERE hash_key=? AND namespace=?; 

-- name: FetchRootNode :one
SELECT nodes.*
FROM mssmt_nodes nodes
JOIN mssmt_roots roots
    ON roots.root_hash = nodes.hash_key AND
        roots.namespace = ?;

-- name: UpsertRootNode :exec
INSERT INTO mssmt_roots (
    root_hash, namespace
) VALUES (
    ?, ?
) ON CONFLICT (namespace)
    DO UPDATE SET root_hash = EXCLUDED.root_hash;
