-- name: FetchUniverseRoot :one
SELECT universe_roots.asset_id, group_key, mssmt_nodes.hash_key root_hash, 
       mssmt_nodes.sum root_sum, genesis_assets.asset_tag asset_name
FROM universe_roots
JOIN mssmt_roots 
    ON universe_roots.namespace_root = mssmt_roots.namespace
JOIN mssmt_nodes 
    ON mssmt_nodes.hash_key = mssmt_roots.root_hash AND
       mssmt_nodes.namespace = mssmt_roots.namespace
JOIN genesis_assets
     ON genesis_assets.asset_id = universe_roots.asset_id
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

-- name: UniverseRoots :many
SELECT universe_roots.asset_id, group_key, mssmt_roots.root_hash root_hash,
       mssmt_nodes.sum root_sum, genesis_assets.asset_tag asset_name
FROM universe_roots
JOIN mssmt_roots
    ON universe_roots.namespace_root = mssmt_roots.namespace
JOIN mssmt_nodes
    ON mssmt_nodes.hash_key = mssmt_roots.root_hash AND
       mssmt_nodes.namespace = mssmt_roots.namespace
JOIN genesis_assets
    ON genesis_assets.asset_id = universe_roots.asset_id;

-- name: InsertUniverseServer :exec
INSERT INTO universe_servers(
    server_host, last_sync_time
) VALUES (
    @server_host, @last_sync_time
);

-- name: DeleteUniverseServer :exec
DELETE FROM universe_servers
WHERE server_host = @target_server OR id = @target_id;

-- name: LogServerSync :exec
UPDATE universe_servers
SET last_sync_time = @new_sync_time
WHERE server_host = @target_server;

-- name: ListUniverseServers :many
SELECT * FROM universe_servers;

-- name: InsertNewSyncEvent :exec
WITH root_asset_id AS (
    SELECT id
    FROM universe_roots
    WHERE asset_id = @asset_id
)
INSERT INTO universe_events (
    event_type, universe_root_id, event_time
) VALUES (
    'SYNC', (SELECT id FROM root_asset_id), @event_time
);

-- name: InsertNewProofEvent :exec
WITH root_asset_id AS (
    SELECT id
    FROM universe_roots
    WHERE asset_id = @asset_id
)
INSERT INTO universe_events (
    event_type, universe_root_id, event_time
) VALUES (
    'NEW_PROOF', (SELECT id FROM root_asset_id), @event_time
);

-- name: QueryUniverseStats :one
WITH num_assets As (
    SELECT COUNT(*) AS num_assets
    FROM universe_roots
)
SELECT COALESCE(SUM(universe_stats.total_asset_syncs), 0) AS total_syncs,
       COALESCE(SUM(universe_stats.total_asset_proofs), 0) AS total_proofs,
       COUNT(num_assets) AS total_num_assets
FROM universe_stats, num_assets;

-- TODO(roasbeef): use the universe id instead for the grouping? so namespace
-- root, simplifies queries

-- name: QueryUniverseAssetStats :many
WITH asset_supply AS (
    SELECT SUM(nodes.sum) AS supply, gen.asset_id AS asset_id
    FROM universe_leaves leaves
    JOIN mssmt_nodes nodes
        ON leaves.leaf_node_key = nodes.key AND
           leaves.leaf_node_namespace = nodes.namespace
    JOIN genesis_info_view gen
        ON leaves.asset_genesis_id = gen.gen_asset_id
    GROUP BY gen.asset_id
), asset_info AS (
    SELECT asset_supply.supply, gen.asset_id AS asset_id, 
           gen.asset_tag AS asset_name, gen.asset_type AS asset_type
    FROM genesis_info_view gen
    JOIN asset_supply
        ON asset_supply.asset_id = gen.asset_id
    WHERE (gen.asset_tag = sqlc.narg('asset_name') OR sqlc.narg('asset_name') IS NULL) AND
          (gen.asset_type = sqlc.narg('asset_type') OR sqlc.narg('asset_type') IS NULL) AND
          (gen.asset_id = sqlc.narg('asset_id') OR sqlc.narg('asset_id') IS NULL)
)
SELECT asset_info.supply AS asset_supply, asset_info.asset_name AS asset_name,
    asset_info.asset_type AS asset_type, asset_info.asset_id AS asset_id,
    universe_stats.total_asset_syncs AS total_syncs,
    universe_stats.total_asset_proofs AS total_proofs
FROM asset_info
JOIN universe_stats
    ON asset_info.asset_id = universe_stats.asset_id
ORDER BY
    CASE
        WHEN sqlc.narg('sort_by') = 'asset_id' THEN asset_info.asset_id
        ELSE NULL
    END,
    CASE
        WHEN sqlc.narg('sort_by') = 'asset_name' THEN asset_info.asset_name
        ELSE NULL
    END,
    CASE
        WHEN sqlc.narg('sort_by') = 'asset_type' THEN asset_info.asset_type
        ELSE NULL
    END
LIMIT @num_limit OFFSET @num_offset;
