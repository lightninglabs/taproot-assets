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
    -- This is a NOP, namespace_root is the unique field that caused the
    -- conflict.
    DO UPDATE SET namespace_root = EXCLUDED.namespace_root
RETURNING id;

-- name: DeleteUniverseEvents :exec
WITH root_id AS (
    SELECT id
    FROM universe_roots
    WHERE namespace_root = @namespace_root
)
DELETE FROM universe_events
WHERE universe_root_id = (SELECT id from root_id);

-- name: DeleteUniverseRoot :exec
DELETE FROM universe_roots
WHERE namespace_root = @namespace_root;

-- name: UpsertUniverseLeaf :exec
INSERT INTO universe_leaves (
    asset_genesis_id, script_key_bytes, universe_root_id, leaf_node_key, 
    leaf_node_namespace, minting_point
) VALUES (
    @asset_genesis_id, @script_key_bytes, @universe_root_id, @leaf_node_key,
    @leaf_node_namespace, @minting_point
) ON CONFLICT (minting_point, script_key_bytes)
    -- This is a NOP, minting_point and script_key_bytes are the unique fields
    -- that caused the conflict.
    DO UPDATE SET minting_point = EXCLUDED.minting_point,
                  script_key_bytes = EXCLUDED.script_key_bytes;

-- name: DeleteUniverseLeaves :exec
DELETE FROM universe_leaves
WHERE leaf_node_namespace = @namespace;

-- name: QueryUniverseLeaves :many
SELECT leaves.script_key_bytes, gen.gen_asset_id, nodes.value genesis_proof, 
       nodes.sum sum_amt, gen.asset_id
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
WITH group_key_root_id AS (
    SELECT id
    FROM universe_roots
    WHERE group_key = @group_key_x_only
), asset_id_root_id AS (
    SELECT leaves.universe_root_id AS id
    FROM universe_leaves leaves
    JOIN genesis_info_view gen
        ON leaves.asset_genesis_id = gen.gen_asset_id
    WHERE gen.asset_id = @asset_id 
    LIMIT 1
)
INSERT INTO universe_events (
    event_type, universe_root_id, event_time, event_timestamp
) VALUES (
    'SYNC',
        CASE WHEN length(@group_key_x_only) > 0 THEN (
            SELECT id FROM group_key_root_id
        ) ELSE (
            SELECT id FROM asset_id_root_id
        ) END,
    @event_time, @event_timestamp
);

-- name: InsertNewProofEvent :exec
WITH group_key_root_id AS (
    SELECT id
    FROM universe_roots
    WHERE group_key = @group_key_x_only
), asset_id_root_id AS (
    SELECT leaves.universe_root_id AS id
    FROM universe_leaves leaves
             JOIN genesis_info_view gen
                  ON leaves.asset_genesis_id = gen.gen_asset_id
    WHERE gen.asset_id = @asset_id
    LIMIT 1
)
INSERT INTO universe_events (
    event_type, universe_root_id, event_time, event_timestamp
) VALUES (
    'NEW_PROOF',
        CASE WHEN length(@group_key_x_only) > 0 THEN (
            SELECT id FROM group_key_root_id
        ) ELSE (
            SELECT id FROM asset_id_root_id
        ) END,
    @event_time, @event_timestamp
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
           gen.asset_tag AS asset_name, gen.asset_type AS asset_type,
           gen.block_height AS genesis_height, gen.prev_out AS genesis_prev_out,
           group_info.tweaked_group_key AS group_key
    FROM genesis_info_view gen
    JOIN asset_supply
        ON asset_supply.asset_id = gen.asset_id
    -- We use a LEFT JOIN here as not every asset has a group key, so this'll
    -- generate rows that have NULL values for the group key fields if an asset
    -- doesn't have a group key.
    LEFT JOIN key_group_info_view group_info
        ON gen.gen_asset_id = group_info.gen_asset_id
    WHERE (gen.asset_tag = sqlc.narg('asset_name') OR sqlc.narg('asset_name') IS NULL) AND
          (gen.asset_type = sqlc.narg('asset_type') OR sqlc.narg('asset_type') IS NULL) AND
          (gen.asset_id = sqlc.narg('asset_id') OR sqlc.narg('asset_id') IS NULL)
)
SELECT asset_info.supply AS asset_supply, asset_info.asset_name AS asset_name,
    asset_info.asset_type AS asset_type, asset_info.asset_id AS asset_id,
    asset_info.genesis_height AS genesis_height,
    asset_info.genesis_prev_out AS genesis_prev_out,
    asset_info.group_key AS group_key,
    universe_stats.total_asset_syncs AS total_syncs,
    universe_stats.total_asset_proofs AS total_proofs
FROM asset_info
JOIN universe_stats
    ON asset_info.asset_id = universe_stats.asset_id
ORDER BY
    CASE WHEN sqlc.narg('sort_by') = 'asset_id' AND sqlc.narg('sort_direction') = 0 THEN
             asset_info.asset_id END ASC,
    CASE WHEN sqlc.narg('sort_by') = 'asset_id' AND sqlc.narg('sort_direction') = 1 THEN
             asset_info.asset_id END DESC,
    CASE WHEN sqlc.narg('sort_by') = 'asset_name' AND sqlc.narg('sort_direction') = 0 THEN
             asset_info.asset_name END ASC ,
    CASE WHEN sqlc.narg('sort_by') = 'asset_name' AND sqlc.narg('sort_direction') = 1 THEN
             asset_info.asset_name END DESC ,
    CASE WHEN sqlc.narg('sort_by') = 'asset_type' AND sqlc.narg('sort_direction') = 0 THEN
             asset_info.asset_type END ASC ,
    CASE WHEN sqlc.narg('sort_by') = 'asset_type' AND sqlc.narg('sort_direction') = 1 THEN
             asset_info.asset_type END DESC,
    CASE WHEN sqlc.narg('sort_by') = 'total_syncs' AND sqlc.narg('sort_direction') = 0 THEN
             universe_stats.total_asset_syncs END ASC ,
    CASE WHEN sqlc.narg('sort_by') = 'total_syncs' AND sqlc.narg('sort_direction') = 1 THEN
             universe_stats.total_asset_syncs END DESC,
    CASE WHEN sqlc.narg('sort_by') = 'total_proofs' AND sqlc.narg('sort_direction') = 0 THEN
             universe_stats.total_asset_proofs END ASC ,
    CASE WHEN sqlc.narg('sort_by') = 'total_proofs' AND sqlc.narg('sort_direction') = 1 THEN
             universe_stats.total_asset_proofs END DESC,
    CASE WHEN sqlc.narg('sort_by') = 'genesis_height' AND sqlc.narg('sort_direction') = 0 THEN
             asset_info.genesis_height END ASC ,
    CASE WHEN sqlc.narg('sort_by') = 'genesis_height' AND sqlc.narg('sort_direction') = 1 THEN
             asset_info.genesis_height END DESC,
    CASE WHEN sqlc.narg('sort_by') = 'total_supply' AND sqlc.narg('sort_direction') = 0 THEN
             asset_info.supply END ASC ,
    CASE WHEN sqlc.narg('sort_by') = 'total_supply' AND sqlc.narg('sort_direction') = 1 THEN
             asset_info.supply END DESC
LIMIT @num_limit OFFSET @num_offset;

-- name: QueryAssetStatsPerDaySqlite :many
SELECT
    cast(strftime('%Y-%m-%d', datetime(event_timestamp, 'unixepoch')) as text) AS day,
    SUM(CASE WHEN event_type = 'SYNC' THEN 1 ELSE 0 END) AS sync_events,
    SUM(CASE WHEN event_type = 'NEW_PROOF' THEN 1 ELSE 0 END) AS new_proof_events
FROM universe_events
WHERE event_type IN ('SYNC', 'NEW_PROOF') AND
      event_timestamp >= @start_time AND event_timestamp <= @end_time
GROUP BY day
ORDER BY day;

-- name: QueryAssetStatsPerDayPostgres :many
SELECT
    to_char(to_timestamp(event_timestamp), 'YYYY-MM-DD') AS day,
    SUM(CASE WHEN event_type = 'SYNC' THEN 1 ELSE 0 END) AS sync_events,
    SUM(CASE WHEN event_type = 'NEW_PROOF' THEN 1 ELSE 0 END) AS new_proof_events
FROM universe_events
WHERE event_type IN ('SYNC', 'NEW_PROOF') AND
      event_timestamp >= @start_time AND event_timestamp <= @end_time
GROUP BY day
ORDER BY day;
