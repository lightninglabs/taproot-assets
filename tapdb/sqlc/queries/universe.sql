-- name: FetchUniverseRoot :one
SELECT universe_roots.asset_id, group_key, proof_type,
       mssmt_nodes.hash_key root_hash, mssmt_nodes.sum root_sum,
       genesis_assets.asset_tag asset_name
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
    namespace_root, asset_id, group_key, proof_type
) VALUES (
    @namespace_root, @asset_id, @group_key, @proof_type
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
WHERE leaves.leaf_node_namespace = @namespace
ORDER BY 
    CASE WHEN sqlc.narg('sort_direction') = 0 THEN leaves.id END ASC,
    CASE WHEN sqlc.narg('sort_direction') = 1 THEN leaves.id END DESC
LIMIT @num_limit OFFSET @num_offset;

-- name: UniverseLeaves :many
SELECT * FROM universe_leaves;

-- name: UniverseRoots :many
SELECT universe_roots.asset_id, group_key, proof_type,
       mssmt_roots.root_hash root_hash, mssmt_nodes.sum root_sum,
       genesis_assets.asset_tag asset_name
FROM universe_roots
JOIN mssmt_roots
    ON universe_roots.namespace_root = mssmt_roots.namespace
JOIN mssmt_nodes
    ON mssmt_nodes.hash_key = mssmt_roots.root_hash AND
       mssmt_nodes.namespace = mssmt_roots.namespace
JOIN genesis_assets
    ON genesis_assets.asset_id = universe_roots.asset_id
ORDER BY 
    CASE WHEN sqlc.narg('sort_direction') = 0 THEN universe_roots.id END ASC,
    CASE WHEN sqlc.narg('sort_direction') = 1 THEN universe_roots.id END DESC
LIMIT @num_limit OFFSET @num_offset;

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

-- name: QueryUniverseServers :many
SELECT * FROM universe_servers
WHERE (id = sqlc.narg('id') OR sqlc.narg('id') IS NULL) AND
      (server_host = sqlc.narg('server_host')
           OR sqlc.narg('server_host') IS NULL);

-- name: InsertNewSyncEvent :exec
WITH group_key_root_id AS (
    SELECT id
    FROM universe_roots roots
    WHERE group_key = @group_key_x_only
      AND roots.proof_type = @proof_type
), asset_id_root_id AS (
    SELECT leaves.universe_root_id AS id
    FROM universe_leaves leaves
    JOIN universe_roots roots
        ON leaves.universe_root_id = roots.id
    JOIN genesis_info_view gen
        ON leaves.asset_genesis_id = gen.gen_asset_id
    WHERE gen.asset_id = @asset_id
        AND roots.proof_type = @proof_type
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
    FROM universe_roots roots
    WHERE group_key = @group_key_x_only
        AND roots.proof_type = @proof_type
), asset_id_root_id AS (
    SELECT leaves.universe_root_id AS id
    FROM universe_leaves leaves
    JOIN universe_roots roots
        ON leaves.universe_root_id = roots.id
    JOIN genesis_info_view gen
        ON leaves.asset_genesis_id = gen.gen_asset_id
    WHERE gen.asset_id = @asset_id
        AND roots.proof_type = @proof_type
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
WITH stats AS (
    SELECT total_asset_syncs, total_asset_proofs
    FROM universe_stats
), group_ids AS (
    SELECT id
    FROM universe_roots
    WHERE group_key IS NOT NULL
), asset_keys AS (
    SELECT hash_key
    FROM mssmt_nodes nodes
    JOIN mssmt_roots roots
      ON nodes.hash_key = roots.root_hash AND
         nodes.namespace = roots.namespace
    JOIN universe_roots uroots
      ON roots.namespace = uroots.namespace_root
), aggregated AS (
    SELECT COALESCE(SUM(stats.total_asset_syncs), 0) AS total_syncs,
           COALESCE(SUM(stats.total_asset_proofs), 0) AS total_proofs,
           0 AS total_num_groups,
           0 AS total_num_assets
    FROM stats
    UNION ALL
    SELECT 0 AS total_syncs,
           0 AS total_proofs,
           COALESCE(COUNT(group_ids.id), 0) AS total_num_groups,
           0 AS total_num_assets
    FROM group_ids
    UNION ALL
    SELECT 0 AS total_syncs,
           0 AS total_proofs,
           0 AS total_num_groups,
           COALESCE(COUNT(asset_keys.hash_key), 0) AS total_num_assets
    FROM asset_keys
)
SELECT SUM(total_syncs) AS total_syncs,
       SUM(total_proofs) AS total_proofs,
       SUM(total_num_groups) AS total_num_groups,
       SUM(total_num_assets) AS total_num_assets
FROM aggregated;

-- TODO(roasbeef): use the universe id instead for the grouping? so namespace
-- root, simplifies queries

-- name: QueryUniverseAssetStats :many
WITH asset_supply AS (
    SELECT SUM(nodes.sum) AS supply, gen.asset_id AS asset_id
    FROM universe_leaves leaves
    JOIN universe_roots roots
        ON leaves.universe_root_id = roots.id
    JOIN mssmt_nodes nodes
        ON leaves.leaf_node_key = nodes.key AND
           leaves.leaf_node_namespace = nodes.namespace
    JOIN genesis_info_view gen
        ON leaves.asset_genesis_id = gen.gen_asset_id
    WHERE roots.proof_type = 'issuance'
    GROUP BY gen.asset_id
), group_supply AS (
    SELECT sum AS num_assets, uroots.group_key AS group_key
    FROM mssmt_nodes nodes
    JOIN mssmt_roots roots
      ON nodes.hash_key = roots.root_hash AND
         nodes.namespace = roots.namespace
    JOIN universe_roots uroots
      ON roots.namespace = uroots.namespace_root
    WHERE uroots.proof_type = 'issuance'
), asset_info AS (
    SELECT asset_supply.supply, group_supply.num_assets AS group_supply,
           gen.asset_id AS asset_id, 
           gen.asset_tag AS asset_name, gen.asset_type AS asset_type,
           gen.block_height AS genesis_height, gen.prev_out AS genesis_prev_out,
           group_info.tweaked_group_key AS group_key,
           gen.output_index AS anchor_index, gen.anchor_txid AS anchor_txid
    FROM genesis_info_view gen
    JOIN asset_supply
        ON asset_supply.asset_id = gen.asset_id
    -- We use a LEFT JOIN here as not every asset has a group key, so this'll
    -- generate rows that have NULL values for the group key fields if an asset
    -- doesn't have a group key.
    LEFT JOIN key_group_info_view group_info
        ON gen.gen_asset_id = group_info.gen_asset_id
    LEFT JOIN group_supply
        ON group_supply.group_key = group_info.x_only_group_key
    WHERE (gen.asset_tag = sqlc.narg('asset_name') OR sqlc.narg('asset_name') IS NULL) AND
          (gen.asset_type = sqlc.narg('asset_type') OR sqlc.narg('asset_type') IS NULL) AND
          (gen.asset_id = sqlc.narg('asset_id') OR sqlc.narg('asset_id') IS NULL)
)
SELECT asset_info.supply AS asset_supply,
    asset_info.group_supply AS group_supply,
    asset_info.asset_name AS asset_name,
    asset_info.asset_type AS asset_type, asset_info.asset_id AS asset_id,
    asset_info.genesis_height AS genesis_height,
    asset_info.genesis_prev_out AS genesis_prev_out,
    asset_info.group_key AS group_key,
    asset_info.anchor_index AS anchor_index,
    asset_info.anchor_txid AS anchor_txid,
    universe_stats.total_asset_syncs AS total_syncs,
    universe_stats.total_asset_proofs AS total_proofs
FROM asset_info
JOIN universe_stats
    ON asset_info.asset_id = universe_stats.asset_id
WHERE universe_stats.proof_type = 'issuance'
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

-- name: UpsertFederationGlobalSyncConfig :exec
INSERT INTO federation_global_sync_config (
    proof_type, allow_sync_insert, allow_sync_export
)
VALUES (@proof_type, @allow_sync_insert, @allow_sync_export)
ON CONFLICT(proof_type)
    DO UPDATE SET
    allow_sync_insert = @allow_sync_insert,
    allow_sync_export = @allow_sync_export;

-- name: QueryFederationGlobalSyncConfigs :many
SELECT proof_type, allow_sync_insert, allow_sync_export
FROM federation_global_sync_config
ORDER BY proof_type;

-- name: UpsertFederationUniSyncConfig :exec
INSERT INTO federation_uni_sync_config  (
    namespace, asset_id, group_key, proof_type, allow_sync_insert, allow_sync_export
)
VALUES(
    @namespace, @asset_id, @group_key, @proof_type, @allow_sync_insert, @allow_sync_export
)
ON CONFLICT(namespace)
    DO UPDATE SET
    allow_sync_insert = @allow_sync_insert,
    allow_sync_export = @allow_sync_export;

-- name: QueryFederationUniSyncConfigs :many
SELECT namespace, asset_id, group_key, proof_type, allow_sync_insert, allow_sync_export
FROM federation_uni_sync_config
ORDER BY group_key NULLS LAST, asset_id NULLS LAST, proof_type;

-- name: UpsertFederationProofSyncLog :one
INSERT INTO federation_proof_sync_log as log (
    status, timestamp, sync_direction, proof_leaf_id, universe_root_id,
    servers_id
) VALUES (
    @status, @timestamp, @sync_direction,
    (
        -- Select the leaf id from the universe_leaves table.
        SELECT id
        FROM universe_leaves
        WHERE leaf_node_namespace = @leaf_namespace
            AND minting_point = @leaf_minting_point_bytes
            AND script_key_bytes = @leaf_script_key_bytes
        LIMIT 1
    ),
    (
        -- Select the universe root id from the universe_roots table.
        SELECT id
        FROM universe_roots
        WHERE namespace_root = @universe_id_namespace
        LIMIT 1
    ),
    (
        -- Select the server id from the universe_servers table.
        SELECT id
        FROM universe_servers
        WHERE server_host = @server_host
        LIMIT 1
    )
) ON CONFLICT (sync_direction, proof_leaf_id, universe_root_id, servers_id)
DO UPDATE SET
    status = EXCLUDED.status,
    timestamp = EXCLUDED.timestamp,
    -- Increment the attempt counter.
    attempt_counter = CASE
       WHEN @bump_sync_attempt_counter = true THEN log.attempt_counter + 1
       ELSE log.attempt_counter
    END
RETURNING id;

-- name: QueryFederationProofSyncLog :many
SELECT
    log.id, status, timestamp, sync_direction, attempt_counter,

    -- Select fields from the universe_servers table.
    server.id as server_id,
    server.server_host,

    -- Select universe leaf related fields.
    leaf.minting_point as leaf_minting_point_bytes,
    leaf.script_key_bytes as leaf_script_key_bytes,
    mssmt_node.value as leaf_genesis_proof,
    genesis.gen_asset_id as leaf_gen_asset_id,
    genesis.asset_id as leaf_asset_id,

    -- Select fields from the universe_roots table.
    root.asset_id as uni_asset_id,
    root.group_key as uni_group_key,
    root.proof_type as uni_proof_type

FROM federation_proof_sync_log as log

JOIN universe_leaves as leaf
    ON leaf.id = log.proof_leaf_id

-- Join on mssmt_nodes to get leaf related fields.
JOIN mssmt_nodes mssmt_node
     ON leaf.leaf_node_key = mssmt_node.key AND
        leaf.leaf_node_namespace = mssmt_node.namespace

-- Join on genesis_info_view to get leaf related fields.
JOIN genesis_info_view genesis
     ON leaf.asset_genesis_id = genesis.gen_asset_id

JOIN universe_servers as server
    ON server.id = log.servers_id

JOIN universe_roots as root
    ON root.id = log.universe_root_id

WHERE (log.sync_direction = sqlc.narg('sync_direction')
           OR sqlc.narg('sync_direction') IS NULL)
        AND
      (log.status = sqlc.narg('status') OR sqlc.narg('status') IS NULL)
        AND

      -- Universe leaves WHERE clauses.
      (leaf.leaf_node_namespace = sqlc.narg('leaf_namespace')
           OR sqlc.narg('leaf_namespace') IS NULL)
        AND
      (leaf.minting_point = sqlc.narg('leaf_minting_point_bytes')
           OR sqlc.narg('leaf_minting_point_bytes') IS NULL)
        AND
      (leaf.script_key_bytes = sqlc.narg('leaf_script_key_bytes')
           OR sqlc.narg('leaf_script_key_bytes') IS NULL);

-- name: DeleteFederationProofSyncLog :exec
WITH selected_server_id AS (
    -- Select the server ids from the universe_servers table for the specified
    -- hosts.
    SELECT id
    FROM universe_servers
    WHERE
        (server_host = sqlc.narg('server_host')
            OR sqlc.narg('server_host') IS NULL)
)
DELETE FROM federation_proof_sync_log
WHERE
    servers_id IN (SELECT id FROM selected_server_id) AND
    (status = sqlc.narg('status')
        OR sqlc.narg('status') IS NULL) AND
    (timestamp >= sqlc.narg('min_timestamp')
        OR sqlc.narg('min_timestamp') IS NULL) AND
    (attempt_counter >= sqlc.narg('min_attempt_counter')
        OR sqlc.narg('min_attempt_counter') IS NULL);

-- name: UpsertMultiverseRoot :one
INSERT INTO multiverse_roots (namespace_root, proof_type)
VALUES (@namespace_root, @proof_type)
ON CONFLICT (namespace_root)
    -- This is a no-op to allow returning the ID.
    DO UPDATE SET namespace_root = EXCLUDED.namespace_root
RETURNING id;

-- name: FetchMultiverseRoot :one
SELECT proof_type, n.hash_key as multiverse_root_hash, n.sum as multiverse_root_sum
FROM multiverse_roots r
JOIN mssmt_roots m
    ON r.namespace_root = m.namespace
JOIN mssmt_nodes n
    ON m.root_hash = n.hash_key AND
       m.namespace = n.namespace
WHERE namespace_root = @namespace_root;

-- name: UpsertMultiverseLeaf :one
INSERT INTO multiverse_leaves (
    multiverse_root_id, asset_id, group_key, leaf_node_key, leaf_node_namespace
) VALUES (
    @multiverse_root_id, @asset_id, @group_key, @leaf_node_key,
    @leaf_node_namespace
)
ON CONFLICT (leaf_node_key, leaf_node_namespace)
    -- This is a no-op to allow returning the ID.
    DO UPDATE SET leaf_node_key = EXCLUDED.leaf_node_key,
                  leaf_node_namespace = EXCLUDED.leaf_node_namespace
RETURNING id;

-- name: DeleteMultiverseLeaf :exec
DELETE FROM multiverse_leaves
WHERE leaf_node_namespace = @namespace AND leaf_node_key = @leaf_node_key;

-- name: QueryMultiverseLeaves :many
SELECT r.namespace_root, r.proof_type, l.asset_id, l.group_key, 
       smt_nodes.value AS universe_root_hash, smt_nodes.sum AS universe_root_sum
FROM multiverse_leaves l
JOIN mssmt_nodes smt_nodes
  ON l.leaf_node_key = smt_nodes.key AND
     l.leaf_node_namespace = smt_nodes.namespace
JOIN multiverse_roots r
  ON l.multiverse_root_id = r.id
WHERE r.proof_type = @proof_type AND
      (l.asset_id = @asset_id OR @asset_id IS NULL) AND
      (l.group_key = @group_key OR @group_key IS NULL);
