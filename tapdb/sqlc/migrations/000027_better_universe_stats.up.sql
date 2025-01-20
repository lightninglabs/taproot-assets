DROP VIEW universe_stats;

CREATE VIEW universe_stats AS
WITH sync_counts AS (
    SELECT universe_root_id, COUNT(*) AS count
    FROM universe_events
    WHERE event_type = 'SYNC'
    GROUP BY universe_root_id
), proof_counts AS (
    SELECT universe_root_id, event_type, COUNT(*) AS count
    FROM universe_events
    WHERE event_type = 'NEW_PROOF'
    GROUP BY universe_root_id, event_type
), aggregated AS (
    SELECT COALESCE(SUM(count), 0) as total_asset_syncs,
           0 AS total_asset_proofs,
           universe_root_id
    FROM sync_counts
    GROUP BY universe_root_id
    UNION ALL
    SELECT 0 AS total_asset_syncs,
           COALESCE(SUM(count), 0) as total_asset_proofs,
           universe_root_id
    FROM proof_counts
    GROUP BY universe_root_id
)
SELECT
    SUM(ag.total_asset_syncs) AS total_asset_syncs,
    SUM(ag.total_asset_proofs) AS total_asset_proofs,
    roots.asset_id,
    roots.group_key,
    roots.proof_type
FROM aggregated ag
JOIN universe_roots roots
    ON ag.universe_root_id = roots.id
GROUP BY roots.asset_id, roots.group_key, roots.proof_type
ORDER BY roots.asset_id, roots.group_key, roots.proof_type;
