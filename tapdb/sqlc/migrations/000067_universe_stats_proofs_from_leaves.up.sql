-- Derive the universe proof count from the leaves we actually hold rather
-- than from the NEW_PROOF event log.
--
-- total_asset_proofs used to be a COUNT(*) over universe_events, which counts
-- registration attempts: a peer re-pushing a leaf we already had wrote another
-- row. Counting universe_leaves reports what the universe holds, and does so
-- for databases that already accumulated duplicate events.
--
-- The sync count is unchanged and still comes from the event log, which is
-- where "how much traffic did we see" belongs.
DROP VIEW universe_stats;

CREATE VIEW universe_stats AS
WITH sync_counts AS (
    SELECT universe_root_id, COUNT(*) AS count
    FROM universe_events
    WHERE event_type = 'SYNC'
    GROUP BY universe_root_id
), proof_counts AS (
    SELECT leaves.universe_root_id, COUNT(*) AS count
    FROM universe_leaves leaves
    JOIN universe_roots roots
        ON leaves.universe_root_id = roots.id
    -- The supply commitment sub-trees (burn, ignore and mint_supply) store
    -- their leaves in this table too, but they are not universe proofs and
    -- were never counted here, as they never produced a NEW_PROOF event.
    WHERE roots.proof_type IN ('issuance', 'transfer')
    GROUP BY leaves.universe_root_id
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
