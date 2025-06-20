DROP VIEW universe_stats;

CREATE VIEW universe_stats AS
SELECT
    roots.asset_id,
    roots.group_key,
    roots.proof_type,
    COUNT(CASE WHEN u.event_type = 'SYNC' THEN 1 END)
        AS total_asset_syncs,
    COUNT(CASE WHEN u.event_type = 'NEW_PROOF' THEN 1 END)
        AS total_asset_proofs
FROM universe_events AS u
INNER JOIN universe_roots AS roots
    ON u.universe_root_id = roots.id
GROUP BY roots.asset_id, roots.group_key, roots.proof_type;
