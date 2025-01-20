-- We restore the previous version of the universe_stats view, as it was created
-- in the 000010_universe_stats.up.sql migration file.

DROP VIEW universe_stats;

CREATE VIEW universe_stats AS
SELECT
    COUNT(CASE WHEN u.event_type = 'SYNC' THEN 1 ELSE NULL END) AS total_asset_syncs,
    COUNT(CASE WHEN u.event_type = 'NEW_PROOF' THEN 1 ELSE NULL END) AS total_asset_proofs,
    roots.asset_id,
    roots.group_key,
    roots.proof_type
FROM universe_events u
JOIN universe_roots roots
  ON u.universe_root_id = roots.id
GROUP BY roots.asset_id, roots.group_key, roots.proof_type;