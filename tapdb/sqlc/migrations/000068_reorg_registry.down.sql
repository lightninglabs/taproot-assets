DROP INDEX IF EXISTS reorg_outbox_pending_idx;
DROP TABLE IF EXISTS reorg_outbox;

DROP INDEX IF EXISTS reorg_dependencies_parent_idx;
DROP INDEX IF EXISTS reorg_dependencies_uk;
DROP TABLE IF EXISTS reorg_dependencies;

DROP INDEX IF EXISTS reorg_candidate_spends_spender_idx;
DROP INDEX IF EXISTS reorg_candidate_spends_uk;
DROP TABLE IF EXISTS reorg_candidate_spends;

DROP INDEX IF EXISTS reorg_trigger_outpoints_op_idx;
DROP INDEX IF EXISTS reorg_trigger_outpoints_uk;
DROP TABLE IF EXISTS reorg_trigger_outpoints;

DROP INDEX IF EXISTS reorg_anchorings_stuck_idx;
DROP INDEX IF EXISTS reorg_anchorings_site_idx;
DROP INDEX IF EXISTS reorg_anchorings_phase_idx;
DROP TABLE IF EXISTS reorg_anchorings;
