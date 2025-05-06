DROP INDEX IF EXISTS supply_commit_transitions_single_pending_idx;
DROP INDEX IF EXISTS supply_update_events_transition_id_idx;
DROP INDEX IF EXISTS supply_commit_transitions_state_machine_group_key_idx;
DROP INDEX IF EXISTS supply_commitments_chain_txn_id_idx;
DROP INDEX IF EXISTS supply_commitments_group_key_idx;

DROP TABLE IF EXISTS supply_update_events;
DROP TABLE IF EXISTS supply_commit_transitions;
DROP TABLE IF EXISTS supply_commit_state_machines;
DROP TABLE IF EXISTS supply_commitments;
DROP TABLE IF EXISTS supply_commit_update_types;
DROP TABLE IF EXISTS supply_commit_states;

ALTER TABLE mint_anchor_uni_commitments DROP COLUMN spent_by;

ALTER TABLE supply_commitments DROP COLUMN supply_root_hash;
ALTER TABLE supply_commitments DROP COLUMN supply_root_sum;
