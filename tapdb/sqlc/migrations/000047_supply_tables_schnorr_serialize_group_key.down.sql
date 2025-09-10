-------------------------------------------------------------------------------
-- Down migration: revert 32-byte group keys back to 33-byte where applicable.
-- Drop all relevant dependants and tables first (indexes, then tables).
-------------------------------------------------------------------------------

-- universe_supply_leaves.
DROP INDEX IF EXISTS universe_supply_leaves_supply_root_id_type_idx;
DROP TABLE IF EXISTS universe_supply_leaves;

-- universe_supply_roots.
DROP INDEX IF EXISTS universe_supply_roots_group_key_idx;
DROP TABLE IF EXISTS universe_supply_roots;

-- supply_update_events.
DROP INDEX IF EXISTS supply_update_events_transition_id_idx;
DROP TABLE IF EXISTS supply_update_events;

-- supply_syncer_push_log.
DROP INDEX IF EXISTS supply_syncer_push_log_group_key_idx;
DROP INDEX IF EXISTS supply_syncer_push_log_server_address_idx;
DROP TABLE IF EXISTS supply_syncer_push_log;

-- supply_commit_transitions.
DROP INDEX IF EXISTS supply_commit_transitions_single_pending_idx;
DROP INDEX IF EXISTS supply_commit_transitions_state_machine_group_key_idx;
DROP TABLE IF EXISTS supply_commit_transitions;

-- supply_commit_state_machines.
DROP TABLE IF EXISTS supply_commit_state_machines;

-- mint_supply_pre_commits.
DROP INDEX IF EXISTS mint_anchor_uni_commitments_outpoint_idx;
DROP INDEX IF EXISTS mint_anchor_uni_commitments_unique;
DROP TABLE IF EXISTS mint_supply_pre_commits;

-- supply_pre_commits.
DROP INDEX IF EXISTS supply_pre_commits_idx_group_key;
DROP INDEX IF EXISTS supply_pre_commits_unique_outpoint;
DROP TABLE IF EXISTS supply_pre_commits;

-- supply_commitments.
DROP INDEX IF EXISTS supply_commitments_chain_txn_id_idx;
DROP INDEX IF EXISTS supply_commitments_group_key_idx;
DROP INDEX IF EXISTS supply_commitments_outpoint_uk;
DROP INDEX IF EXISTS supply_commitments_spent_commitment_idx;
DROP TABLE IF EXISTS supply_commitments;

-------------------------------------------------------------------------------
-- Recreate tables and indexes with 33-byte group_key where they were 32-byte.
-------------------------------------------------------------------------------

-- Recreate universe_supply_roots with original 33-byte group_key.
CREATE TABLE universe_supply_roots (
    id INTEGER PRIMARY KEY,

    -- The namespace root of the MS-SMT representing this supply tree.
    -- We set the foreign key constraint evaluation to be deferred until after
    -- the database transaction ends. Otherwise, if the root of the SMT is
    -- deleted temporarily before inserting a new root, then this constraint
    -- is violated.
    namespace_root VARCHAR UNIQUE NOT NULL REFERENCES mssmt_roots(namespace) DEFERRABLE INITIALLY DEFERRED,

    -- The tweaked group key identifying the asset group this supply tree belongs to.
    group_key BLOB UNIQUE NOT NULL CHECK(length(group_key) = 33)
);

-- Recreate the index.
CREATE INDEX universe_supply_roots_group_key_idx ON universe_supply_roots(group_key);

-- Recreate dependant table and FK.
CREATE TABLE universe_supply_leaves (
    id INTEGER PRIMARY KEY,

    -- Reference to the root supply tree this leaf belongs to.
    supply_root_id BIGINT NOT NULL REFERENCES universe_supply_roots(id) ON DELETE CASCADE,

    -- The type of sub-tree this leaf represents (mint_supply, burn, ignore).
    sub_tree_type TEXT NOT NULL REFERENCES proof_types(proof_type),

    -- The key used for this leaf within the root supply tree's MS-SMT.
    leaf_node_key BLOB NOT NULL,

    -- The namespace within mssmt_nodes where the actual sub-tree root node resides.
    leaf_node_namespace VARCHAR NOT NULL
);

CREATE UNIQUE INDEX universe_supply_leaves_supply_root_id_type_idx
    ON universe_supply_leaves (supply_root_id, sub_tree_type);

-- Recreate supply_syncer_push_log with original 33-byte group_key.
CREATE TABLE supply_syncer_push_log (
    id INTEGER PRIMARY KEY,

    -- The tweaked group key identifying the asset group this push log belongs to.
    -- This should match the group_key format used in universe_supply_roots.
    group_key BLOB NOT NULL CHECK(length(group_key) = 33),

    -- The highest block height among all supply leaves in this push.
    max_pushed_block_height INTEGER NOT NULL,

    -- The server address (host:port) where the commitment was pushed.
    server_address TEXT NOT NULL,

    -- The transaction ID (hash) of the supply commitment.
    commit_txid BLOB NOT NULL CHECK(length(commit_txid) = 32),

    -- The supply commitment output index within the commitment transaction.
    output_index INTEGER NOT NULL,

    -- The number of leaves included in this specific push.
    num_leaves_pushed INTEGER NOT NULL,

    -- The timestamp when this push log entry was created (unix timestamp in seconds).
    created_at BIGINT NOT NULL
);

-- Recreate the indexes.
CREATE INDEX supply_syncer_push_log_group_key_idx ON supply_syncer_push_log(group_key);
CREATE INDEX supply_syncer_push_log_server_address_idx ON supply_syncer_push_log(server_address);

-- Recreate supply_commitments with original 33-byte group_key.
CREATE TABLE supply_commitments (
    commit_id INTEGER PRIMARY KEY,

    -- The tweaked group key identifying the asset group this commitment belongs to.
    group_key BLOB NOT NULL CHECK(length(group_key) = 33),

    -- The chain transaction that included this commitment.
    chain_txn_id BIGINT NOT NULL REFERENCES chain_txns(txn_id),

    -- The output index within the chain_txn_id transaction for the commitment.
    output_index INTEGER,

    -- The internal key used for the commitment output.
    internal_key_id BIGINT NOT NULL REFERENCES internal_keys(key_id),

    -- The taproot output key used for the commitment output.
    output_key BLOB NOT NULL CHECK(length(output_key) = 33),

    -- The block header of the block mining the commitment transaction.
    block_header BLOB,

    -- The block height at which the commitment transaction was confirmed.
    -- Can be NULL if the transaction is not yet confirmed.
    block_height INTEGER,

    -- The merkle proof demonstrating the commitment's inclusion in the block.
    merkle_proof BLOB,

    -- The root hash of the supply commitment at this snapshot.
    supply_root_hash BLOB,

    -- The root sum of the supply commitment at this snapshot.
    supply_root_sum BIGINT,

    spent_commitment BIGINT REFERENCES supply_commitments(commit_id)
);

-- Recreate the indexes.
CREATE INDEX supply_commitments_chain_txn_id_idx ON supply_commitments(chain_txn_id);
CREATE INDEX supply_commitments_group_key_idx ON supply_commitments(group_key);
CREATE UNIQUE INDEX supply_commitments_outpoint_uk ON supply_commitments(chain_txn_id, output_index);
CREATE INDEX supply_commitments_spent_commitment_idx ON supply_commitments(spent_commitment);

-- Recreate supply_commit_state_machines with original 33-byte group_key.
CREATE TABLE supply_commit_state_machines (
    -- The tweaked group key identifying the asset group's state machine.
    group_key BLOB PRIMARY KEY CHECK(length(group_key) = 33),

    -- The current state of the state machine.
    current_state_id INTEGER NOT NULL REFERENCES supply_commit_states(id),

    -- The latest successfully committed supply state on chain.
    -- Can be NULL if no commitment has been made yet.
    latest_commitment_id BIGINT REFERENCES supply_commitments(commit_id)
);

-- Recreate supply_commit_transitions.
CREATE TABLE supply_commit_transitions (
    transition_id INTEGER PRIMARY KEY,

    -- Reference back to the state machine this transition belongs to.
    state_machine_group_key BLOB NOT NULL REFERENCES supply_commit_state_machines(group_key),

    -- The commitment being replaced by this transition.
    -- Can be NULL if this is the first commitment.
    old_commitment_id BIGINT REFERENCES supply_commitments(commit_id),

    -- The new commitment that this transition aims to create.
    -- Can be NULL initially, before the commitment details are created.
    new_commitment_id BIGINT REFERENCES supply_commitments(commit_id),

    -- The chain transaction that, once confirmed, will finalize this transition.
    -- Can be NULL until the transaction is created and signed.
    pending_commit_txn_id BIGINT REFERENCES chain_txns(txn_id),

    -- Indicates if this transition is frozen and should not accept new updates.
    frozen BOOLEAN NOT NULL DEFAULT FALSE,

    -- Indicates if this transition has been successfully completed and committed.
    finalized BOOLEAN NOT NULL DEFAULT FALSE,

    -- Timestamp when this transition was initiated (unix timestamp in seconds).
    creation_time BIGINT NOT NULL
);

CREATE UNIQUE INDEX supply_commit_transitions_single_pending_idx
    ON supply_commit_transitions (state_machine_group_key) WHERE finalized = FALSE;
CREATE INDEX supply_commit_transitions_state_machine_group_key_idx
    ON supply_commit_transitions(state_machine_group_key);

-- Recreate supply_update_events with original 33-byte group_key.
CREATE TABLE supply_update_events (
    event_id INTEGER PRIMARY KEY,

    -- The group key of the asset group this event belongs to.
    -- This is needed to query for dangling events for a specific group.
    group_key BLOB NOT NULL CHECK(length(group_key) = 33),

    -- Reference to the state transition this event is part of.
    -- Can be NULL if the event is staged while another transition is active.
    transition_id BIGINT REFERENCES supply_commit_transitions(transition_id) ON DELETE CASCADE,

    -- The type of update (mint, burn, ignore).
    update_type_id INTEGER NOT NULL REFERENCES supply_commit_update_types(id),

    -- Opaque blob containing the serialized data for the specific
    -- SupplyUpdateEvent (NewMintEvent, NewBurnEvent, NewIgnoreEvent).
    event_data BLOB NOT NULL
);

-- Recreate the index.
CREATE INDEX supply_update_events_transition_id_idx ON supply_update_events(transition_id);

-- Recreate mint_supply_pre_commits with original group_key definition.
CREATE TABLE mint_supply_pre_commits (
    id INTEGER PRIMARY KEY,

    -- The ID of the minting batch this universe commitment relates to.
    batch_id INTEGER NOT NULL REFERENCES asset_minting_batches(batch_id),

    -- The index of the mint batch anchor transaction pre-commitment output.
    tx_output_index INTEGER NOT NULL,

    -- The Taproot output internal key for the pre-commitment output.
    taproot_internal_key_id BIGINT NOT NULL REFERENCES internal_keys(key_id),

    -- The commitment that spent this pre-commitment output, if any.
    spent_by BIGINT REFERENCES supply_commitments(commit_id),

    -- The outpoint of the pre-commitment output (txid || vout).
    outpoint BLOB,

    -- The asset group key for this pre-commitment.
    -- Restored to original definition without length check.
    group_key BLOB
);

-- Recreate the indexes.
CREATE INDEX mint_anchor_uni_commitments_outpoint_idx
    ON mint_supply_pre_commits(outpoint)
    WHERE outpoint IS NOT NULL;
CREATE UNIQUE INDEX mint_anchor_uni_commitments_unique
    ON mint_supply_pre_commits (batch_id, tx_output_index);

-- Recreate supply_pre_commits with 33-byte group_key.
CREATE TABLE supply_pre_commits (
    id INTEGER PRIMARY KEY,

    -- The asset group key for this supply pre-commitment.
    -- Restored to 33-byte length check.
    group_key BLOB NOT NULL CHECK(length(group_key) = 33),

    -- The taproot internal key of the pre-commitment transaction output.
    taproot_internal_key BLOB NOT NULL CHECK(length(taproot_internal_key) = 33),

    -- The pre-commit outpoint from the mint anchor transaction.
    outpoint BLOB NOT NULL CHECK(length(outpoint) > 0),

    -- The chain transaction that included this pre-commitment output.
    chain_txn_db_id BIGINT NOT NULL REFERENCES chain_txns(txn_id),

    -- Reference to supply commitment which spends this pre-commitment.
    spent_by BIGINT REFERENCES supply_commitments(commit_id)
);

CREATE INDEX supply_pre_commits_idx_group_key ON supply_pre_commits(group_key);
CREATE UNIQUE INDEX supply_pre_commits_unique_outpoint ON supply_pre_commits(outpoint);
