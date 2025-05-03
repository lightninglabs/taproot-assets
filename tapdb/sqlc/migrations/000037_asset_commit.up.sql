-- Enum-like table for state machine states.
CREATE TABLE supply_commit_states (
    id INTEGER PRIMARY KEY,
    state_name TEXT UNIQUE NOT NULL
);

-- Populate the possible states.
INSERT INTO supply_commit_states (id, state_name) VALUES
    (0, 'DefaultState'),
    (1, 'UpdatesPendingState'),
    (2, 'CommitTreeCreateState'),
    (3, 'CommitTxCreateState'),
    (4, 'CommitTxSignState'),
    (5, 'CommitBroadcastState'),
    (6, 'CommitFinalizeState');

-- Enum-like table for supply update event types.
CREATE TABLE supply_commit_update_types (
    id INTEGER PRIMARY KEY,
    update_type_name TEXT UNIQUE NOT NULL
);

-- Populate the possible update types.
INSERT INTO supply_commit_update_types (id, update_type_name) VALUES
    (0, 'mint'),
    (1, 'burn'),
    (2, 'ignore');

-- Table storing the details of a specific supply commitment (root and sub-trees).
-- This represents a committed state on chain.
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
    supply_root_sum BIGINT
);

-- Main table tracking the state machine instance per asset group.
CREATE TABLE supply_commit_state_machines (
    -- The tweaked group key identifying the asset group's state machine.
    group_key BLOB PRIMARY KEY CHECK(length(group_key) = 33),

    -- The current state of the state machine.
    current_state_id INTEGER NOT NULL REFERENCES supply_commit_states(id),

    -- The latest successfully committed supply state on chain.
    -- Can be NULL if no commitment has been made yet.
    latest_commitment_id BIGINT REFERENCES supply_commitments(commit_id)
);

-- Table tracking a pending state transition for a state machine.
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

    -- Indicates if this transition has been successfully completed and committed.
    finalized BOOLEAN NOT NULL DEFAULT FALSE,

    -- Timestamp when this transition was initiated.
    creation_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Table storing individual update events associated with a pending transition.
CREATE TABLE supply_update_events (
    event_id INTEGER PRIMARY KEY,

    -- Reference to the state transition this event is part of.
    transition_id BIGINT NOT NULL REFERENCES supply_commit_transitions(transition_id) ON DELETE CASCADE,

    -- The type of update (mint, burn, ignore).
    update_type_id INTEGER NOT NULL REFERENCES supply_commit_update_types(id),

    -- Opaque blob containing the serialized data for the specific
    -- SupplyUpdateEvent (NewMintEvent, NewBurnEvent, NewIgnoreEvent).
    event_data BLOB NOT NULL
);

-- In order to be able to easily fetch the set of unspent pre-commitment
-- outputs, we'll add a new spent_by field to mint_anchor_uni_commitments.
ALTER TABLE mint_anchor_uni_commitments
    ADD COLUMN spent_by BIGINT REFERENCES supply_commitments(commit_id);

-- Add indexes for frequent lookups.
CREATE INDEX supply_commitments_chain_txn_id_idx ON supply_commitments(chain_txn_id);
CREATE INDEX supply_commit_transitions_state_machine_group_key_idx ON supply_commit_transitions(state_machine_group_key);
CREATE INDEX supply_update_events_transition_id_idx ON supply_update_events(transition_id);
CREATE INDEX supply_commitments_group_key_idx ON supply_commitments(group_key);

-- Ensure only one non-finalized transition exists per state machine group key.
CREATE UNIQUE INDEX supply_commit_transitions_single_pending_idx
    ON supply_commit_transitions (state_machine_group_key) WHERE finalized = 0;
