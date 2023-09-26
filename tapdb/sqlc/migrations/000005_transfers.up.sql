CREATE TABLE IF NOT EXISTS asset_transfers (
    id BIGINT PRIMARY KEY, 

    height_hint INTEGER NOT NULL,
    
    anchor_txn_id BIGINT NOT NULL REFERENCES chain_txns(txn_id),

    transfer_time_unix TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS transfer_time_idx
    ON asset_transfers (transfer_time_unix);
CREATE INDEX IF NOT EXISTS transfer_txn_idx
    ON asset_transfers (anchor_txn_id);

CREATE TABLE IF NOT EXISTS asset_transfer_inputs (
    input_id BIGINT PRIMARY KEY,
    
    transfer_id BIGINT NOT NULL REFERENCES asset_transfers(id),
    
    anchor_point BLOB NOT NULL,
    
    asset_id BLOB NOT NULL,
    
    script_key BLOB NOT NULL,
    
    amount BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS transfer_inputs_idx
    ON asset_transfer_inputs (transfer_id);

CREATE TABLE IF NOT EXISTS asset_transfer_outputs (
    output_id BIGINT PRIMARY KEY,
    
    transfer_id BIGINT NOT NULL REFERENCES asset_transfers(id),
    
    anchor_utxo BIGINT NOT NULL REFERENCES managed_utxos(utxo_id),
    
    script_key BIGINT NOT NULL REFERENCES script_keys(script_key_id),
    
    script_key_local BOOL NOT NULL,
    
    amount BIGINT NOT NULL,

    asset_version INTEGER NOT NULL,
    
    serialized_witnesses BLOB,
    
    split_commitment_root_hash BLOB,
    
    split_commitment_root_value BIGINT,
    
    proof_suffix BLOB,

    num_passive_assets INTEGER NOT NULL,

    output_type SMALLINT NOT NULL,

    -- proof_courier_addr is the proof courier service address associated with
    -- the output. This value will be NULL for outputs that do not require proof
    -- transfer.
    proof_courier_addr BLOB
);
CREATE INDEX IF NOT EXISTS transfer_outputs_idx
    ON asset_transfer_outputs (transfer_id);

CREATE TABLE IF NOT EXISTS receiver_proof_transfer_attempts (
    proof_locator_hash BLOB NOT NULL,

    time_unix TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS proof_locator_hash_index 
    ON receiver_proof_transfer_attempts (proof_locator_hash);

-- passive_assets is a table that stores the information needed to
-- re-anchor a passive asset.
CREATE TABLE IF NOT EXISTS passive_assets (
    passive_id BIGINT PRIMARY KEY,

    transfer_id BIGINT NOT NULL REFERENCES asset_transfers(id),

    asset_id BIGINT NOT NULL REFERENCES assets(asset_id),
    
    new_anchor_utxo BIGINT NOT NULL REFERENCES managed_utxos(utxo_id),

    script_key BLOB NOT NULL,

    asset_version INTEGER NOT NULL,

    new_witness_stack BLOB,

    new_proof BLOB
);
CREATE INDEX IF NOT EXISTS passive_assets_idx
    ON passive_assets (transfer_id);
