CREATE TABLE IF NOT EXISTS asset_transfers (
    id INTEGER PRIMARY KEY, 

    height_hint INTEGER NOT NULL,
    
    anchor_txn_id INTEGER NOT NULL REFERENCES chain_txns(txn_id),

    transfer_time_unix TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS transfer_time_idx
    ON asset_transfers (transfer_time_unix);
CREATE INDEX IF NOT EXISTS transfer_txn_idx
    ON asset_transfers (anchor_txn_id);

CREATE TABLE IF NOT EXISTS asset_transfer_inputs (
    input_id INTEGER PRIMARY KEY,
    
    transfer_id INTEGER NOT NULL REFERENCES asset_transfers(id),
    
    anchor_point BLOB NOT NULL,
    
    asset_id BLOB NOT NULL,
    
    script_key BLOB NOT NULL,
    
    amount BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS transfer_inputs_idx
    ON asset_transfer_inputs (transfer_id);

CREATE TABLE IF NOT EXISTS asset_transfer_outputs (
    output_id INTEGER PRIMARY KEY,
    
    transfer_id INTEGER NOT NULL REFERENCES asset_transfers(id),
    
    anchor_utxo INTEGER NOT NULL REFERENCES managed_utxos(utxo_id),
    
    script_key INTEGER NOT NULL REFERENCES script_keys(script_key_id),
    
    script_key_local bool NOT NULL,
    
    amount BIGINT NOT NULL,
    
    serialized_witnesses BLOB NOT NULL,
    
    split_commitment_root_hash BLOB,
    
    split_commitment_root_value BIGINT,
    
    proof_suffix BLOB NOT NULL,

    num_passive_assets INTEGER NOT NULL
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
    passive_id INTEGER PRIMARY KEY,

    transfer_id INTEGER NOT NULL REFERENCES asset_transfers(id),

    asset_id INTEGER NOT NULL REFERENCES assets(asset_id),
    
    new_anchor_utxo INTEGER NOT NULL REFERENCES managed_utxos(utxo_id),

    script_key BLOB NOT NULL,

    new_witness_stack BLOB,

    new_proof BLOB
);
CREATE INDEX IF NOT EXISTS passive_assets_idx
    ON passive_assets (transfer_id);
