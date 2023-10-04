-- addr_events stores all events related to inbound (received) assets for
-- addresses.
CREATE TABLE IF NOT EXISTS addr_events (
    id BIGINT PRIMARY KEY,

    -- creation_time is the creation time of this event.
    creation_time TIMESTAMP NOT NULL,

    -- addr_id is the reference to the address this event was emitted for.
    addr_id BIGINT NOT NULL REFERENCES addrs(id),

    -- status is the status of the inbound asset.
    status SMALLINT NOT NULL CHECK (status IN (0, 1, 2, 3)),

    -- chain_txn_id is a reference to the chain transaction that has the Taproot
    -- output for this event.
    chain_txn_id BIGINT NOT NULL REFERENCES chain_txns(txn_id),

    -- chain_txn_output_index is the index of the on-chain output (of the
    -- transaction referenced by chain_txn_id) that houses the Taproot Asset
    -- commitment.
    chain_txn_output_index INTEGER NOT NULL,

    -- managed_utxo_id is a reference to the managed UTXO the internal wallet
    -- tracks with on-chain funds that belong to us.
    managed_utxo_id BIGINT NOT NULL REFERENCES managed_utxos(utxo_id),

    -- asset_proof_id is a reference to the proof associated with this asset
    -- event.
    asset_proof_id BIGINT REFERENCES asset_proofs(proof_id),
    
    -- asset_id is a reference to the asset once we have taken custody of it.
    -- This will only be set once the proofs were imported successfully and the
    -- event is in the status complete.
    asset_id BIGINT REFERENCES assets(asset_id),
    
    UNIQUE(addr_id, chain_txn_id, chain_txn_output_index)
);
CREATE INDEX IF NOT EXISTS creation_time_idx ON addr_events(creation_time);
CREATE INDEX IF NOT EXISTS status_idx ON addr_events(status);
CREATE INDEX IF NOT EXISTS asset_proof_id_idx ON addr_events(asset_proof_id);
CREATE INDEX IF NOT EXISTS asset_id_idx ON addr_events(asset_id);
