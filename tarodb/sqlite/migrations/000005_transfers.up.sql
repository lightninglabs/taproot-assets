CREATE TABLE IF NOT EXISTS asset_transfers (
    id INTEGER PRIMARY KEY, 

    old_anchor_point BLOB NOT NULL,

    new_internal_key INTEGER NOT NULL REFERENCES internal_keys(key_id),

    new_anchor_utxo INTEGER NOT NULL REFERENCES managed_utxos(utxo_id),

    transfer_time_unix TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS transfer_lookup on asset_transfers (transfer_time_unix);

CREATE TABLE IF NOT EXISTS asset_deltas (
    id INTEGER PRIMARY KEY,

    old_script_key BLOB NOT NULL,

    new_amt BIGINT NOT NULL,

    new_script_key INTEGER NOT NULL REFERENCES internal_keys(key_id),

    serialized_witnesses BLOB NOT NULL,

    transfer_id INTEGER NOT NULL REFERENCES asset_transfers(id)
);
