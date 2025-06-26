CREATE UNIQUE INDEX IF NOT EXISTS addrs_script_key_version_2_uk
    ON addrs (script_key_id, version) WHERE version = 2;

CREATE TABLE IF NOT EXISTS addr_event_outputs (
    id INTEGER PRIMARY KEY,

    -- addr_event_id is the reference to the address event this output belongs to.
    addr_event_id BIGINT NOT NULL REFERENCES addr_events(id),

    amount BIGINT NOT NULL,
    
    asset_id BLOB NOT NULL CHECK(length(asset_id) = 32),

    -- script_key_id points to the internal key that we created to serve as the
    -- script key to be able to receive this asset.
    script_key_id BIGINT NOT NULL REFERENCES script_keys(script_key_id)
);

CREATE TABLE IF NOT EXISTS addr_event_proofs (
    id INTEGER PRIMARY KEY,

    -- addr_event_id is the reference to the address event this proof belongs to.
    addr_event_id BIGINT NOT NULL REFERENCES addr_events(id),

    -- asset_proof_id is a reference to the proof associated with this asset
    -- event.
    asset_proof_id BIGINT NOT NULL REFERENCES asset_proofs(proof_id)
);

-- TODO(guggero):
--  - migration for existing records,
--  - drop column asset_proof_id from addr_events
