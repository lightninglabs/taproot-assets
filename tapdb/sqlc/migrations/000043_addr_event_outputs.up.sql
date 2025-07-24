-- Addresses with version 2 use the raw internal key as the script key. And we
-- need to be able to identify these addresses by script key, so we need a
-- unique index on the script_key_id and version columns to prevent users from
-- creating duplicate V2 addresses.
CREATE UNIQUE INDEX IF NOT EXISTS addrs_script_key_version_2_uk
    ON addrs (script_key_id, version) WHERE version = 2;

-- An event can now have multiple asset outputs, in case multiple tranches of a
-- grouped asset were sent as part of a V2 address transfer.
CREATE TABLE IF NOT EXISTS addr_event_outputs (
    id INTEGER PRIMARY KEY,

    -- addr_event_id is the reference to the address event this output belongs
    -- to.
    addr_event_id BIGINT NOT NULL REFERENCES addr_events(id),

    -- amount is the amount of the asset that this output represents. This might
    -- only be part of the total amount of the address that is referenced by the
    -- event.
    amount BIGINT NOT NULL,
    
    -- asset_id is the ID of the asset that this output represents.
    asset_id BLOB NOT NULL CHECK(length(asset_id) = 32),

    -- script_key_id points to the internal key that we created to serve as the
    -- script key to be able to receive this asset.
    script_key_id BIGINT NOT NULL REFERENCES script_keys(script_key_id)
);

-- The same asset ID can only be used once per address event, so we add a
-- unique constraint on the combination of addr_event_id and asset_id. This will
-- allow us to upsert event outputs.
CREATE UNIQUE INDEX IF NOT EXISTS addr_event_outputs_addr_event_id_asset_id_uk
    ON addr_event_outputs (addr_event_id, asset_id);

-- We also make sure joins are fast by creating an index on addr_event_id.
CREATE INDEX IF NOT EXISTS addr_event_outputs_addr_event_id_idx
    ON addr_event_outputs (addr_event_id);

-- The data migration is quite simple, we just join the existing data from
-- multiple tables into the new addr_event_outputs table.
INSERT INTO addr_event_outputs (
    addr_event_id, amount, asset_id, script_key_id
)
SELECT 
    ae.id AS addr_event_id,
    a.amount AS amount,
    ga.asset_id AS asset_id,
    a.script_key_id AS script_key_id
FROM addr_events AS ae
JOIN addrs AS a
    ON a.id = ae.addr_id
JOIN genesis_assets AS ga
    ON a.genesis_asset_id = ga.gen_asset_id;

-- We'll also have multiple proofs associated with an address event, in case
-- multiple proofs were sent as part of a V2 address transfer.
CREATE TABLE IF NOT EXISTS addr_event_proofs (
    id INTEGER PRIMARY KEY,

    -- addr_event_id is the reference to the address event this proof belongs to.
    addr_event_id BIGINT NOT NULL REFERENCES addr_events(id),

    -- asset_proof_id is a reference to the proof associated with this asset
    -- event.
    asset_proof_id BIGINT NOT NULL REFERENCES asset_proofs(proof_id),

    -- asset_id_fk is a reference to the asset once we have taken custody of it.
    -- This will only be set once the proofs were imported successfully and the
    -- event is in the status complete.
    asset_id_fk BIGINT REFERENCES assets(asset_id)
);

-- The same asset proof can only be used once per address event, so we add a
-- unique constraint on the combination of addr_event_id and asset_proof_id.
-- This will allow us to upsert event proofs.
CREATE UNIQUE INDEX IF NOT EXISTS 
    addr_event_proofs_addr_event_id_asset_proof_id_uk
    ON addr_event_proofs (addr_event_id, asset_proof_id);

-- We also make sure joins are fast by creating an index on addr_event_id.
CREATE INDEX IF NOT EXISTS addr_event_proofs_addr_event_id_idx
    ON addr_event_proofs (addr_event_id);

-- And again, we migrate the existing data from the 1:1 relationship to the new
-- 1:n relationship.
INSERT INTO addr_event_proofs (
    addr_event_id, asset_proof_id, asset_id_fk
)
SELECT 
    ae.id AS addr_event_id,
    ae.asset_proof_id AS asset_proof_id,
    ae.asset_id AS asset_id_fk
FROM addr_events AS ae
LEFT JOIN assets AS a
    ON ae.asset_id = a.asset_id 
WHERE ae.asset_proof_id IS NOT NULL;

-- And now we can drop the old columns from the tables.
DROP INDEX IF EXISTS asset_proof_id_idx;
DROP INDEX IF EXISTS asset_id_idx;
ALTER TABLE addr_events
    DROP COLUMN asset_id;

ALTER TABLE addr_events
    DROP COLUMN asset_proof_id;
