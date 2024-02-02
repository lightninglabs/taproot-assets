-- The witness index indicates the order of the witness in the list of witnesses
-- for a given asset. We didn't really support more than one witness before, so
-- the default value of 0 should be fine for all existing assets.
ALTER TABLE asset_witnesses ADD COLUMN witness_index INTEGER NOT NULL DEFAULT 0;

-- We need to be able to upsert witnesses, so we need a unique constraint on
-- (asset_id, witness_index).
CREATE UNIQUE INDEX asset_witnesses_asset_id_witness_index_unique
ON asset_witnesses (
    asset_id, witness_index
);
