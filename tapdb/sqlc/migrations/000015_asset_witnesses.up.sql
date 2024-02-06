-- The witness index indicates the order of the witness in the list of witnesses
-- for a given asset. We'll be inserting an actual value in the next query, so
-- we just start with -1.
ALTER TABLE asset_witnesses ADD COLUMN witness_index INTEGER NOT NULL DEFAULT -1;

-- Update the witness index to be the same as the witness id. We'll use the
-- witness_index for sorting only, so setting the default to the witness_id is
-- just to make sure we preserve the current order of witnesses while also
-- satisfying the unique constraint we add below.
UPDATE asset_witnesses SET witness_index = CAST(witness_id AS INTEGER)
    WHERE witness_index = -1;

-- We need to be able to upsert witnesses, so we need a unique constraint on
-- (asset_id, witness_index).
CREATE UNIQUE INDEX asset_witnesses_asset_id_witness_index_unique
ON asset_witnesses (
    asset_id, witness_index
);
