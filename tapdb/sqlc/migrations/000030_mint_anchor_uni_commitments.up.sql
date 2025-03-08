-- Add a column to the asset_minting_batches table which stores the output index
-- of the asset anchor transaction output.
ALTER TABLE asset_minting_batches ADD COLUMN assets_output_index INTEGER;

-- Existing minting anchor transactions have exactly two outputs: the asset
-- commitment and the change output. We can therefore infer the asset anchor
-- output index from the change output index.
UPDATE asset_minting_batches
SET assets_output_index = CASE
    WHEN change_output_index = 1 THEN 0
    WHEN change_output_index = 0 THEN 1
    -- If change_output_index is neither 0 nor 1, just set the asset anchor
    -- output index to NULL.
    ELSE NULL
END;

-- Add a flag column which indicates if the universe commitments are enabled for
-- this minting batch. This should default to false for all existing minting
-- batches.
ALTER TABLE asset_minting_batches
    ADD COLUMN universe_commitments BOOLEAN NOT NULL DEFAULT FALSE;

-- Create a table to relate a mint batch anchor transaction to its universe
-- commitments.
CREATE TABLE IF NOT EXISTS mint_anchor_uni_commitments (
    id INTEGER PRIMARY KEY,

    -- The ID of the minting batch this universe commitment relates to.
    batch_id INTEGER NOT NULL REFERENCES asset_minting_batches(batch_id),

    -- The index of the mint batch anchor transaction pre-commitment output.
    tx_output_index INTEGER NOT NULL,

    -- The Taproot output internal key for the pre-commitment output.
    taproot_internal_key BLOB,

    -- The asset group key associated with the universe commitment.
    group_key BLOB
);

-- Create a unique index on the mint_anchor_uni_commitments table to enforce the
-- uniqueness of (batch_id, tx_output_index) pairs.
CREATE UNIQUE INDEX mint_anchor_uni_commitments_unique
    ON mint_anchor_uni_commitments (batch_id, tx_output_index);
