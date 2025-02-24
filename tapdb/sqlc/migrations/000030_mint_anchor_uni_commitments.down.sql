-- Drop the table mint_anchor_uni_commitments.
    DROP TABLE IF EXISTS mint_anchor_uni_commitments;

-- Drop the universe_commitments column from the asset_minting_batches table.
ALTER TABLE asset_minting_batches
    DROP COLUMN universe_commitments;

-- Drop the assets output index column from the asset_minting_batches table.
ALTER TABLE asset_minting_batches DROP COLUMN assets_output_index;