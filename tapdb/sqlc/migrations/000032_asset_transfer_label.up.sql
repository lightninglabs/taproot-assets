-- Add a column `label` to table `asset_transfer`.
ALTER TABLE asset_transfers ADD COLUMN label VARCHAR DEFAULT NULL;