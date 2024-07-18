-- Remove the unique constraint on the `transfer_id` and `position` columns in
-- the `asset_transfer_outputs` table.
DROP INDEX asset_transfer_outputs_transfer_id_position_unique;

-- Remove the `proof_delivery_complete` column from the `asset_transfer_outputs`
-- table.
ALTER TABLE asset_transfer_outputs DROP COLUMN proof_delivery_complete;

-- Remove the `position` column from the `asset_transfer_outputs` table.
ALTER TABLE asset_transfer_outputs DROP COLUMN position;