-- Remove the index on the input anchor points.
DROP INDEX IF EXISTS transfer_inputs_anchor_point_idx;

-- Remove the superseded flag from the asset_transfers table.
ALTER TABLE asset_transfers DROP COLUMN superseded;
