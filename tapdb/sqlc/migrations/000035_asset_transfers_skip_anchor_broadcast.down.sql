-- Remove the skip_anchor_tx_broadcast flag from asset_transfers table.
ALTER TABLE asset_transfers DROP COLUMN skip_anchor_tx_broadcast;
