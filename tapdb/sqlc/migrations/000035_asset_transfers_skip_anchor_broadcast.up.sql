-- Add a flag to optionally skip anchor transaction broadcast for asset
-- transfers.
ALTER TABLE asset_transfers
ADD COLUMN skip_anchor_tx_broadcast BOOLEAN NOT NULL DEFAULT FALSE;
