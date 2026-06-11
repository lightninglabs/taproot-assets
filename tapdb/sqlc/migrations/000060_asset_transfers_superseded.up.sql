-- Add a flag that marks an asset transfer as superseded: another transfer
-- spending (some of) the same inputs confirmed on-chain, so this transfer's
-- anchor transaction can never confirm. Superseded transfers are no longer
-- considered pending and are not resumed at startup.
ALTER TABLE asset_transfers ADD COLUMN superseded BOOLEAN NOT NULL DEFAULT FALSE;

-- Index the input anchor points, so that finding conflicting transfers at
-- confirmation time doesn't require a full table scan.
CREATE INDEX IF NOT EXISTS transfer_inputs_anchor_point_idx
    ON asset_transfer_inputs (anchor_point);
