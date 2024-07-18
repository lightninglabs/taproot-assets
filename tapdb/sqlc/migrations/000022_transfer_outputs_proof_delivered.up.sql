-- Add a column to track if the proof has been delivered for an asset transfer
-- output.
ALTER TABLE asset_transfer_outputs
ADD COLUMN proof_delivery_complete BOOL;

-- Add column `position` which indicates the index of the output in the list of
-- outputs for a given transfer. This index position in conjunction with the
-- transfer id can be used to uniquely identify a transfer output.
--
-- We'll be inserting an actual value in the next query, so we just start
-- with -1.
ALTER TABLE asset_transfer_outputs
ADD COLUMN position INTEGER NOT NULL DEFAULT -1;

-- Update the position to be the same as the output id for existing entries.
-- We'll use the position integer as a uniquely identifiable number of an output
-- within a transfer, so setting the default to the output_id is just to make
-- sure we have a unique value that also satisfies the unique constraint we add
-- below.
UPDATE asset_transfer_outputs SET position = CAST(output_id AS INTEGER)
WHERE position = -1;

-- We enforce a unique constraint such that for a given transfer, the position
-- of an output is unique.
CREATE UNIQUE INDEX asset_transfer_outputs_transfer_id_position_unique
ON asset_transfer_outputs (
    transfer_id, position
);
