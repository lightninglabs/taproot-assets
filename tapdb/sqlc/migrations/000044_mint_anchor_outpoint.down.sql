-- Remove the outpoint column and its index
DROP INDEX IF EXISTS mint_anchor_uni_commitments_outpoint_idx;
ALTER TABLE mint_anchor_uni_commitments DROP COLUMN outpoint;