-- Add outpoint field to mint_anchor_uni_commitments to track the exact UTXO
-- This allows precise marking of spent pre-commitments using the transaction inputs
ALTER TABLE mint_anchor_uni_commitments
    ADD COLUMN outpoint BLOB;

-- Create an index for efficient lookups by outpoint
CREATE INDEX mint_anchor_uni_commitments_outpoint_idx 
    ON mint_anchor_uni_commitments(outpoint)
    WHERE outpoint IS NOT NULL;