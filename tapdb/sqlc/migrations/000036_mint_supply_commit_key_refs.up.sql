-- Add delegation_key_id column to asset_seedlings table as a foreign key
-- to internal_keys table
ALTER TABLE asset_seedlings
ADD COLUMN delegation_key_id
BIGINT REFERENCES internal_keys(key_id);

-- Replace taproot_internal_key column with taproot_internal_key_id 
-- as a foreign key to internal_keys table in mint_anchor_uni_commitments.
-- It is safe to drop taproot_internal_key column as supply commitment
-- pre-commitment feature was not functional.
ALTER TABLE mint_anchor_uni_commitments
DROP COLUMN taproot_internal_key;

ALTER TABLE mint_anchor_uni_commitments
ADD COLUMN taproot_internal_key_id
BIGINT REFERENCES internal_keys(key_id)
NOT NULL;