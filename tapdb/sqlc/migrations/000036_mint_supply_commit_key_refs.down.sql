-- Remove delegation_key_id column from asset_seedlings table
ALTER TABLE asset_seedlings
DROP COLUMN delegation_key_id;

-- Restore taproot_internal_key column and remove taproot_internal_key_id
-- from mint_anchor_uni_commitments table
ALTER TABLE mint_anchor_uni_commitments
DROP COLUMN taproot_internal_key_id;

ALTER TABLE mint_anchor_uni_commitments
ADD COLUMN taproot_internal_key BLOB;
