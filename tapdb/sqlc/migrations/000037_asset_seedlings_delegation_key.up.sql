-- Add delegation_key column to asset_seedlings, referencing internal_keys.
ALTER TABLE asset_seedlings ADD COLUMN delegation_key BIGINT REFERENCES internal_keys(key_id); 