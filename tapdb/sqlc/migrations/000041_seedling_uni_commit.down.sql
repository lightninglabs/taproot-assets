-- Remove universe commitments flag column from seedling table.
ALTER TABLE asset_seedlings
DROP COLUMN IF EXISTS universe_commitments;