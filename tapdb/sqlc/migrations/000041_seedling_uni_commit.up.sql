-- Add universe commitments flag column to asset_seedlings table.
ALTER TABLE asset_seedlings
ADD COLUMN universe_commitments BOOLEAN NOT NULL DEFAULT FALSE;