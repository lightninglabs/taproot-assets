-- We add a set of new minting/universe related columns. Those will all be
-- added to the meta record as odd (optional) TLV fields. Therefore, they will
-- not be set on older assets, which is why we need to make them nullable here.
ALTER TABLE assets_meta ADD COLUMN meta_decimal_display INTEGER;

ALTER TABLE assets_meta ADD COLUMN meta_universe_commitments BOOL;

-- If there's more than one URL, we're going to join them using the 0x00 control
-- character (which is invalid in a URL itself).
ALTER TABLE assets_meta ADD COLUMN meta_canonical_universes BLOB;

ALTER TABLE assets_meta ADD COLUMN meta_delegation_key BLOB;
