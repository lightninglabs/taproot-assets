-- We add a set of new minting/universe related columns. Those will all be
-- added to the meta record as odd (optional) TLV fields. Therefore, they will
-- not be set on older assets, which is why we need to make them nullable here.
ALTER TABLE assets_meta ADD COLUMN meta_decimal_display INTEGER;
ALTER TABLE assets_meta ADD COLUMN meta_canonical_universe VARCHAR;
