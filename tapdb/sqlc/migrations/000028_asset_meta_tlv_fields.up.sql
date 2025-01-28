-- We add a set of new minting/universe related columns. Those will all be
-- added to the meta record as odd (optional) TLV fields. Therefore, they will
-- not be set on older assets, which is why we need to make them nullable here.
ALTER TABLE assets_meta ADD COLUMN meta_decimal_display INTEGER;

-- This boolean indicates if the asset is going to produce universe commitments.
ALTER TABLE assets_meta ADD COLUMN meta_universe_commitments BOOL;

-- If there's more than one URL, we're going to join them using the 0x00 control
-- character (which is invalid in a URL itself). The size restriction is based
-- on the number of allowed URLs (16) and the maximum size per URL (255). We
-- need to allow for the control character in between, so we just assume 256
-- characters per URL.
ALTER TABLE assets_meta ADD COLUMN meta_canonical_universes BLOB
    CHECK(LENGTH(meta_canonical_universes) <= 4096);

-- We don't want to decide on the SQL level if this key is a 33-byte compressed
-- or 32-byte x-only one, so we just use the <= operator in case we ever need
-- to change the semantics on this field (on the SQL level we just care about
-- there being a size restriction in the first place).
ALTER TABLE assets_meta ADD COLUMN meta_delegation_key BLOB
    CHECK(LENGTH(meta_delegation_key) <= 33);
