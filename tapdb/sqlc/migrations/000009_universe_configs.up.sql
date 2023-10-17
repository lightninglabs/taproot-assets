DROP TABLE IF EXISTS federation_uni_sync_config;

-- This table contains universe (asset/asset group) specific federation sync
-- configuration.
CREATE TABLE IF NOT EXISTS federation_uni_sync_config (
    -- namespace is the string representation of the universe identifier, and
    -- ensures that there are no duplicate configs.
    namespace VARCHAR NOT NULL PRIMARY KEY,

    -- This field contains the byte serialized ID of the asset to which this
    -- configuration is applicable.
    asset_id BLOB CHECK(length(asset_id) = 32) NULL,

    -- This field contains the byte serialized compressed group key public key
    -- of the asset group to which this configuration is applicable.
    group_key BLOB CHECK(LENGTH(group_key) = 33) NULL,

    -- This field is an enum representing the proof type stored in the given
    -- universe.
    proof_type TEXT NOT NULL CHECK(proof_type IN ('issuance', 'transfer')),

    -- This field is a boolean that indicates whether or not the given universe
    -- should accept remote proof insertion via federation sync.
    allow_sync_insert BOOLEAN NOT NULL,

    -- This field is a boolean that indicates whether or not the given universe
    -- should accept remote proof export via federation sync.
    allow_sync_export BOOLEAN NOT NULL,

    -- Both the asset ID and group key cannot be null at the same time.
    CHECK (
        (asset_id IS NOT NULL AND group_key IS NULL) OR
        (asset_id IS NULL AND group_key IS NOT NULL)
    )
);