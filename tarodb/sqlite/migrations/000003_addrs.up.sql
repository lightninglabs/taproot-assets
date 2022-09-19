-- addrs stores all the created addresses of the daemon. All addresses contain
-- a creation time and all the information needed to reconstruct the taproot
-- output on chain we'll use to send/recv to/from this address.
CREATE TABLE IF NOT EXISTS addrs (
    id INTEGER PRIMARY KEY,

    -- version is the Taro script version this address support.
    version SMALLINT NOT NULL,

    -- asset_id is the asset ID of the asset we want to send/recv.
    asset_id BLOB NOT NULL,

    -- fam_key is the raw blob of the family key. For assets w/o a family key,
    -- this field will be NULL.
    fam_key BLOB,

    -- script_key_id points to the internal key that we created to serve as the
    -- script key to be able to receive this asset.
    script_key_id INTEGER NOT NULL REFERENCES script_keys(script_key_id),

    -- taproot_key_id points to the internal key that we'll use to serve as the
    -- taproot internal key to receive this asset.
    taproot_key_id INTEGER NOT NULL REFERENCES internal_keys(key_id),

    -- amount is the amount of asset we want to receive.
    amount BIGINT NOT NULL,  

    -- asset_type is the type of asset we want to receive. 
    asset_type SMALLINT NOT NULL,

    -- creation_time is the creation time of this asset.
    creation_time TIMESTAMP NOT NULL
);

-- We'll create some indexes over the asset ID, family key, and also creation
-- time to speed up common queries.
CREATE INDEX IF NOT EXISTS addr_asset_ids ON addrs (asset_id);
CREATE INDEX IF NOT EXISTS addr_fam_keys ON addrs (fam_key);
CREATE INDEX IF NOT EXISTS addr_timestamp ON addrs (creation_time);
