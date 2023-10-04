-- addrs stores all the created addresses of the daemon. All addresses contain
-- a creation time and all the information needed to reconstruct the taproot
-- output on chain we'll use to send/recv to/from this address.
CREATE TABLE IF NOT EXISTS addrs (
    id BIGINT PRIMARY KEY,

    -- version is the version of the Taproot Asset address format.
    version SMALLINT NOT NULL,

    -- asset_version is the asset version this address supports.
    asset_version SMALLINT NOT NULL,

    -- genesis_asset_id points to the asset genesis of the asset we want to
    -- send/recv.
    genesis_asset_id BIGINT NOT NULL REFERENCES genesis_assets(gen_asset_id),

    -- group_key is the raw blob of the group key. For assets w/o a group key,
    -- this field will be NULL.
    group_key BLOB,

    -- script_key_id points to the internal key that we created to serve as the
    -- script key to be able to receive this asset.
    script_key_id BIGINT NOT NULL REFERENCES script_keys(script_key_id),

    -- taproot_key_id points to the internal key that we'll use to serve as the
    -- taproot internal key to receive this asset.
    taproot_key_id BIGINT NOT NULL REFERENCES internal_keys(key_id),

    -- tapscript_sibling is the serialized tapscript sibling preimage that
    -- should be committed to in the taproot output alongside the Taproot Asset
    -- commitment. If no sibling is present, this field will be NULL.
    tapscript_sibling BLOB,

    -- taproot_output_key is the tweaked taproot output key that assets must
    -- be sent to on chain to be received, represented as a 32-byte x-only
    -- public key.
    taproot_output_key BLOB NOT NULL UNIQUE CHECK(length(taproot_output_key) = 32),

    -- amount is the amount of asset we want to receive.
    amount BIGINT NOT NULL,  

    -- asset_type is the type of asset we want to receive. 
    asset_type SMALLINT NOT NULL,

    -- creation_time is the creation time of this asset.
    creation_time TIMESTAMP NOT NULL,

    -- managed_from is the timestamp at which the address started to be managed
    -- by the internal wallet.
    managed_from TIMESTAMP,

    -- proof_courier_addr is the address of the proof courier that will be
    -- used in distributing proofs associated with a particular tap address.
    proof_courier_addr BLOB NOT NULL
);

-- We'll create some indexes over the asset ID, group key, and also creation
-- time to speed up common queries.
CREATE INDEX IF NOT EXISTS addr_asset_genesis_ids ON addrs (genesis_asset_id);
CREATE INDEX IF NOT EXISTS addr_group_keys ON addrs (group_key);
CREATE INDEX IF NOT EXISTS addr_creation_time ON addrs (creation_time);
CREATE INDEX IF NOT EXISTS addr_managed_from ON addrs (managed_from);
