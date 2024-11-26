CREATE TABLE IF NOT EXISTS asset_burn_transfers (
    -- The auto-incrementing integer that identifies this burn transfer.
    burn_id INTEGER PRIMARY KEY, 

    -- A reference to the primary key of the transfer that includes this burn.
    transfer_id INTEGER NOT NULL REFERENCES asset_transfers(id),
     
    -- A note that may contain user defined metadata.
    note TEXT,

    -- The asset id of the burnt asset.
    asset_id BLOB NOT NULL REFERENCES genesis_assets(asset_id),

    -- The group key of the group the burnt asset belonged to.
    group_key BLOB REFERENCES asset_groups(tweaked_group_key),

    -- The amount of the asset that was burned.
    amount BIGINT NOT NULL
)