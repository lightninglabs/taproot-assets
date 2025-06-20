-- We need to modify the transfer ID to be a BIGINT instead of INTEGER,
-- otherwise at some point things will break unexpectedly.

CREATE TABLE IF NOT EXISTS asset_burn_transfers_corrected (
    -- The auto-incrementing integer that identifies this burn transfer.
    burn_id INTEGER PRIMARY KEY,

    -- A reference to the primary key of the transfer that includes this burn.
    transfer_id BIGINT NOT NULL REFERENCES asset_transfers (id),

    -- A note that may contain user defined metadata.
    note TEXT,

    -- The asset id of the burnt asset.
    asset_id BLOB NOT NULL REFERENCES genesis_assets (asset_id),

    -- The group key of the group the burnt asset belonged to.
    group_key BLOB REFERENCES asset_groups (tweaked_group_key),

    -- The amount of the asset that was burned.
    amount BIGINT NOT NULL
);

INSERT INTO asset_burn_transfers_corrected (
    burn_id, transfer_id, note, asset_id, group_key, amount
)
SELECT
    burn_id,
    transfer_id,
    note,
    asset_id,
    group_key,
    amount
FROM asset_burn_transfers;

DROP TABLE asset_burn_transfers;

ALTER TABLE asset_burn_transfers_corrected RENAME TO asset_burn_transfers;
