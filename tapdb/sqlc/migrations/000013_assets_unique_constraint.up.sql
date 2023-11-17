-- We will apply a new unique constraint on the assets table. This constraint
-- will be on the columns (anchor_utxo_id, genesis_id, script_key_id).
-- Rows in the existing table may violate this constraint, so we need to delete
-- all but one row in each violating set of rows before applying the constraint.
WITH duplicate_rows AS (
    SELECT
        asset_id,
        anchor_utxo_id,
        genesis_id,
        script_key_id,

        -- This is the row number of the row within the set of rows that violate
        -- the constraint. We will delete all rows with a row number greater
        -- than 1.
        ROW_NUMBER() OVER (PARTITION BY anchor_utxo_id, genesis_id, script_key_id ORDER BY asset_id) AS row_num
    FROM assets
)
DELETE FROM assets
WHERE (anchor_utxo_id, genesis_id, script_key_id) IN (
    SELECT anchor_utxo_id, genesis_id, script_key_id
    FROM duplicate_rows
    -- Delete all rows with a row number greater than 1. This should leave
    -- exactly one row (row number 0) for each set of rows that violate the
    -- constraint.
    WHERE row_num > 1
);

-- Create a unique index on the new table
CREATE UNIQUE INDEX assets_uniqueness_index_anchor_utxo_id_genesis_id_script_key_id
ON assets (anchor_utxo_id, genesis_id, script_key_id);

