-- Revert batch_id back to NOT NULL in supply_pre_commits table and
-- rename back to mint_anchor_uni_commitments. Since SQLite doesn't support
-- ALTER COLUMN, we need to recreate the table.

-- Create a new table with the original structure (batch_id NOT NULL).
CREATE TABLE mint_anchor_uni_commitments (
    id INTEGER PRIMARY KEY,

    -- The ID of the minting batch this universe commitment relates to.
    batch_id INTEGER NOT NULL REFERENCES asset_minting_batches(batch_id),

    -- The index of the mint batch anchor transaction pre-commitment output.
    tx_output_index INTEGER NOT NULL,

    -- The Taproot output internal key for the pre-commitment output.
    group_key BLOB,

    -- The taproot internal key ID reference.
    taproot_internal_key_id BIGINT REFERENCES internal_keys(key_id) NOT NULL,

    -- Reference to supply commitments.
    spent_by BIGINT REFERENCES supply_commitments(commit_id),

    -- The outpoint for this commitment.
    outpoint BLOB
);

-- Copy all existing data from the old table to the new table.
-- This will fail if there are any NULL batch_id values, which is expected
-- behavior for a down migration that removes nullable support.
INSERT INTO mint_anchor_uni_commitments (
    id, batch_id, tx_output_index, group_key, taproot_internal_key_id, spent_by,
    outpoint
)
SELECT
    id, batch_id, tx_output_index, group_key, taproot_internal_key_id, spent_by,
    outpoint
FROM supply_pre_commits
WHERE batch_id IS NOT NULL;

-- DROP old indexes before dropping the table.
DROP INDEX IF EXISTS supply_pre_commits_unique_outpoint;

-- Drop the old table.
DROP TABLE supply_pre_commits;

-- Recreate the indexes.
CREATE INDEX mint_anchor_uni_commitments_outpoint_idx
    ON mint_anchor_uni_commitments(outpoint)
    WHERE outpoint IS NOT NULL;
