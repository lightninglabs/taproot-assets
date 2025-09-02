-- Make batch_id nullable in mint_anchor_uni_commitments table and rename to
-- supply_pre_commits. Since SQLite doesn't support ALTER COLUMN, we need
-- to recreate the table.

-- Create a new table with the desired structure (batch_id nullable).
CREATE TABLE supply_pre_commits (
    id INTEGER PRIMARY KEY,

    -- The ID of the minting batch this universe commitment relates to.
    -- Now nullable to allow universe commitments without a specific batch.
    batch_id INTEGER REFERENCES asset_minting_batches(batch_id),

    -- The index of the mint batch anchor transaction pre-commitment output.
    tx_output_index INTEGER NOT NULL,

    -- The Taproot output internal key for the pre-commitment output.
    group_key BLOB,

    -- The taproot internal key ID reference.
    taproot_internal_key_id BIGINT REFERENCES internal_keys(key_id) NOT NULL,

    -- Reference to supply commitments.
    spent_by BIGINT REFERENCES supply_commitments(commit_id),

    -- The outpoint for this commitment.
    outpoint BLOB NOT NULL CHECK(length(outpoint) > 0)
);

-- Copy all existing data from the old table to the new table.
INSERT INTO supply_pre_commits (
    id, batch_id, tx_output_index, group_key, taproot_internal_key_id, spent_by,
    outpoint
)
SELECT
    id, batch_id, tx_output_index, group_key, taproot_internal_key_id, spent_by,
    outpoint
FROM mint_anchor_uni_commitments;

-- Drop the old index before dropping the table.
DROP INDEX IF EXISTS mint_anchor_uni_commitments_outpoint_idx;

-- Drop the old table.
DROP TABLE mint_anchor_uni_commitments;

-- Create a unique index on outpoint.
CREATE UNIQUE INDEX supply_pre_commits_unique_outpoint
    ON supply_pre_commits(outpoint);
