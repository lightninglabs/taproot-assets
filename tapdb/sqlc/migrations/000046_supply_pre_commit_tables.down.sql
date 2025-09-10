-- Undo table rename.
ALTER TABLE mint_supply_pre_commits
    RENAME TO mint_anchor_uni_commitments;

-- Drop the new supply_pre_commits table.
DROP INDEX IF EXISTS supply_pre_commits_idx_group_key;
DROP INDEX IF EXISTS supply_pre_commits_unique_outpoint;
DROP TABLE IF EXISTS supply_pre_commits;