-- Each supply-commit minting batch contributes exactly one pre-commitment
-- output. The output index is derived binding data, not part of the logical
-- identity, so enforce cardinality by batch rather than relying only on the
-- historical (batch_id, tx_output_index) constraint.
CREATE UNIQUE INDEX mint_supply_pre_commits_unique_batch
    ON mint_supply_pre_commits (batch_id);
