-- Most impactful for query_asset_stats which currently has highest latency
-- Supports the common join pattern and filters on proof_type.
CREATE INDEX IF NOT EXISTS idx_universe_leaves_asset 
ON universe_leaves(asset_genesis_id, universe_root_id);

-- Helps with the join conditions we frequently see
-- This is especially useful for query_universe_leaves and improves join efficiency.
CREATE INDEX IF NOT EXISTS idx_mssmt_nodes_composite 
ON mssmt_nodes(namespace, key, hash_key, sum);

-- Optimizes the common namespace_root lookups along with proof_type filtering
-- This helps with fetch_universe_root and roots-related queries.
CREATE INDEX IF NOT EXISTS idx_universe_roots_composite
ON universe_roots(namespace_root, proof_type, asset_id);