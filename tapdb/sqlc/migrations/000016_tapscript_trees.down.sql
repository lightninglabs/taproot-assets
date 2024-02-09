DROP INDEX IF EXISTS tapscript_edges_unique;
DROP TABLE IF EXISTS tapscript_edges;
DROP TABLE IF EXISTS tapscript_nodes;
DROP TABLE IF EXISTS tapscript_roots;
ALTER TABLE asset_minting_batches DROP COLUMN tapscript_sibling;