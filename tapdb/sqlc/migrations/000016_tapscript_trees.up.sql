-- The tapscript sibling is an optional hash that represents the root hash of a
-- tapscript tree. On batch finalization, this hash is used with the Taproot
-- Asset commitment to create the Taproot output key of the genesis output.
ALTER TABLE asset_minting_batches ADD COLUMN tapscript_sibling BLOB;

-- This table stores root hashes for tapscript trees, and a flag to ensure that
-- the stored tree nodes are decoded correctly.
CREATE TABLE IF NOT EXISTS tapscript_roots (
        root_id BIGINT PRIMARY KEY,

        -- The root hash of a tapscript tree.
        root_hash BLOB NOT NULL UNIQUE CHECK(length(root_hash) = 32),

        -- A flag to record if a tapscript tree was stored as two tapHashes, or
        -- a set of tapLeafs.
        branch_only BOOLEAN NOT NULL DEFAULT FALSE
);

-- This table stores tapscript nodes, which are tapHashes or tapLeafs. A node
-- may be included in multiple tapscript trees.
CREATE TABLE IF NOT EXISTS tapscript_nodes (
        node_id BIGINT PRIMARY KEY,

        -- The serialized tapscript node, which may be a tapHash or tapLeaf.
        raw_node BLOB NOT NULL UNIQUE
);

-- This table stores tapscript edges, which link a serialized tapscript node
-- to a tapscript tree root hash and preserve the node ordering in the tree.
CREATE TABLE IF NOT EXISTS tapscript_edges (
        edge_id BIGINT PRIMARY KEY,

        -- The root hash of a tree that includes the referenced tapscript node.
        root_hash_id BIGINT NOT NULL REFERENCES tapscript_roots(root_id),

        -- The index of the referenced node in the tapscript tree, which is
        -- needed to correctly reconstruct the tapscript tree.
        node_index BIGINT NOT NULL,

        -- The tapscript node referenced by this edge.
        raw_node_id BIGINT NOT NULL REFERENCES tapscript_nodes(node_id)
);

-- A leaf can be repeated within a tree, and shared amongst trees, but there can
-- only be one leaf at a given index in a tree.
CREATE UNIQUE INDEX tapscript_edges_unique ON tapscript_edges (
        root_hash_id, node_index, raw_node_id
);
