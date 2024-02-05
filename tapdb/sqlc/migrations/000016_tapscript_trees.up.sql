CREATE TABLE IF NOT EXISTS tapscript_roots (
        root_id BIGINT PRIMARY KEY,

        root_hash BLOB NOT NULL UNIQUE CHECK(length(root_hash) = 32),

        branch_only BOOLEAN NOT NULL DEFAULT FALSE
);

-- A script leaf can be referenced from multiple trees.
CREATE TABLE IF NOT EXISTS tapscript_nodes (
        node_id BIGINT PRIMARY KEY,

        raw_node BLOB NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS tapscript_edges (
        edge_id BIGINT PRIMARY KEY,

        root_hash_id BIGINT NOT NULL REFERENCES tapscript_roots(root_id),

        node_index BIGINT NOT NULL,

        raw_node_id BIGINT NOT NULL REFERENCES tapscript_nodes(node_id)
);

-- A leaf can be repeated within a tree, and shared amongst trees, but there can
-- only be one leaf at a given index in a tree.
CREATE UNIQUE INDEX tapscript_edges_unique ON tapscript_edges (
        root_hash_id, node_index, raw_node_id
);
