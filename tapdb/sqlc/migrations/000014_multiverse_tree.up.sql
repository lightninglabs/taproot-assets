CREATE TABLE IF NOT EXISTS multiverse_roots (
    id BIGINT PRIMARY KEY,

    -- For the namespace root, we set the foreign key constraint evaluation to
    -- be deferred until after the database transaction ends. Otherwise, if the
    -- root of the SMT is deleted temporarily before inserting a new root, then
    -- this constraint is violated as there's no longer a root that this
    -- universe tree can point to.
    namespace_root VARCHAR UNIQUE NOT NULL REFERENCES mssmt_roots(namespace) DEFERRABLE INITIALLY DEFERRED,

    -- This field is an enum representing the proof type stored in the given
    -- universe.
    proof_type TEXT NOT NULL CHECK(proof_type IN ('issuance', 'transfer'))
);

CREATE TABLE IF NOT EXISTS multiverse_leaves (
    id BIGINT PRIMARY KEY,

    multiverse_root_id BIGINT NOT NULL REFERENCES multiverse_roots(id),

    asset_id BLOB CHECK(length(asset_id) = 32),

    -- We use the 32 byte schnorr key here as this is what's used to derive the
    -- top-level Taproot Asset commitment key.
    group_key BLOB CHECK(LENGTH(group_key) = 32),
    
    leaf_node_key BLOB NOT NULL,

    leaf_node_namespace VARCHAR NOT NULL,

    -- Both the asset ID and group key cannot be null at the same time.
    CHECK (
        (asset_id IS NOT NULL AND group_key IS NULL) OR
        (asset_id IS NULL AND group_key IS NOT NULL)
    )
);

CREATE UNIQUE INDEX multiverse_leaves_unique ON multiverse_leaves (
    leaf_node_key, leaf_node_namespace
);

-- If there already is a multiverse root entry in the mssmt_roots for the
-- issuance or transfer multiverses, add them to the multiverse_roots table as
-- well. Both statements are no-ops if the root doesn't exist yet.
INSERT INTO multiverse_roots (namespace_root, proof_type)
SELECT 'multiverse-issuance', 'issuance'
WHERE EXISTS (
    SELECT 1 FROM mssmt_roots WHERE namespace = 'multiverse-issuance'
);

INSERT INTO multiverse_roots (namespace_root, proof_type)
SELECT 'multiverse-transfer', 'transfer'
WHERE EXISTS (
    SELECT 1 FROM mssmt_roots WHERE namespace = 'multiverse-transfer'
);

-- And now we create the multiverse_leaves entries for the multiverse roots.
-- This is a no-op if the multiverse root doesn't exist yet.
INSERT INTO multiverse_leaves (
    multiverse_root_id, asset_id, group_key, leaf_node_key, leaf_node_namespace
) SELECT
      (SELECT id from multiverse_roots mr where mr.namespace_root = 'multiverse-issuance'),
      CASE WHEN ur.group_key IS NULL THEN ur.asset_id ELSE NULL END,
      ur.group_key,
      -- UNHEX() only exists in SQLite and it doesn't take a second argument
      -- (the 'hex' part). But it also doesn't complain about it, so we can
      -- leave it in for the Postgres version which is replaced in-memory to
      -- DECODE() which needs the 'hex' argument.
      UNHEX(REPLACE(ur.namespace_root, 'issuance-', ''), 'hex'),
      ur.namespace_root
  FROM universe_roots ur
  WHERE ur.namespace_root LIKE 'issuance-%';

INSERT INTO multiverse_leaves (
    multiverse_root_id, asset_id, group_key, leaf_node_key, leaf_node_namespace
) SELECT
      (SELECT id from multiverse_roots mr where mr.namespace_root = 'multiverse-transfer'),
      CASE WHEN ur.group_key IS NULL THEN ur.asset_id ELSE NULL END,
      ur.group_key,
      -- UNHEX() only exists in SQLite and it doesn't take a second argument
      -- (the 'hex' part). But it also doesn't complain about it, so we can
      -- leave it in for the Postgres version which is replaced in-memory to
      -- DECODE() which needs the 'hex' argument.
      UNHEX(REPLACE(ur.namespace_root, 'transfer-', ''), 'hex'),
      ur.namespace_root
FROM universe_roots ur
WHERE ur.namespace_root LIKE 'transfer-%';
