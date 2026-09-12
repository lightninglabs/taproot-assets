-- Add a match_key column to reorg_anchorings and a unique partial
-- index on (site_id, match_key). Sites use this as their per-site
-- identity key at registration: the porter uses the anchor txid, the
-- receive site uses the anchor txid, the mint uses the genesis
-- txid, and the supply-commit uses the commit txid.
--
-- The pattern replaces a linear scan through AllAnchorings(site) +
-- payload decode: sites now look up their existing anchoring via
-- LookupByMatchKey in O(1). Match keys are opaque bytes; the null
-- key represents "no match key set" (legacy rows created before
-- this migration) and is excluded from the uniqueness constraint so
-- those rows do not conflict with each other.

ALTER TABLE reorg_anchorings
    ADD COLUMN match_key BLOB;

CREATE UNIQUE INDEX reorg_anchorings_site_match_key_uk
    ON reorg_anchorings(site_id, match_key)
    WHERE match_key IS NOT NULL;
