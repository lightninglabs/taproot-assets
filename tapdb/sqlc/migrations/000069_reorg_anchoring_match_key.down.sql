DROP INDEX IF EXISTS reorg_anchorings_site_match_key_uk;

ALTER TABLE reorg_anchorings
    DROP COLUMN match_key;
