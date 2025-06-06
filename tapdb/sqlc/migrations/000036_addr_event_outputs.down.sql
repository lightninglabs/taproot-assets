DROP INDEX IF EXISTS addrs_script_key_version_2_uk;
DROP TABLE IF EXISTS addr_event_proofs;
DROP TABLE IF EXISTS addr_event_outputs;

-- We don't allow downgrades, so we don't need a reverse migration for
-- the dropped column asset_proof_id in addr_events.
