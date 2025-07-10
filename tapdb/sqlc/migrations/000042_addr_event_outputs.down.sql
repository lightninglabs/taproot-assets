DROP INDEX IF EXISTS addrs_script_key_version_2_uk;
DROP INDEX IF EXISTS addr_event_outputs_addr_event_id_asset_id_uk;
DROP INDEX IF EXISTS addr_event_outputs_addr_event_id_idx;
DROP INDEX IF EXISTS addr_event_proofs_addr_event_id_asset_proof_id_uk;
DROP INDEX IF EXISTS addr_event_proofs_addr_event_id_idx;

DROP TABLE IF EXISTS addr_event_proofs;
DROP TABLE IF EXISTS addr_event_outputs;

-- We don't allow downgrades, so we don't need a reverse migration for
-- the dropped column asset_proof_id in addr_events. We just add the column
-- back, so the schema is valid again (in case we ever need to downgrade in a
-- unit test or something).

ALTER TABLE addr_events
    ADD COLUMN asset_proof_id BIGINT REFERENCES asset_proofs(proof_id);
ALTER TABLE addr_events
    ADD COLUMN asset_id BIGINT REFERENCES assets(asset_id);

ALTER TABLE asset_transfer_outputs
    DROP COLUMN tap_address;
