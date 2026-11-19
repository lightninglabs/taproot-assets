ALTER TABLE asset_proofs
    DROP COLUMN provenance_indexed;

DROP INDEX IF EXISTS asset_proof_anchors_txid_idx;
DROP TABLE IF EXISTS asset_proof_anchors;
