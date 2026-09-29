-- A proof file is a DAG: anchor transactions can occur in its linear history
-- and recursively in additional-input proof files. This reverse index makes a
-- transaction re-confirmation find every stored proof file that contains it.
CREATE TABLE asset_proof_anchors (
    proof_id BIGINT NOT NULL REFERENCES asset_proofs(proof_id)
        ON DELETE CASCADE,
    anchor_txid BLOB NOT NULL CHECK(length(anchor_txid) = 32),

    PRIMARY KEY (proof_id, anchor_txid)
);

CREATE INDEX asset_proof_anchors_txid_idx
    ON asset_proof_anchors(anchor_txid);

-- Raw proof upserts clear this bit. Only the indexed proof writer sets it
-- after replacing the reverse-index rows, making bypasses discoverable and
-- giving startup adoption a durable, resumable work queue.
ALTER TABLE asset_proofs
    ADD COLUMN provenance_indexed BOOLEAN NOT NULL DEFAULT FALSE;
