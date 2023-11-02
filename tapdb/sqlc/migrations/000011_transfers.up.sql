DROP TABLE IF EXISTS receiver_proof_transfer_attempts;

-- proof_transfer_log is a table that stores the proof receive/delivery transfer
-- attempts log. The transfers recorded in this log may not have succeeded.
CREATE TABLE IF NOT EXISTS proof_transfer_log (
    -- The type of proof transfer attempt. The transfer is either a proof
    -- delivery to the transfer counterparty or receiving a proof from the
    -- transfer counterparty. Note that the transfer counterparty is usually
    -- the proof courier service.
    transfer_type TEXT NOT NULL CHECK(transfer_type IN ('send', 'receive')),

    proof_locator_hash BLOB NOT NULL,

    time_unix TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS proof_locator_hash_index
ON proof_transfer_log (proof_locator_hash);