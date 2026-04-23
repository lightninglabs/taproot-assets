-- Drop the accepted_max_amount column from rfq_policies.
-- SQLite < 3.35 does not support DROP COLUMN, so we use the
-- table-recreation pattern.  The forwards table has a FK to
-- rfq_policies(rfq_id), so it must be handled as well.

-- 1. Save forwards data and drop the table.
CREATE TEMP TABLE IF NOT EXISTS forwards_backup
    AS SELECT * FROM forwards;
DROP TABLE IF EXISTS forwards;

-- 2. Rename old rfq_policies and recreate without the column.
ALTER TABLE rfq_policies RENAME TO rfq_policies_old;

CREATE TABLE IF NOT EXISTS rfq_policies (
    id INTEGER PRIMARY KEY,

    policy_type TEXT NOT NULL CHECK (
        policy_type IN (
            'RFQ_POLICY_TYPE_SALE',
            'RFQ_POLICY_TYPE_PURCHASE',
            'RFQ_POLICY_TYPE_PEER_ACCEPTED_BUY'
        )
    ),

    scid BIGINT NOT NULL,
    rfq_id BLOB NOT NULL CHECK (length(rfq_id) = 32),
    peer BLOB NOT NULL CHECK (length(peer) = 33),
    asset_id BLOB CHECK (length(asset_id) = 32),
    asset_group_key BLOB CHECK (length(asset_group_key) = 33),
    rate_coefficient BLOB NOT NULL,
    rate_scale INTEGER NOT NULL,
    expiry BIGINT NOT NULL,
    max_out_asset_amt BIGINT,
    payment_max_msat BIGINT,
    request_asset_max_amt BIGINT,
    request_payment_max_msat BIGINT,
    price_oracle_metadata TEXT,
    request_version INTEGER,
    agreed_at BIGINT NOT NULL
);

INSERT INTO rfq_policies (
    id,
    policy_type, scid, rfq_id, peer, asset_id, asset_group_key,
    rate_coefficient, rate_scale, expiry, max_out_asset_amt,
    payment_max_msat, request_asset_max_amt,
    request_payment_max_msat, price_oracle_metadata,
    request_version, agreed_at
) SELECT
    id,
    policy_type, scid, rfq_id, peer, asset_id, asset_group_key,
    rate_coefficient, rate_scale, expiry, max_out_asset_amt,
    payment_max_msat, request_asset_max_amt,
    request_payment_max_msat, price_oracle_metadata,
    request_version, agreed_at
FROM rfq_policies_old;
DROP TABLE rfq_policies_old;

CREATE UNIQUE INDEX IF NOT EXISTS rfq_policies_rfq_id_idx
    ON rfq_policies (rfq_id);
CREATE INDEX IF NOT EXISTS rfq_policies_scid_idx
    ON rfq_policies (scid);

-- 3. Recreate forwards table and restore data.
CREATE TABLE IF NOT EXISTS forwards (
    id INTEGER PRIMARY KEY,
    opened_at TIMESTAMP NOT NULL,
    settled_at TIMESTAMP,
    failed_at TIMESTAMP,
    rfq_id BLOB NOT NULL CHECK (length(rfq_id) = 32)
        REFERENCES rfq_policies(rfq_id),
    chan_id_in BIGINT NOT NULL,
    chan_id_out BIGINT NOT NULL,
    htlc_id BIGINT NOT NULL,
    asset_amt BIGINT NOT NULL,
    amt_in_msat BIGINT NOT NULL,
    amt_out_msat BIGINT NOT NULL,
    UNIQUE(chan_id_in, htlc_id)
);

INSERT INTO forwards (
    id,
    opened_at, settled_at, failed_at, rfq_id, chan_id_in,
    chan_id_out, htlc_id, asset_amt, amt_in_msat, amt_out_msat
) SELECT
    id,
    opened_at, settled_at, failed_at, rfq_id, chan_id_in,
    chan_id_out, htlc_id, asset_amt, amt_in_msat, amt_out_msat
FROM forwards_backup;
DROP TABLE forwards_backup;

CREATE INDEX IF NOT EXISTS forwards_opened_at_idx
    ON forwards(opened_at);
CREATE INDEX IF NOT EXISTS forwards_settled_at_idx
    ON forwards(settled_at);
CREATE INDEX IF NOT EXISTS forwards_rfq_id_idx
    ON forwards(rfq_id);
