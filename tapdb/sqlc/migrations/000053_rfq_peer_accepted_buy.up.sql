-- Recreate rfq_policies with an expanded CHECK constraint that also allows
-- peer-accepted buy quotes ('RFQ_POLICY_TYPE_PEER_ACCEPTED_BUY').
-- SQLite does not support ALTER CONSTRAINT, so we recreate the table.
--
-- Because the forwards table has a foreign key reference to
-- rfq_policies(rfq_id), and SQLite rewrites FK references on table rename,
-- we must also drop and recreate the forwards table to avoid a dangling FK.

-- 1. Save existing forwards data and drop the table.
CREATE TEMP TABLE IF NOT EXISTS forwards_backup AS SELECT * FROM forwards;
DROP TABLE IF EXISTS forwards;

-- 2. Rename the old rfq_policies table and create the new one with the
--    expanded CHECK constraint.
ALTER TABLE rfq_policies RENAME TO rfq_policies_old;

CREATE TABLE IF NOT EXISTS rfq_policies (
    id INTEGER PRIMARY KEY,

    -- policy_type denotes the type of the policy.
    policy_type TEXT NOT NULL CHECK (
        policy_type IN (
            'RFQ_POLICY_TYPE_SALE',
            'RFQ_POLICY_TYPE_PURCHASE',
            'RFQ_POLICY_TYPE_PEER_ACCEPTED_BUY'
        )
    ),

    -- scid is the short channel ID associated with the policy.
    scid BIGINT NOT NULL,

    -- rfq_id is the unique identifier for the RFQ session.
    rfq_id BLOB NOT NULL CHECK (length(rfq_id) = 32),

    -- peer is the public key of the peer node.
    peer BLOB NOT NULL CHECK (length(peer) = 33),

    -- asset_id is the optional asset ID.
    asset_id BLOB CHECK (length(asset_id) = 32),

    -- asset_group_key is the optional asset group key.
    asset_group_key BLOB CHECK (length(asset_group_key) = 33),

    -- rate_coefficient is the coefficient of the exchange rate.
    rate_coefficient BLOB NOT NULL,

    -- rate_scale is the scale of the exchange rate.
    rate_scale INTEGER NOT NULL,

    -- expiry is the expiration timestamp of the policy.
    expiry BIGINT NOT NULL,

    -- max_out_asset_amt is the maximum asset amount for sale policies.
    max_out_asset_amt BIGINT,

    -- payment_max_msat is the maximum payment amount for purchase policies.
    payment_max_msat BIGINT,

    -- request_asset_max_amt is the requested maximum asset amount.
    request_asset_max_amt BIGINT,

    -- request_payment_max_msat is the requested maximum payment amount.
    request_payment_max_msat BIGINT,

    -- price_oracle_metadata contains metadata about the price oracle.
    price_oracle_metadata TEXT,

    -- request_version is the version of the RFQ request.
    request_version INTEGER,

    -- agreed_at is the timestamp when the policy was agreed upon.
    agreed_at BIGINT NOT NULL
);

INSERT INTO rfq_policies SELECT * FROM rfq_policies_old;
DROP TABLE rfq_policies_old;

CREATE UNIQUE INDEX IF NOT EXISTS rfq_policies_rfq_id_idx ON rfq_policies (rfq_id);
CREATE INDEX IF NOT EXISTS rfq_policies_scid_idx ON rfq_policies (scid);

-- 3. Recreate the forwards table with the FK pointing to the new
--    rfq_policies table, restore data and indexes.
CREATE TABLE IF NOT EXISTS forwards (
    id INTEGER PRIMARY KEY,

    -- opened_at is the timestamp when the forward was initiated.
    opened_at TIMESTAMP NOT NULL,

    -- settled_at is the timestamp when the forward settled.
    settled_at TIMESTAMP,

    -- failed_at is the timestamp when the forward failed.
    failed_at TIMESTAMP,

    -- rfq_id is the foreign key to the RFQ policy.
    rfq_id BLOB NOT NULL CHECK (length(rfq_id) = 32)
        REFERENCES rfq_policies(rfq_id),

    -- chan_id_in is the short channel ID of the incoming channel.
    chan_id_in BIGINT NOT NULL,

    -- chan_id_out is the short channel ID of the outgoing channel.
    chan_id_out BIGINT NOT NULL,

    -- htlc_id is the HTLC ID on the incoming channel.
    htlc_id BIGINT NOT NULL,

    -- asset_amt is the asset amount involved in this swap.
    asset_amt BIGINT NOT NULL,

    -- amt_in_msat is the actual amount received on the incoming channel in
    -- millisatoshis.
    amt_in_msat BIGINT NOT NULL,

    -- amt_out_msat is the actual amount sent on the outgoing channel in
    -- millisatoshis.
    amt_out_msat BIGINT NOT NULL,

    UNIQUE(chan_id_in, htlc_id)
);

INSERT INTO forwards SELECT * FROM forwards_backup;
DROP TABLE forwards_backup;

CREATE INDEX IF NOT EXISTS forwards_opened_at_idx ON forwards(opened_at);
CREATE INDEX IF NOT EXISTS forwards_settled_at_idx ON forwards(settled_at);
CREATE INDEX IF NOT EXISTS forwards_rfq_id_idx ON forwards(rfq_id);
