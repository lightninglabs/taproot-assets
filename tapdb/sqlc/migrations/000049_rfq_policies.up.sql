CREATE TABLE IF NOT EXISTS rfq_policies (
    id INTEGER PRIMARY KEY,

    -- policy_type denotes the type of the policy (buy or sell).
    -- It can be either 'RFQ_POLICY_TYPE_SALE' or 'RFQ_POLICY_TYPE_PURCHASE'.
    policy_type TEXT NOT NULL CHECK (
        policy_type IN ('RFQ_POLICY_TYPE_SALE', 'RFQ_POLICY_TYPE_PURCHASE')
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

CREATE UNIQUE INDEX IF NOT EXISTS rfq_policies_rfq_id_idx ON rfq_policies (rfq_id);
