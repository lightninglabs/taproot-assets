CREATE TABLE IF NOT EXISTS rfq_policies (
    id INTEGER PRIMARY KEY,
    policy_type TEXT NOT NULL CHECK (
        policy_type IN ('asset_sale', 'asset_purchase')
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
    agreed_at BIGINT NOT NULL,
    UNIQUE(rfq_id)
);
