CREATE TABLE IF NOT EXISTS forwarding_events (
    id BIGINT PRIMARY KEY,
    
    timestamp TIMESTAMP NOT NULL,
    
    incoming_htlc_id BIGINT NOT NULL,
    
    outgoing_htlc_id BIGINT NOT NULL,
    
    asset_id BLOB NOT NULL,
    
    amount_in_msat BIGINT NOT NULL,
    
    amount_out_msat BIGINT NOT NULL,
    
    -- Coefficient of the exchange rate (stored as bytes for arbitrary precision).
    rate_coefficient BLOB NOT NULL,
    
    -- Scale of the rate (decimal places).
    rate_scale INTEGER NOT NULL,
    
    fee_msat BIGINT NOT NULL,
    
    incoming_channel_id BIGINT NOT NULL,
    
    outgoing_channel_id BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS forwarding_events_timestamp_idx 
    ON forwarding_events(timestamp);
CREATE INDEX IF NOT EXISTS forwarding_events_asset_id_idx 
    ON forwarding_events(asset_id);

