CREATE TABLE IF NOT EXISTS rfq_forwards (
    id INTEGER PRIMARY KEY,

    -- settled_at is the unix timestamp when the forward settled.
    settled_at BIGINT NOT NULL,

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

    UNIQUE(chan_id_in, htlc_id)
);

CREATE INDEX IF NOT EXISTS rfq_forwards_settled_at_idx ON rfq_forwards(settled_at);
CREATE INDEX IF NOT EXISTS rfq_forwards_rfq_id_idx ON rfq_forwards(rfq_id);
