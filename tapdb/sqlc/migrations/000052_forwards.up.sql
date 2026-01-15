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

CREATE INDEX IF NOT EXISTS forwards_opened_at_idx ON forwards(opened_at);
CREATE INDEX IF NOT EXISTS forwards_settled_at_idx ON forwards(settled_at);
CREATE INDEX IF NOT EXISTS forwards_rfq_id_idx ON forwards(rfq_id);
