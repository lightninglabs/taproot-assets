CREATE TABLE IF NOT EXISTS tx_proof_claimed_outpoints (
    -- The p2tr outpoint that is being claimed, must be unique so we declare it
    -- as the primary key.
    outpoint BLOB PRIMARY KEY,

    -- The block hash of the block that contains the transaction that has the
    -- outpoint being claimed.
    block_hash BLOB NOT NULL,
    
    -- The block height of the block that contains the transaction that has the
    -- outpoint being claimed.
    block_height INTEGER NOT NULL,
    
    -- The internal key of the p2tr outpoint that is being claimed. 
    internal_key BLOB NOT NULL CHECK (length(internal_key) = 33),
    
    -- The optional merkle root of the p2tr outpoint that is being claimed.
    merkle_root BLOB
);

CREATE TABLE IF NOT EXISTS authmailbox_messages (
    -- The primary key of the message, which is an auto-incrementing integer.
    id INTEGER PRIMARY KEY,
    
    -- The claimed outpoint that this message is associated with. This must
    -- reference an existing outpoint in the tx_proof_claimed_outpoints table
    -- and must be unique, ensuring that each message is only associated with a
    -- single claimed outpoint.
    claimed_outpoint BLOB NOT NULL REFERENCES
    tx_proof_claimed_outpoints(outpoint) ON DELETE CASCADE,
    
    -- The receiver key is the receiver's public key against which the payload
    -- is encrypted.
    receiver_key BLOB NOT NULL CHECK (length(receiver_key) = 33),
    
    -- The encrypted payload of the message, which contains the sender's
    -- ephemeral public key as part of the additional data (along with the nonce
    -- used for the ECIES-HKDF-SHA256-XCHA20POLY1305 encryption).
    encrypted_payload BLOB NOT NULL,
    
    -- The timestamp when the message was created on the server. This is a unix
    -- timestamp in seconds to allow for easy querying and sorting of messages
    -- based on their arrival time, without time zone complications.
    arrival_timestamp BIGINT NOT NULL,
    
    -- The optional expiry block height for the message, which indicates
    -- when the message should be considered expired and can be deleted.
    expiry_block_height INTEGER
);

-- Each message must have a unique claimed outpoint, which serves as a spam
-- mitigation mechanism.
CREATE UNIQUE INDEX IF NOT EXISTS authmailbox_messages_claimed_outpoint_idx
ON authmailbox_messages (claimed_outpoint);
