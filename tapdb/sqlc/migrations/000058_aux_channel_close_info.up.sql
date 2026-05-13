-- aux_channel_close_info holds the per-channel state that
-- tapchannel.AuxChanCloser needs to finalize a cooperative close after a
-- restart. Without this table, the in-memory state stashed by
-- AuxCloseOutputs is lost across a tapd restart between close broadcast
-- and on-chain confirmation, causing FinalizeClose to fail.
CREATE TABLE IF NOT EXISTS aux_channel_close_info (
    -- chan_point is the funding outpoint of the channel, serialized as
    -- 32 bytes of txid followed by 4 bytes of big-endian output index.
    chan_point BLOB PRIMARY KEY CHECK (length(chan_point) = 36),

    -- info_blob is an opaque encoding of the persistedCloseInfo struct
    -- defined in the tapchannel package. The encoding/decoding lives
    -- with the consumer so that internal field changes don't require a
    -- new migration here.
    info_blob BLOB NOT NULL
);
