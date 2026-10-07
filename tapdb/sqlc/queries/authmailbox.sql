-- name: InsertTxProof :exec
INSERT INTO tx_proof_claimed_outpoints (
    outpoint, block_hash, block_height, internal_key, merkle_root
) VALUES (
    $1, $2, $3, $4, $5
);

-- name: InsertAuthMailboxMessage :one
INSERT INTO authmailbox_messages (
    claimed_outpoint, receiver_key, encrypted_payload, arrival_timestamp
) VALUES (
    $1, $2, $3, $4
)
RETURNING id;

-- name: FetchAuthMailboxMessage :one
SELECT 
    m.id,
    m.claimed_outpoint,
    m.receiver_key,
    m.encrypted_payload,
    m.arrival_timestamp,
    op.block_height
FROM authmailbox_messages m
JOIN tx_proof_claimed_outpoints op
    ON m.claimed_outpoint = op.outpoint
WHERE id = $1
    -- A message whose receiver deleted it keeps its row but has an empty
    -- payload, and is no longer in the mailbox.
    AND length(m.encrypted_payload) > 0;

-- name: FetchAuthMailboxMessageByOutpoint :one
-- Unlike the other message queries, this also returns a message that its
-- receiver has deleted, as the row records that the outpoint was used to send
-- it.
SELECT
    m.id,
    m.claimed_outpoint,
    m.receiver_key,
    m.encrypted_payload,
    m.arrival_timestamp,
    op.block_height
FROM authmailbox_messages m
JOIN tx_proof_claimed_outpoints op
    ON m.claimed_outpoint = op.outpoint
WHERE m.claimed_outpoint = $1;

-- name: QueryAuthMailboxMessages :many
SELECT
    m.id,
    m.claimed_outpoint,
    m.receiver_key,
    m.encrypted_payload,
    m.arrival_timestamp,
    op.block_height
FROM authmailbox_messages m
JOIN tx_proof_claimed_outpoints op
    ON m.claimed_outpoint = op.outpoint
WHERE
    m.receiver_key = $1
    AND length(m.encrypted_payload) > 0
    -- The after_time and after_id are exclusive, so we query greater than.
    AND (
        m.arrival_timestamp > sqlc.narg('after_time')
        OR sqlc.narg('after_time') IS NULL
    )
    AND (
        m.id > sqlc.narg('after_id')
        OR sqlc.narg('after_id') IS NULL
    )
    -- The start_block is inclusive, so we query greater than or equal.
    AND (
        op.block_height >= sqlc.narg('start_block')
        OR sqlc.narg('start_block') IS NULL
    );

-- name: CountAuthMailboxMessages :one
SELECT COUNT(*) AS count
FROM authmailbox_messages m
WHERE length(m.encrypted_payload) > 0;

-- name: ListClaimedOutpoints :many
SELECT outpoint, internal_key, merkle_root, block_height
FROM tx_proof_claimed_outpoints
ORDER BY block_height ASC
LIMIT @num_limit OFFSET @num_offset;

-- name: DeleteTxProofClaimedOutpoint :exec
DELETE FROM tx_proof_claimed_outpoints
WHERE outpoint = $1;

-- name: ClearAuthMailboxMessagePayload :execrows
-- Removes a message from its receiver's mailbox by emptying its payload. The
-- row itself stays until its claimed outpoint is deleted, so that a resend of
-- the same message is still recognized as one. substr yields an empty value of
-- the column's own type on both database backends.
UPDATE authmailbox_messages
SET encrypted_payload = substr(encrypted_payload, 1, 0)
WHERE id = @message_id AND receiver_key = @receiver_key
    AND length(encrypted_payload) > 0;
