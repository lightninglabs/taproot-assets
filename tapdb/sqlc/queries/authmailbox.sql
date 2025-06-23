-- name: InsertTxProof :exec
INSERT INTO tx_proof_claimed_outpoints (
    outpoint, block_hash, block_height, internal_key, merkle_root
) VALUES (
    $1, $2, $3, $4, $5
);

-- name: ContainsTxProof :one
SELECT EXISTS (
    SELECT 1
    FROM tx_proof_claimed_outpoints
    WHERE outpoint = $1
);

-- name: InsertAuthMailboxMessage :one
INSERT INTO authmailbox_messages (
    claimed_outpoint, receiver_key, encrypted_payload, arrival_timestamp,
                                  expiry_block_height
) VALUES (
    $1, $2, $3, $4, $5
)
RETURNING id;

-- name: FetchAuthMailboxMessages :one
SELECT 
    m.id,
    m.claimed_outpoint,
    m.receiver_key,
    m.encrypted_payload,
    m.arrival_timestamp,
    m.expiry_block_height,
    op.block_height
FROM authmailbox_messages m
JOIN tx_proof_claimed_outpoints op
    ON m.claimed_outpoint = op.outpoint
WHERE id = $1;

-- name: QueryAuthMailboxMessages :many
SELECT
    m.id,
    m.claimed_outpoint,
    m.receiver_key,
    m.encrypted_payload,
    m.arrival_timestamp,
    m.expiry_block_height,
    op.block_height
FROM authmailbox_messages m
JOIN tx_proof_claimed_outpoints op
    ON m.claimed_outpoint = op.outpoint
WHERE
    m.receiver_key = $1
    -- The after_time and after_id are exclusive, so we query greater than.
    AND (
        sqlc.narg('after_time') IS NULL
        OR m.arrival_timestamp > sqlc.narg('after_time')
    )
    AND (
        sqlc.narg('after_id') IS NULL
        OR m.id > sqlc.narg('after_id')
    )
    -- The start_block is inclusive, so we query greater than or equal.
    AND (
        sqlc.narg('start_block') IS NULL
        OR op.block_height >= sqlc.narg('start_block')
    );

-- name: CountAuthMailboxMessages :one
SELECT COUNT(*) AS count
FROM authmailbox_messages m;
