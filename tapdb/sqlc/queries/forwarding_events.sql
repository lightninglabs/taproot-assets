-- name: InsertForwardingEvent :exec
INSERT INTO forwarding_events (
    timestamp,
    incoming_htlc_id,
    outgoing_htlc_id,
    asset_id,
    amount_in_msat,
    amount_out_msat,
    rate_coefficient,
    rate_scale,
    fee_msat,
    incoming_channel_id,
    outgoing_channel_id
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
);

-- name: QueryForwardingEvents :many
SELECT
    id,
    timestamp,
    incoming_htlc_id,
    outgoing_htlc_id,
    asset_id,
    amount_in_msat,
    amount_out_msat,
    rate_coefficient,
    rate_scale,
    fee_msat,
    incoming_channel_id,
    outgoing_channel_id
FROM forwarding_events
WHERE
    (sqlc.narg('start_time')::TIMESTAMP IS NULL OR timestamp >= sqlc.narg('start_time'))
    AND
    (sqlc.narg('end_time')::TIMESTAMP IS NULL OR timestamp <= sqlc.narg('end_time'))
    AND
    (sqlc.narg('asset_id')::BLOB IS NULL OR asset_id = sqlc.narg('asset_id'))
ORDER BY
    CASE WHEN sqlc.narg('sort_direction') = 0 THEN timestamp END ASC,
    CASE WHEN sqlc.narg('sort_direction') = 1 THEN timestamp END DESC
LIMIT sqlc.arg('num_limit')
OFFSET sqlc.arg('num_offset');

