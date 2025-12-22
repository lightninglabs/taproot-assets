-- name: InsertRfqPolicy :one
INSERT INTO rfq_policies (
    policy_type,
    scid,
    rfq_id,
    peer,
    asset_id,
    asset_group_key,
    rate_coefficient,
    rate_scale,
    expiry,
    max_out_asset_amt,
    payment_max_msat,
    request_asset_max_amt,
    request_payment_max_msat,
    price_oracle_metadata,
    request_version,
    agreed_at
)
VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9,
    $10, $11, $12, $13, $14, $15, $16
)
RETURNING id;

-- name: FetchActiveRfqPolicies :many
SELECT
    id,
    policy_type,
    scid,
    rfq_id,
    peer,
    asset_id,
    asset_group_key,
    rate_coefficient,
    rate_scale,
    expiry,
    max_out_asset_amt,
    payment_max_msat,
    request_asset_max_amt,
    request_payment_max_msat,
    price_oracle_metadata,
    request_version,
    agreed_at
FROM rfq_policies
WHERE expiry >= sqlc.arg('min_expiry');

-- name: InsertRfqForward :one
INSERT INTO rfq_forwards (
    settled_at,
    rfq_id,
    chan_id_in,
    chan_id_out,
    htlc_id,
    asset_amt
)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING id;

-- name: QueryRfqForwards :many
SELECT
    f.id,
    f.settled_at,
    f.rfq_id,
    f.chan_id_in,
    f.chan_id_out,
    f.htlc_id,
    f.asset_amt,
    p.policy_type,
    p.peer,
    p.asset_id,
    p.asset_group_key,
    p.rate_coefficient,
    p.rate_scale
FROM rfq_forwards f
JOIN rfq_policies p ON f.rfq_id = p.rfq_id
WHERE f.settled_at >= @settled_after
    AND f.settled_at <= @settled_before
    AND (p.peer = sqlc.narg('peer') OR sqlc.narg('peer') IS NULL)
    AND (p.asset_id = sqlc.narg('asset_id') OR
         sqlc.narg('asset_id') IS NULL)
    AND (p.asset_group_key = sqlc.narg('asset_group_key') OR
         sqlc.narg('asset_group_key') IS NULL)
ORDER BY f.settled_at DESC
LIMIT @num_limit OFFSET @num_offset;

-- name: CountRfqForwards :one
SELECT COUNT(*) as total
FROM rfq_forwards f
JOIN rfq_policies p ON f.rfq_id = p.rfq_id
WHERE f.settled_at >= @settled_after
    AND f.settled_at <= @settled_before
    AND (p.peer = sqlc.narg('peer') OR sqlc.narg('peer') IS NULL)
    AND (p.asset_id = sqlc.narg('asset_id') OR
         sqlc.narg('asset_id') IS NULL)
    AND (p.asset_group_key = sqlc.narg('asset_group_key') OR
         sqlc.narg('asset_group_key') IS NULL);
