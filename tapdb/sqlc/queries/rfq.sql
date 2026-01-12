-- name: InsertRfqPolicy :one
INSERT INTO rfq_policies (
    policy_type, scid, rfq_id, peer, asset_id, asset_group_key,
    rate_coefficient, rate_scale, expiry, max_out_asset_amt, payment_max_msat,
    request_asset_max_amt, request_payment_max_msat, price_oracle_metadata,
    request_version, agreed_at
)
VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9,
    $10, $11, $12, $13, $14, $15, $16
)
RETURNING id;

-- name: FetchActiveRfqPolicies :many
SELECT
    id, policy_type, scid, rfq_id, peer, asset_id, asset_group_key,
    rate_coefficient, rate_scale, expiry, max_out_asset_amt, payment_max_msat,
    request_asset_max_amt, request_payment_max_msat, price_oracle_metadata,
    request_version, agreed_at
FROM rfq_policies
WHERE expiry >= sqlc.arg('min_expiry');

-- name: UpsertForward :one
INSERT INTO forwards (
    opened_at, settled_at, failed_at, rfq_id, chan_id_in, chan_id_out,
    htlc_id, asset_amt, amt_in_msat, amt_out_msat
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT(chan_id_in, htlc_id) DO UPDATE SET
    opened_at = excluded.opened_at,
    settled_at = COALESCE(excluded.settled_at, forwards.settled_at),
    failed_at = COALESCE(excluded.failed_at, forwards.failed_at),
    rfq_id = excluded.rfq_id,
    chan_id_out = excluded.chan_id_out,
    asset_amt = excluded.asset_amt,
    amt_in_msat = excluded.amt_in_msat,
    amt_out_msat = excluded.amt_out_msat
RETURNING id;

-- name: QueryPendingForwards :many
SELECT
    f.opened_at, f.rfq_id, f.chan_id_in, f.chan_id_out, f.htlc_id,
    f.asset_amt, f.amt_in_msat, f.amt_out_msat
FROM forwards f
WHERE f.settled_at IS NULL AND f.failed_at IS NULL
ORDER BY f.opened_at DESC;

-- name: QueryForwards :many
SELECT
    f.id, f.opened_at, f.settled_at, f.failed_at, f.rfq_id,
    f.chan_id_in, f.chan_id_out, f.htlc_id, f.asset_amt, f.amt_in_msat,
    f.amt_out_msat, p.policy_type, p.peer, p.asset_id, p.asset_group_key,
    p.rate_coefficient, p.rate_scale
FROM forwards f
JOIN rfq_policies p ON f.rfq_id = p.rfq_id
WHERE f.opened_at >= @opened_after AND f.opened_at <= @opened_before
    AND (p.peer = sqlc.narg('peer') OR sqlc.narg('peer') IS NULL)
    AND (p.asset_id = sqlc.narg('asset_id') OR
         sqlc.narg('asset_id') IS NULL)
    AND (p.asset_group_key = sqlc.narg('asset_group_key') OR
         sqlc.narg('asset_group_key') IS NULL)
ORDER BY f.opened_at DESC
LIMIT @num_limit OFFSET @num_offset;

-- name: CountForwards :one
SELECT COUNT(*) as total
FROM forwards f
JOIN rfq_policies p ON f.rfq_id = p.rfq_id
WHERE f.opened_at >= @opened_after AND f.opened_at <= @opened_before
    AND (p.peer = sqlc.narg('peer') OR sqlc.narg('peer') IS NULL)
    AND (p.asset_id = sqlc.narg('asset_id') OR
         sqlc.narg('asset_id') IS NULL)
    AND (p.asset_group_key = sqlc.narg('asset_group_key') OR
         sqlc.narg('asset_group_key') IS NULL);
