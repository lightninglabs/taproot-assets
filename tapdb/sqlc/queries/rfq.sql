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
