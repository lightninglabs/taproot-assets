-- name: UpsertAuxCloseInfo :exec
INSERT INTO aux_channel_close_info (chan_point, info_blob)
VALUES ($1, $2)
ON CONFLICT(chan_point) DO UPDATE SET
    info_blob = excluded.info_blob;

-- name: FetchAuxCloseInfo :one
SELECT info_blob
FROM aux_channel_close_info
WHERE chan_point = $1;

-- name: DeleteAuxCloseInfo :exec
DELETE FROM aux_channel_close_info
WHERE chan_point = $1;
