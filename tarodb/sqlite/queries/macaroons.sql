-- name: GetRootKey :one
SELECT * FROM macaroons 
WHERE id = ? LIMIT 1;

-- name: InsertRootKey :exec
INSERT INTO macaroons (id, root_key) VALUES (?, ?);
