-- name: GetRootKey :one
SELECT * FROM macaroons 
WHERE id = $1 LIMIT 1;

-- name: InsertRootKey :exec
INSERT INTO macaroons (id, root_key) VALUES ($1, $2);
