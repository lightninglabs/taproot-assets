-- name: AssetsDBSizePostgres :one
SELECT pg_catalog.pg_database_size(current_database()) AS size;

-- name: AssetsDBSizeSqlite :one
SELECT pc.page_count * ps.page_size AS size_in_bytes
FROM pragma_page_count() AS pc, pragma_page_size() AS ps;
