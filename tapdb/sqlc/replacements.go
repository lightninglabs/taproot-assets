package sqlc

// SQLiteSchemaReplacements maps Postgres-specific SQL fragments to
// SQLite-compatible no-ops. Used by both the runtime migration
// layer (tapdb/sqlite.go) and the schema merge tool
// (cmd/merge-sql-schemas).
var SQLiteSchemaReplacements = map[string]string{
	"SELECT setval(pg_get_serial_sequence(" +
		"'universe_leaves', 'id'), COALESCE((" +
		"SELECT MAX(id) FROM universe_leaves" +
		"), 1), (SELECT COUNT(*) FROM " +
		"universe_leaves) > 0);": "SELECT 1;",
	"SELECT setval(pg_get_serial_sequence(" +
		"'supply_commit_states', 'id'), " +
		"COALESCE((SELECT MAX(id) FROM " +
		"supply_commit_states), 1), (SELECT " +
		"COUNT(*) FROM supply_commit_states" +
		") > 0);": "SELECT 1;",
	"SELECT setval(pg_get_serial_sequence(" +
		"'supply_commit_update_types', 'id'), " +
		"COALESCE((SELECT MAX(id) FROM " +
		"supply_commit_update_types), 1), " +
		"(SELECT COUNT(*) FROM " +
		"supply_commit_update_types) > 0);": "SELECT 1;",
}
