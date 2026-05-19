-- Reset BIGSERIAL sequences that were left behind by migrations
-- that inserted rows with explicit id values.
--
-- Migration 31 copied universe_leaves rows with explicit ids.
-- Migration 40 inserted supply_commit_states (0-6) and
-- supply_commit_update_types (0-2) with explicit ids.
--
-- On SQLite these are no-ops (replaced via sqliteSchemaReplacements).
SELECT setval(pg_get_serial_sequence('universe_leaves', 'id'), COALESCE((SELECT MAX(id) FROM universe_leaves), 1), (SELECT COUNT(*) FROM universe_leaves) > 0);
SELECT setval(pg_get_serial_sequence('supply_commit_states', 'id'), COALESCE((SELECT MAX(id) FROM supply_commit_states), 1), (SELECT COUNT(*) FROM supply_commit_states) > 0);
SELECT setval(pg_get_serial_sequence('supply_commit_update_types', 'id'), COALESCE((SELECT MAX(id) FROM supply_commit_update_types), 1), (SELECT COUNT(*) FROM supply_commit_update_types) > 0);
