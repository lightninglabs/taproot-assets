DROP INDEX IF EXISTS universe_supply_leaves_supply_root_id_type_idx;
DROP INDEX IF EXISTS universe_supply_leaves_supply_root_id_idx;
DROP INDEX IF EXISTS universe_supply_roots_group_key_idx;

DROP TABLE IF EXISTS universe_supply_leaves;
DROP TABLE IF EXISTS universe_supply_roots;

-- Note: We typically don't remove enum values ('burn', 'ignore') from
-- proof_types in a down migration to avoid breaking other potential uses.
