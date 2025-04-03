-- The declared_known flag was just a workaround. Now that we have an actual
-- type, we don't need this flag anymore.
ALTER TABLE script_keys DROP COLUMN declared_known;
