-- The key_type column is used to store the type of key that is stored in the
-- script_keys table. The type is a Golang numeric type that will have values
-- such as BIP-0086, script path with custom (externally defined) script, script
-- path with Taproot Asset Channel related script, etc. The NULL value
-- will mean the type is not known. Existing script keys will be inspected by
-- the post-migration step Golang code that determines the type of each script
-- key.
ALTER TABLE script_keys ADD COLUMN key_type SMALLINT;
