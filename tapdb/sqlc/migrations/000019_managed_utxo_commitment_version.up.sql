-- Add a field to store the version of the Taproot Asset commitment anchored in
-- this UTXO. Existing UTXOs will have this set to NULL.
ALTER TABLE managed_utxos ADD COLUMN root_version SMALLINT;