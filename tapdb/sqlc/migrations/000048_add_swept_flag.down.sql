-- Remove swept flag from managed_utxos table
ALTER TABLE managed_utxos DROP COLUMN swept;
