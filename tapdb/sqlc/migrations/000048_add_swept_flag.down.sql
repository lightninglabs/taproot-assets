-- Remove swept transaction reference from managed_utxos table.
ALTER TABLE managed_utxos DROP COLUMN swept_txn_id;
