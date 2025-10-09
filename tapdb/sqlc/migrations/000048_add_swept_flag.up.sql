-- Add swept flag to managed_utxos table to track when UTXOs have been swept
ALTER TABLE managed_utxos ADD COLUMN swept BOOLEAN NOT NULL DEFAULT FALSE;
