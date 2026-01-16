-- Record which chain transaction swept a managed UTXO.
ALTER TABLE managed_utxos
    ADD COLUMN swept_txn_id BIGINT REFERENCES chain_txns(txn_id);
