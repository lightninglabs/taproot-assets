CREATE UNIQUE INDEX assets_genesis_id_script_key_id_anchor_utxo_id_unique
ON assets (
    genesis_id, script_key_id, anchor_utxo_id
);
