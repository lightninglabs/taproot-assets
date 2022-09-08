-- chain_txns stores any transactions relevant to tarod. This includes
-- transaction that mint, transfer and receive assets. Full transaction
-- information, along with indexing information is stored.
-- TODO(roasbeef): also store SPV proof?
CREATE TABLE IF NOT EXISTS chain_txns (
    txn_id INTEGER PRIMARY KEY,

    txid BLOB UNIQUE NOT NULL,

    raw_tx BLOB NOT NULL,

    block_height INTEGER,

    block_hash BLOB,

    tx_index INTEGER 
);

-- genesis_points stores all genesis_points relevant to tardo, which is the
-- first outpoint of the transaction that mints assets. This table stores the
-- outpoint itself, and also a references to the transaction that _spends_ that
-- outpoint.
CREATE TABLE IF NOT EXISTS genesis_points (
    genesis_id INTEGER PRIMARY KEY,

    -- TODO(roasbeef): just need the input index here instead?
    prev_out BLOB UNIQUE NOT NULL,

    anchor_tx_id INTEGER REFERENCES chain_txns(txn_id)
);

-- genesis_assets stores the base information for a given asset. This includes
-- all the information needed to derive the assetID for an asset. This table
-- reference the genesis point which is also a necessary component for
-- computing an asset ID.
CREATE TABLE IF NOT EXISTS genesis_assets (
    gen_asset_id INTEGER PRIMARY KEY,

    asset_id BLOB,

    asset_tag TEXT UNIQUE NOT NULL,

    meta_data BLOB,

    output_index INTEGER NOT NULL,

    -- TODO(roasbeef): make into an enum? also add into asset_id generation?
    -- BIP PR
    asset_type SMALLINT NOT NULL,

    genesis_point_id INTEGER NOT NULL REFERENCES genesis_points(genesis_id)
);
CREATE INDEX IF NOT EXISTS asset_ids on genesis_assets(asset_id);

-- internal_keys is the set of public keys managed and used by the daemon. The
-- full KeyLocator is stored so we can use these keys without actually storing
-- the private keys on disk.
CREATE TABLE IF NOT EXISTS internal_keys (
    key_id INTEGER PRIMARY KEY,

    -- We'll always store the full 33-byte key on disk, to make sure we're
    -- retaining full information.
    raw_key BLOB NOT NULL UNIQUE CHECK(length(raw_key) == 33),

    -- An optonal tweak for the raw_key. If NULL, the raw_key may be tweaked
    -- BIP0086 style.
    tweak BLOB,

    key_family INTEGER NOT NULL,

    key_index INTEGER NOT NULL
);

-- asset_families stores information related to the asset family key for a
-- given asset. This includes the raw tweaked_fam_key, which is the result of
-- tweaking the base family key by the associated genesis point. This table
-- references the set of internal keys, and also the genesis_points table.
CREATE TABLE IF NOT EXISTS asset_families (
    family_id INTEGER PRIMARY KEY,

    tweaked_fam_key BLOB UNIQUE NOT NULL, 

    -- TODO(roasbeef): also need to mix in output index here? to derive the
    -- genesis key?
    internal_key_id INTEGER NOT NULL REFERENCES internal_keys(key_id),

    genesis_point_id INTEGER NOT NULL REFERENCES genesis_points(genesis_id)
);

-- asset_family_sigs stores the set of signatures for an asset family key. Each
-- time a family key is used (creation of an initial asset, and then all on
-- going asset) a signature that signs the corresponding asset ID must also
-- be included. This table reference the asset ID it's used to create as well
-- as the family key that signed the asset in the first place.
CREATE TABLE IF NOT EXISTS asset_family_sigs (
    sig_id INTEGER PRIMARY KEY,

    genesis_sig BLOB NOT NULL, 

    -- TODO(roasbeef): not needed since already in assets row?
    gen_asset_id INTEGER NOT NULL REFERENCES genesis_assets(gen_asset_id),

    key_fam_id INTEGER NOT NULL REFERENCES asset_families(family_id)
);

-- managed_utxos is the set of UTXOs managed by tarod. These UTXOs may commit
-- to several assets. These UTXOs are also always imported into the backing
-- wallet, so the wallet is able to keep track of the amount of sats that are
-- used to anchor Taro assets.
CREATE TABLE IF NOT EXISTS managed_utxos (
    utxo_id INTEGER PRIMARY KEY,

    outpoint BLOB UNIQUE NOT NULL,

    -- TODO(roasbeef): need to make these INT instead then interpolate due to
    -- 64 bit issues?
    amt_sats BIGINT NOT NULL,

    internal_key_id INTEGER NOT NULL REFERENCES internal_keys(key_id),

    tapscript_sibling BLOB,

    -- TODO(roasbeef): can then reconstruct on start up to ensure matches up
    taro_root BLOB NOT NULL,

    txn_id INTEGER NOT NULL REFERENCES chain_txns(txn_id)
);

-- assets is the main table that stores (or references) the complete asset
-- information. This represents the latest state of any given asset, as it also
-- references the managed_utxos table which stores the current location of the
-- asset, along with the sibling taproot hash needed to properly reveal and
-- spend the asset.
CREATE TABLE IF NOT EXISTS assets (
    asset_id INTEGER PRIMARY KEY REFERENCES genesis_assets(gen_asset_id),

    version INTEGER NOT NULL,

    script_key_id INTEGER NOT NULL REFERENCES internal_keys(key_id),

    -- TODO(roasbeef): don't need this after all?
    asset_family_sig_id INTEGER REFERENCES asset_family_sigs(sig_id),

    -- TODO(roasbeef): make into enum?
    script_version INTEGER NOT NULL,

    -- TODO(roasbeef): add constraints?
    amount BIGINT NOT NULL,

    lock_time INTEGER,

    relative_lock_time INTEGER,

    -- TODO(roasbeef): new table?
    split_commitment_root_hash BLOB,

    split_commitment_root_value BIGINT,

    anchor_utxo_id INTEGER REFERENCES managed_utxos(utxo_id)
);

-- asset_witnesses stores the set of input witnesses for the latest state of an
-- asset. This then references the script key of an asset, creation a one to
-- many relationship.
CREATE TABLE IF NOT EXISTS asset_witnesses (
    witness_id INTEGER PRIMARY KEY,

    asset_id INTEGER NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,

    prev_out_point BLOB NOT NULL,

    prev_asset_id BLOB NOT NULL,

    prev_script_key BLOB NOT NULL,

    witness_stack BLOB NOT NULL,

    split_commitment_proof BLOB
);

CREATE TABLE IF NOT EXISTS asset_proofs (
    proof_id INTEGER PRIMARY KEY,

    -- We enforce that this value is unique so we can use an UPSERT to update a
    -- proof file that already exists.
    asset_id INTEGER NOT NULL REFERENCES assets(asset_id) UNIQUE,

    -- TODO(roasbef): store the merkle root separately? then can refer back to
    -- for all other files

    proof_file BLOB NOT NULL
);

-- asset_seedlings are budding assets: the contain the base asset information
-- need to create an asset, but don' tyet have a genesis point.
CREATE TABLE IF NOT EXISTS asset_seedlings (
    seedling_id INTEGER PRIMARY KEY,

    -- TODO(roasbeef): data redundant w/ genesis_assets?
    -- move into asset details table?
    asset_name TEXT NOT NULL,

    asset_type SMALLINT NOT NULL,

    asset_supply BIGINT NOT NULL,

    asset_meta BLOB,

    emission_enabled BOOLEAN NOT NULL,

    asset_id INTEGER REFERENCES genesis_assets(gen_asset_id),

    batch_id INTEGER NOT NULL REFERENCES asset_minting_batches(batch_id)
);

-- asset_minting_batches stores the set of all batches used to create several
-- assets in a single transaction. The batch also includes the PSBT of the
-- minting transaction which once signed and broadcast will actually create the
-- assets.
CREATE TABLE IF NOT EXISTS asset_minting_batches (
    batch_id INTEGER PRIMARY KEY REFERENCES internal_keys(key_id),

    -- TODO(roasbeef): make into proper enum table or use check to ensure
    -- proper values
    batch_state SMALLINT NOT NULL,

    minting_tx_psbt BLOB,

    -- TODO(roasbeef): redundant w/ info in genesis_assets table?
    minting_output_index SMALLINT,

    genesis_id INTEGER REFERENCES genesis_points(genesis_id),

    creation_time_unix TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS batch_state_lookup on asset_minting_batches (batch_state);

-- TODO(roasbeef): need on delete cascade for all these?
