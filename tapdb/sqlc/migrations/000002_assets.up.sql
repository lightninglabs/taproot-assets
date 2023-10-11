-- chain_txns stores any transactions relevant to tapd. This includes
-- transaction that mint, transfer and receive assets. Full transaction
-- information, along with indexing information is stored.
-- TODO(roasbeef): also store SPV proof?
CREATE TABLE IF NOT EXISTS chain_txns (
    txn_id BIGINT PRIMARY KEY,

    txid BLOB UNIQUE NOT NULL,

    chain_fees BIGINT NOT NULL,

    raw_tx BLOB NOT NULL,

    block_height INTEGER,

    block_hash BLOB,

    tx_index INTEGER
);

-- genesis_points stores all genesis_points relevant to tapd, which is the
-- first outpoint of the transaction that mints assets. This table stores the
-- outpoint itself, and also a references to the transaction that _spends_ that
-- outpoint.
CREATE TABLE IF NOT EXISTS genesis_points (
    genesis_id BIGINT PRIMARY KEY,

    -- TODO(roasbeef): just need the input index here instead?
    prev_out BLOB UNIQUE NOT NULL,

    anchor_tx_id BIGINT REFERENCES chain_txns(txn_id)
);

-- assets_meta is a table that holds all the metadata information for genesis
-- assets that we either created, or bootstrapped from the relevant Base
-- Universe.
CREATE TABLE IF NOT EXISTS assets_meta (
    meta_id BIGINT PRIMARY KEY,

    meta_data_hash BLOB UNIQUE CHECK(length(meta_data_hash) = 32),

    -- TODO(roasbeef): also have other opque blob here for future fields?
    meta_data_blob BLOB,

    meta_data_type SMALLINT
);

-- genesis_assets stores the base information for a given asset. This includes
-- all the information needed to derive the assetID for an asset. This table
-- reference the genesis point which is also a necessary component for
-- computing an asset ID.
CREATE TABLE IF NOT EXISTS genesis_assets (
    gen_asset_id BIGINT PRIMARY KEY,

    asset_id BLOB UNIQUE,

    asset_tag TEXT NOT NULL,

    meta_data_id BIGINT REFERENCES assets_meta(meta_id),

    output_index INTEGER NOT NULL,

    -- TODO(roasbeef): make into an enum? also add into asset_id generation?
    -- BIP PR
    asset_type SMALLINT NOT NULL,

    genesis_point_id BIGINT NOT NULL REFERENCES genesis_points(genesis_id)
);
CREATE INDEX IF NOT EXISTS asset_ids on genesis_assets(asset_id);

-- internal_keys is the set of public keys managed and used by the daemon. The
-- full KeyLocator is stored so we can use these keys without actually storing
-- the private keys on disk.
CREATE TABLE IF NOT EXISTS internal_keys (
    key_id BIGINT PRIMARY KEY,

    -- We'll always store the full 33-byte key on disk, to make sure we're
    -- retaining full information.
    raw_key BLOB NOT NULL UNIQUE CHECK(length(raw_key) = 33),

    key_family INTEGER NOT NULL,

    key_index INTEGER NOT NULL
);

-- asset_groups stores information related to the asset group key for a
-- given asset. This includes the raw tweaked_group_key, which is the result of
-- tweaking the base group key by the associated genesis point. This table
-- references the set of internal keys, and also the genesis_points table.
CREATE TABLE IF NOT EXISTS asset_groups (
    group_id BIGINT PRIMARY KEY,

    tweaked_group_key BLOB UNIQUE NOT NULL CHECK(length(tweaked_group_key) = 33), 

    tapscript_root BLOB,

    -- TODO(roasbeef): also need to mix in output index here? to derive the
    -- genesis key?
    internal_key_id BIGINT NOT NULL REFERENCES internal_keys(key_id),

    genesis_point_id BIGINT NOT NULL REFERENCES genesis_points(genesis_id)
);

-- asset_group_witnesses stores the set of signatures/witness stacks for an
-- asset group key. Each time a group key is used (creation of an initial asset,
-- and then all on going asset) a signature/witness that signs the corresponding
-- asset ID must also be included. This table reference the asset ID it's used
-- to create as well as the group key that signed the asset in the first place.
CREATE TABLE IF NOT EXISTS asset_group_witnesses (
    witness_id BIGINT PRIMARY KEY,

    -- The witness stack can contain either a single Schnorr signature for key
    -- spends of the tweaked group key, or a more complex script witness.
    witness_stack BLOB NOT NULL,

    -- TODO(roasbeef): not needed since already in assets row?
    gen_asset_id BIGINT NOT NULL REFERENCES genesis_assets(gen_asset_id) UNIQUE,

    group_key_id BIGINT NOT NULL REFERENCES asset_groups(group_id)
);

-- managed_utxos is the set of UTXOs managed by tapd. These UTXOs may commit
-- to several assets. These UTXOs are also always imported into the backing
-- wallet, so the wallet is able to keep track of the amount of sats that are
-- used to anchor Taproot assets.
CREATE TABLE IF NOT EXISTS managed_utxos (
    utxo_id BIGINT PRIMARY KEY,

    outpoint BLOB UNIQUE NOT NULL,

    -- TODO(roasbeef): need to make these INT instead then interpolate due to
    -- 64 bit issues?
    amt_sats BIGINT NOT NULL,

    internal_key_id BIGINT NOT NULL REFERENCES internal_keys(key_id),

    -- The Taproot Asset root commitment hash.
    taproot_asset_root BLOB NOT NULL CHECK(length(taproot_asset_root) = 32),

    -- The serialized tapscript sibling preimage. If this is empty then the
    -- Taproot Asset root commitment is equal to the merkle_root below.
    tapscript_sibling BLOB,

    -- The Taproot merkle root hash. If there is no tapscript sibling then this
    -- corresponds to the Taproot Asset root commitment hash.
    --
    -- TODO(roasbeef): can then reconstruct on start up to ensure matches up
    merkle_root BLOB NOT NULL CHECK(length(merkle_root) = 32),

    txn_id BIGINT NOT NULL REFERENCES chain_txns(txn_id),

    -- The identity of the application that currently has a lease on this UTXO.
    -- If NULL, then the UTXO is not currently leased. A lease means that the
    -- UTXO is being reserved/locked to be spent in an upcoming transaction and
    -- that it should not be available for coin selection through any of the
    -- wallet RPCs.
    lease_owner BLOB CHECK(length(lease_owner) = 32),

    -- The absolute expiry of the lease in seconds as a Unix timestamp. If the
    -- expiry is NULL or the timestamp is in the past, then the lease is not
    -- valid and the UTXO is available for coin selection.
    lease_expiry TIMESTAMP
);

CREATE TABLE IF NOT EXISTS script_keys (
    script_key_id BIGINT PRIMARY KEY,

    -- The actual internal key here that we hold the private key for. Applying
    -- the tweak to this gives us the tweaked_script_key.
    internal_key_id BIGINT NOT NULL REFERENCES internal_keys(key_id),

    -- The script key after applying the tweak. This is what goes directly in
    -- the asset TLV.
    tweaked_script_key BLOB NOT NULL UNIQUE CHECK(length(tweaked_script_key) = 33),

    -- An optional tweak for the script_key. If NULL, the raw_key may be
    -- tweaked BIP-0086 style.
    tweak BLOB
);

-- assets is the main table that stores (or references) the complete asset
-- information. This represents the latest state of any given asset, as it also
-- references the managed_utxos table which stores the current location of the
-- asset, along with the sibling taproot hash needed to properly reveal and
-- spend the asset.
CREATE TABLE IF NOT EXISTS assets (
    asset_id BIGINT PRIMARY KEY,
    
    genesis_id BIGINT NOT NULL REFERENCES genesis_assets(gen_asset_id),

    version INTEGER NOT NULL,

    script_key_id BIGINT NOT NULL REFERENCES script_keys(script_key_id),

    -- TODO(roasbeef): don't need this after all?
    asset_group_witness_id BIGINT REFERENCES asset_group_witnesses(witness_id),

    -- TODO(roasbeef): make into enum?
    script_version INTEGER NOT NULL,

    -- TODO(roasbeef): add constraints?
    amount BIGINT NOT NULL,

    lock_time INTEGER,

    relative_lock_time INTEGER,

    -- TODO(roasbeef): move into new table, then 1:1 in the new table
    split_commitment_root_hash BLOB,

    split_commitment_root_value BIGINT,

    anchor_utxo_id BIGINT REFERENCES managed_utxos(utxo_id),
    
    -- A boolean that indicates that the asset was spent. This is only
    -- set for assets that were transferred in an active manner (as part of an
    -- user initiated transfer). Passive assets that are just re-anchored are
    -- updated in-place.
    spent BOOLEAN NOT NULL DEFAULT FALSE,
    
    UNIQUE(asset_id, genesis_id, script_key_id)
);

-- asset_witnesses stores the set of input witnesses for the latest state of an
-- asset. This then references the script key of an asset, creation a one to
-- many relationship.
CREATE TABLE IF NOT EXISTS asset_witnesses (
    witness_id BIGINT PRIMARY KEY,

    asset_id BIGINT NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,

    prev_out_point BLOB NOT NULL,

    prev_asset_id BLOB NOT NULL,

    prev_script_key BLOB NOT NULL,

    -- The witness stack can be NULL for genesis assets where (for now) they
    -- have no witnesses, but we use this to be able to detect them as such.
    witness_stack BLOB,

    split_commitment_proof BLOB
);

CREATE TABLE IF NOT EXISTS asset_proofs (
    proof_id BIGINT PRIMARY KEY,

    -- We enforce that this value is unique so we can use an UPSERT to update a
    -- proof file that already exists.
    asset_id BIGINT NOT NULL REFERENCES assets(asset_id) UNIQUE,

    -- TODO(roasbef): store the merkle root separately? then can refer back to
    -- for all other files

    proof_file BLOB NOT NULL
);

-- asset_minting_batches stores the set of all batches used to create several
-- assets in a single transaction. The batch also includes the PSBT of the
-- minting transaction which once signed and broadcast will actually create the
-- assets.
CREATE TABLE IF NOT EXISTS asset_minting_batches (
    batch_id BIGINT PRIMARY KEY REFERENCES internal_keys(key_id),

    -- TODO(roasbeef): make into proper enum table or use check to ensure
    -- proper values
    batch_state SMALLINT NOT NULL,

    minting_tx_psbt BLOB,

    change_output_index INTEGER,

    genesis_id BIGINT REFERENCES genesis_points(genesis_id),

    height_hint INTEGER NOT NULL,

    creation_time_unix TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS batch_state_lookup on asset_minting_batches (batch_state);

-- asset_seedlings are budding assets: the contain the base asset information
-- need to create an asset, but doesn't yet have a genesis point.
CREATE TABLE IF NOT EXISTS asset_seedlings (
    seedling_id BIGINT PRIMARY KEY,

    -- TODO(roasbeef): data redundant w/ genesis_assets?
    -- move into asset details table?
    asset_name TEXT NOT NULL,

    asset_version SMALLINT NOT NULL,

    asset_type SMALLINT NOT NULL,

    asset_supply BIGINT NOT NULL,

    asset_meta_id BIGINT NOT NULL REFERENCES assets_meta(meta_id),

    emission_enabled BOOLEAN NOT NULL,

    batch_id BIGINT NOT NULL REFERENCES asset_minting_batches(batch_id),

    group_genesis_id BIGINT REFERENCES genesis_assets(gen_asset_id),

    group_anchor_id BIGINT REFERENCES asset_seedlings(seedling_id)
);

-- TODO(roasbeef): need on delete cascade for all these?

-- This view is used to fetch the base asset information from disk based on
-- the raw key of the batch that will ultimately create this set of assets.
-- To do so, we'll need to traverse a few tables to join the set of assets
-- with the genesis points, then with the batches that reference this
-- points, to the internal key that reference the batch, then restricted
-- for internal keys that match our main batch key.
CREATE VIEW genesis_info_view AS
    SELECT
        gen_asset_id, asset_id, asset_tag, assets_meta.meta_data_hash meta_hash,
        output_index, asset_type, genesis_points.prev_out prev_out, block_height
    FROM genesis_assets
    -- We do a LEFT JOIN here, as not every asset has a set of
    -- metadata that matches the asset.
    LEFT JOIN assets_meta
        ON genesis_assets.meta_data_id = assets_meta.meta_id
    JOIN genesis_points
        ON genesis_assets.genesis_point_id = genesis_points.genesis_id
    LEFT JOIN chain_txns
        ON genesis_points.anchor_tx_id = chain_txns.txn_id;

-- This view is used to perform a series of joins that allow us to extract
-- the group key information, as well as the group sigs for the series of
-- assets we care about. We obtain only the assets found in the batch
-- above, with the WHERE query at the bottom.
CREATE VIEW key_group_info_view AS
    SELECT
        witness_id, gen_asset_id, witness_stack, tapscript_root,
        tweaked_group_key, raw_key, key_index, key_family,
        substr(tweaked_group_key, 2) AS x_only_group_key
    FROM asset_group_witnesses wit
    JOIN asset_groups groups
        ON wit.group_key_id = groups.group_id
    JOIN internal_keys keys
        ON keys.key_id = groups.internal_key_id
    WHERE wit.gen_asset_id IN (SELECT gen_asset_id FROM genesis_info_view);
