CREATE INDEX addr_asset_genesis_ids ON addrs (genesis_asset_id);

CREATE INDEX addr_creation_time ON addrs (creation_time);

CREATE TABLE addr_events (
    id INTEGER PRIMARY KEY,

    -- creation_time is the creation time of this event.
    creation_time TIMESTAMP NOT NULL,

    -- addr_id is the reference to the address this event was emitted for.
    addr_id BIGINT NOT NULL REFERENCES addrs(id),

    -- status is the status of the inbound asset.
    status SMALLINT NOT NULL CHECK (status IN (0, 1, 2, 3)),

    -- chain_txn_id is a reference to the chain transaction that has the Taproot
    -- output for this event.
    chain_txn_id BIGINT NOT NULL REFERENCES chain_txns(txn_id),

    -- chain_txn_output_index is the index of the on-chain output (of the
    -- transaction referenced by chain_txn_id) that houses the Taproot Asset
    -- commitment.
    chain_txn_output_index INTEGER NOT NULL,

    -- managed_utxo_id is a reference to the managed UTXO the internal wallet
    -- tracks with on-chain funds that belong to us.
    managed_utxo_id BIGINT NOT NULL REFERENCES managed_utxos(utxo_id),

    -- asset_proof_id is a reference to the proof associated with this asset
    -- event.
    asset_proof_id BIGINT REFERENCES asset_proofs(proof_id),
    
    -- asset_id is a reference to the asset once we have taken custody of it.
    -- This will only be set once the proofs were imported successfully and the
    -- event is in the status complete.
    asset_id BIGINT REFERENCES assets(asset_id),
    
    UNIQUE(addr_id, chain_txn_id, chain_txn_output_index)
);

CREATE INDEX addr_group_keys ON addrs (group_key);

CREATE INDEX addr_managed_from ON addrs (managed_from);

CREATE TABLE addrs (
    id INTEGER PRIMARY KEY,

    -- version is the version of the Taproot Asset address format.
    version SMALLINT NOT NULL,

    -- asset_version is the asset version this address supports.
    asset_version SMALLINT NOT NULL,

    -- genesis_asset_id points to the asset genesis of the asset we want to
    -- send/recv.
    genesis_asset_id BIGINT NOT NULL REFERENCES genesis_assets(gen_asset_id),

    -- group_key is the raw blob of the group key. For assets w/o a group key,
    -- this field will be NULL.
    group_key BLOB,

    -- script_key_id points to the internal key that we created to serve as the
    -- script key to be able to receive this asset.
    script_key_id BIGINT NOT NULL REFERENCES script_keys(script_key_id),

    -- taproot_key_id points to the internal key that we'll use to serve as the
    -- taproot internal key to receive this asset.
    taproot_key_id BIGINT NOT NULL REFERENCES internal_keys(key_id),

    -- tapscript_sibling is the serialized tapscript sibling preimage that
    -- should be committed to in the taproot output alongside the Taproot Asset
    -- commitment. If no sibling is present, this field will be NULL.
    tapscript_sibling BLOB,

    -- taproot_output_key is the tweaked taproot output key that assets must
    -- be sent to on chain to be received, represented as a 32-byte x-only
    -- public key.
    taproot_output_key BLOB NOT NULL UNIQUE CHECK(length(taproot_output_key) = 32),

    -- amount is the amount of asset we want to receive.
    amount BIGINT NOT NULL,  

    -- asset_type is the type of asset we want to receive. 
    asset_type SMALLINT NOT NULL,

    -- creation_time is the creation time of this asset.
    creation_time TIMESTAMP NOT NULL,

    -- managed_from is the timestamp at which the address started to be managed
    -- by the internal wallet.
    managed_from TIMESTAMP,

    -- proof_courier_addr is the address of the proof courier that will be
    -- used in distributing proofs associated with a particular tap address.
    proof_courier_addr BLOB NOT NULL
);

CREATE TABLE asset_burn_transfers (
    -- The auto-incrementing integer that identifies this burn transfer.
    burn_id INTEGER PRIMARY KEY, 

    -- A reference to the primary key of the transfer that includes this burn.
    transfer_id INTEGER NOT NULL REFERENCES asset_transfers(id),
     
    -- A note that may contain user defined metadata.
    note TEXT,

    -- The asset id of the burnt asset.
    asset_id BLOB NOT NULL REFERENCES genesis_assets(asset_id),

    -- The group key of the group the burnt asset belonged to.
    group_key BLOB REFERENCES asset_groups(tweaked_group_key),

    -- The amount of the asset that was burned.
    amount BIGINT NOT NULL
);

CREATE TABLE asset_group_witnesses (
    witness_id INTEGER PRIMARY KEY,

    -- The witness stack can contain either a single Schnorr signature for key
    -- spends of the tweaked group key, or a more complex script witness.
    witness_stack BLOB NOT NULL,

    -- TODO(roasbeef): not needed since already in assets row?
    gen_asset_id BIGINT NOT NULL REFERENCES genesis_assets(gen_asset_id) UNIQUE,

    group_key_id BIGINT NOT NULL REFERENCES asset_groups(group_id)
);

CREATE TABLE asset_groups (
    group_id INTEGER PRIMARY KEY,

    tweaked_group_key BLOB UNIQUE NOT NULL CHECK(length(tweaked_group_key) = 33), 

    tapscript_root BLOB,

    -- TODO(roasbeef): also need to mix in output index here? to derive the
    -- genesis key?
    internal_key_id BIGINT NOT NULL REFERENCES internal_keys(key_id),

    genesis_point_id BIGINT NOT NULL REFERENCES genesis_points(genesis_id)
, version INTEGER NOT NULL DEFAULT 0, custom_subtree_root_id INTEGER
REFERENCES tapscript_roots(root_id));

CREATE INDEX asset_id_idx ON addr_events(asset_id);

CREATE INDEX asset_ids on genesis_assets(asset_id);

CREATE TABLE asset_minting_batches (
    batch_id INTEGER PRIMARY KEY REFERENCES internal_keys(key_id),

    -- TODO(roasbeef): make into proper enum table or use check to ensure
    -- proper values
    batch_state SMALLINT NOT NULL,

    minting_tx_psbt BLOB,

    change_output_index INTEGER,

    genesis_id BIGINT REFERENCES genesis_points(genesis_id),

    height_hint INTEGER NOT NULL,

    creation_time_unix TIMESTAMP NOT NULL
, tapscript_sibling BLOB, assets_output_index INTEGER, universe_commitments BOOLEAN NOT NULL DEFAULT FALSE);

CREATE INDEX asset_proof_id_idx ON addr_events(asset_proof_id);

CREATE TABLE asset_proofs (
    proof_id INTEGER PRIMARY KEY,

    -- We enforce that this value is unique so we can use an UPSERT to update a
    -- proof file that already exists.
    asset_id BIGINT NOT NULL REFERENCES assets(asset_id) UNIQUE,

    -- TODO(roasbef): store the merkle root separately? then can refer back to
    -- for all other files

    proof_file BLOB NOT NULL
);

CREATE TABLE asset_seedlings (
    seedling_id INTEGER PRIMARY KEY,

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
, script_key_id BIGINT REFERENCES script_keys(script_key_id), group_internal_key_id BIGINT REFERENCES internal_keys(key_id), group_tapscript_root BLOB);

CREATE TABLE asset_transfer_inputs (
    input_id INTEGER PRIMARY KEY,
    
    transfer_id BIGINT NOT NULL REFERENCES asset_transfers(id),
    
    anchor_point BLOB NOT NULL,
    
    asset_id BLOB NOT NULL,
    
    script_key BLOB NOT NULL,
    
    amount BIGINT NOT NULL
);

CREATE TABLE asset_transfer_outputs (
    output_id INTEGER PRIMARY KEY,
    
    transfer_id BIGINT NOT NULL REFERENCES asset_transfers(id),
    
    anchor_utxo BIGINT NOT NULL REFERENCES managed_utxos(utxo_id),
    
    script_key BIGINT NOT NULL REFERENCES script_keys(script_key_id),
    
    script_key_local BOOL NOT NULL,
    
    amount BIGINT NOT NULL,

    asset_version INTEGER NOT NULL,
    
    serialized_witnesses BLOB,
    
    split_commitment_root_hash BLOB,
    
    split_commitment_root_value BIGINT,
    
    proof_suffix BLOB,

    num_passive_assets INTEGER NOT NULL,

    output_type SMALLINT NOT NULL,

    -- proof_courier_addr is the proof courier service address associated with
    -- the output. This value will be NULL for outputs that do not require proof
    -- transfer.
    proof_courier_addr BLOB
, lock_time INTEGER, relative_lock_time INTEGER, proof_delivery_complete BOOL, position INTEGER NOT NULL DEFAULT -1);

CREATE UNIQUE INDEX asset_transfer_outputs_transfer_id_position_unique
ON asset_transfer_outputs (
    transfer_id, position
);

CREATE TABLE asset_transfers (
    id INTEGER PRIMARY KEY, 

    height_hint INTEGER NOT NULL,
    
    anchor_txn_id BIGINT NOT NULL REFERENCES chain_txns(txn_id),

    transfer_time_unix TIMESTAMP NOT NULL
, label VARCHAR DEFAULT NULL);

CREATE TABLE asset_witnesses (
    witness_id INTEGER PRIMARY KEY,

    asset_id BIGINT NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,

    prev_out_point BLOB NOT NULL,

    prev_asset_id BLOB NOT NULL,

    prev_script_key BLOB NOT NULL,

    -- The witness stack can be NULL for genesis assets where (for now) they
    -- have no witnesses, but we use this to be able to detect them as such.
    witness_stack BLOB,

    split_commitment_proof BLOB
, witness_index INTEGER NOT NULL DEFAULT -1);

CREATE UNIQUE INDEX asset_witnesses_asset_id_witness_index_unique
    ON asset_witnesses (
                asset_id, witness_index
        );

CREATE TABLE assets (
    asset_id INTEGER PRIMARY KEY,
    
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

CREATE UNIQUE INDEX assets_genesis_id_script_key_id_anchor_utxo_id_unique
    ON assets (
               genesis_id, script_key_id, anchor_utxo_id
        );

CREATE TABLE assets_meta (
    meta_id INTEGER PRIMARY KEY,

    meta_data_hash BLOB UNIQUE CHECK(length(meta_data_hash) = 32),

    -- TODO(roasbeef): also have other opque blob here for future fields?
    meta_data_blob BLOB,

    meta_data_type SMALLINT
, meta_decimal_display INTEGER, meta_universe_commitments BOOL, meta_canonical_universes BLOB
    CHECK(LENGTH(meta_canonical_universes) <= 4096), meta_delegation_key BLOB
    CHECK(LENGTH(meta_delegation_key) <= 33));

CREATE INDEX batch_state_lookup on asset_minting_batches (batch_state);

CREATE TABLE chain_txns (
    txn_id INTEGER PRIMARY KEY,

    txid BLOB UNIQUE NOT NULL,

    chain_fees BIGINT NOT NULL,

    raw_tx BLOB NOT NULL,

    block_height INTEGER,

    block_hash BLOB,

    tx_index INTEGER
);

CREATE INDEX creation_time_idx ON addr_events(creation_time);

CREATE TABLE federation_global_sync_config (
    proof_type TEXT NOT NULL PRIMARY KEY REFERENCES proof_types(proof_type),
    allow_sync_insert BOOLEAN NOT NULL,
    allow_sync_export BOOLEAN NOT NULL
);

CREATE TABLE federation_proof_sync_log (
    id INTEGER PRIMARY KEY,

    -- The status of the proof sync attempt.
    status TEXT NOT NULL CHECK(status IN ('pending', 'complete')),

    -- The timestamp of when the log entry for the associated proof was last
    -- updated.
    timestamp TIMESTAMP NOT NULL,

    -- The number of attempts that have been made to sync the proof.
    attempt_counter BIGINT NOT NULL DEFAULT 0,

    -- The direction of the proof sync attempt.
    sync_direction TEXT NOT NULL CHECK(sync_direction IN ('push', 'pull')),

    -- The ID of the subject proof leaf.
    proof_leaf_id BIGINT NOT NULL REFERENCES universe_leaves(id),

    -- The ID of the universe that the proof leaf belongs to.
    universe_root_id BIGINT NOT NULL REFERENCES universe_roots(id),

    -- The ID of the server that the proof will be/was synced to.
    servers_id BIGINT NOT NULL REFERENCES universe_servers(id)
);

CREATE UNIQUE INDEX federation_proof_sync_log_unique_index_proof_leaf_id_servers_id
ON federation_proof_sync_log (
    sync_direction,
    proof_leaf_id,
    universe_root_id,
    servers_id
);

CREATE TABLE federation_uni_sync_config (
    -- namespace is the string representation of the universe identifier, and
    -- ensures that there are no duplicate configs.
    namespace VARCHAR NOT NULL PRIMARY KEY,

    -- This field contains the byte serialized ID of the asset to which this
    -- configuration is applicable.
    asset_id BLOB CHECK(length(asset_id) = 32) NULL,

    -- This field contains the byte serialized compressed group key public key
    -- of the asset group to which this configuration is applicable.
    group_key BLOB CHECK(LENGTH(group_key) = 33) NULL,

    -- This field is an enum representing the proof type stored in the given
    -- universe.
    allow_sync_insert BOOLEAN NOT NULL,

    -- This field is a boolean that indicates whether or not the given universe
    -- should accept remote proof export via federation sync.
    allow_sync_export BOOLEAN NOT NULL, proof_type TEXT REFERENCES proof_types(proof_type),

    -- Both the asset ID and group key cannot be null at the same time.
    CHECK (
        (asset_id IS NOT NULL AND group_key IS NULL) OR
        (asset_id IS NULL AND group_key IS NOT NULL)
    )
);

CREATE TABLE genesis_assets (
    gen_asset_id INTEGER PRIMARY KEY,

    asset_id BLOB UNIQUE,

    asset_tag TEXT NOT NULL,

    meta_data_id BIGINT REFERENCES assets_meta(meta_id),

    output_index INTEGER NOT NULL,

    -- TODO(roasbeef): make into an enum? also add into asset_id generation?
    -- BIP PR
    asset_type SMALLINT NOT NULL,

    genesis_point_id BIGINT NOT NULL REFERENCES genesis_points(genesis_id)
);

CREATE VIEW genesis_info_view AS
    SELECT
        gen_asset_id, asset_id, asset_tag, assets_meta.meta_data_hash meta_hash,
        output_index, asset_type, genesis_points.prev_out prev_out,
        chain_txns.txid anchor_txid, block_height
    FROM genesis_assets
    -- We do a LEFT JOIN here, as not every asset has a set of
    -- metadata that matches the asset.
    LEFT JOIN assets_meta
        ON genesis_assets.meta_data_id = assets_meta.meta_id
    JOIN genesis_points
        ON genesis_assets.genesis_point_id = genesis_points.genesis_id
    LEFT JOIN chain_txns
        ON genesis_points.anchor_tx_id = chain_txns.txn_id;

CREATE TABLE genesis_points (
    genesis_id INTEGER PRIMARY KEY,

    -- TODO(roasbeef): just need the input index here instead?
    prev_out BLOB UNIQUE NOT NULL,

    anchor_tx_id BIGINT REFERENCES chain_txns(txn_id)
);

CREATE INDEX idx_mssmt_nodes_composite 
ON mssmt_nodes(namespace, key, hash_key, sum);

CREATE INDEX idx_universe_roots_composite ON universe_roots(namespace_root, proof_type, asset_id);

CREATE TABLE internal_keys (
    key_id INTEGER PRIMARY KEY,

    -- We'll always store the full 33-byte key on disk, to make sure we're
    -- retaining full information.
    raw_key BLOB NOT NULL UNIQUE CHECK(length(raw_key) = 33),

    key_family INTEGER NOT NULL,

    key_index INTEGER NOT NULL
);

CREATE VIEW key_group_info_view AS
SELECT
    groups.version, witness_id, gen_asset_id, witness_stack, tapscript_root,
    tweaked_group_key, raw_key, key_index, key_family,
    substr(tweaked_group_key, 2) AS x_only_group_key,
    tapscript_roots.root_hash AS custom_subtree_root
FROM asset_group_witnesses wit
         JOIN asset_groups groups
              ON wit.group_key_id = groups.group_id
         JOIN internal_keys keys
              ON keys.key_id = groups.internal_key_id

         -- Include the tapscript root hash for the custom subtree. Here we use
         -- a LEFT JOIN to allow for the case where a group does not have a
         -- custom subtree in which case the custom_subtree_root will be NULL.
         LEFT JOIN tapscript_roots
                   ON groups.custom_subtree_root_id = tapscript_roots.root_id
WHERE wit.gen_asset_id IN (SELECT gen_asset_id FROM genesis_info_view);

CREATE TABLE macaroons (
    id BLOB PRIMARY KEY,
    root_key BLOB NOT NULL 
);

CREATE TABLE managed_utxos (
    utxo_id INTEGER PRIMARY KEY,

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
, root_version SMALLINT);

CREATE TABLE mint_anchor_uni_commitments (
    id INTEGER PRIMARY KEY,

    -- The ID of the minting batch this universe commitment relates to.
    batch_id INTEGER NOT NULL REFERENCES asset_minting_batches(batch_id),

    -- The index of the mint batch anchor transaction pre-commitment output.
    tx_output_index INTEGER NOT NULL,

    -- The Taproot output internal key for the pre-commitment output.
    taproot_internal_key BLOB,

    -- The asset group key associated with the universe commitment.
    group_key BLOB
, spent_by BIGINT REFERENCES supply_commitments(commit_id));

CREATE UNIQUE INDEX mint_anchor_uni_commitments_unique
    ON mint_anchor_uni_commitments (batch_id, tx_output_index);

CREATE TABLE mssmt_nodes (
    -- hash_key is the hash key by which we reference all nodes.
    hash_key BLOB NOT NULL,
 
    -- l_hash_key is the hash key of the left child or NULL. If this is a
    -- branch then either l_hash_key or r_hash_key is not NULL.
    l_hash_key BLOB,
  
    -- r_hash_key is the hash key of the right child or NULL. If this is a
    -- branch then either l_hash_key or r_hash_key is not NULL.
    r_hash_key BLOB,
  
    -- key is the leaf key if this is a compacted leaf node.
    key BLOB,
  
    -- value is the leaf value if this is a leaf node.
    value BLOB,

    -- sum is the sum of the node.
    sum BIGINT NOT NULL,

    -- namespace allows an application to store several distinct MS-SMT nodes
    -- in the same table, partitioning them by the namespace value.
    namespace VARCHAR NOT NULL,

    -- A combination of the hash_key and the namespace comprise our primary
    -- key. Using these two in concert allows us to do things like copy trees
    -- between namespaces.
    PRIMARY KEY (hash_key, namespace)
);

CREATE INDEX mssmt_nodes_l_hash_key_idx ON mssmt_nodes (l_hash_key);

CREATE INDEX mssmt_nodes_r_hash_key_idx ON mssmt_nodes (r_hash_key);

CREATE TABLE mssmt_roots (
    -- namespace allows us to store several root hash pointers for distinct
    -- trees.
    namespace VARCHAR NOT NULL PRIMARY KEY,

    -- root_hash points to the root hash node of the MS-SMT tree.
    root_hash BLOB NOT NULL,

    FOREIGN KEY (namespace, root_hash) REFERENCES mssmt_nodes (namespace, hash_key) ON DELETE CASCADE
);

CREATE TABLE multiverse_leaves (
    id INTEGER PRIMARY KEY,

    multiverse_root_id BIGINT NOT NULL REFERENCES multiverse_roots(id),

    asset_id BLOB CHECK(length(asset_id) = 32),

    -- We use the 32 byte schnorr key here as this is what's used to derive the
    -- top-level Taproot Asset commitment key.
    group_key BLOB CHECK(LENGTH(group_key) = 32),
    
    leaf_node_key BLOB NOT NULL,

    leaf_node_namespace VARCHAR NOT NULL,

    -- Both the asset ID and group key cannot be null at the same time.
    CHECK (
        (asset_id IS NOT NULL AND group_key IS NULL) OR
        (asset_id IS NULL AND group_key IS NOT NULL)
    )
);

CREATE UNIQUE INDEX multiverse_leaves_unique ON multiverse_leaves (
    leaf_node_key, leaf_node_namespace
);

CREATE TABLE multiverse_roots (
    id INTEGER PRIMARY KEY,

    -- For the namespace root, we set the foreign key constraint evaluation to
    -- be deferred until after the database transaction ends. Otherwise, if the
    -- root of the SMT is deleted temporarily before inserting a new root, then
    -- this constraint is violated as there's no longer a root that this
    -- universe tree can point to.
    namespace_root VARCHAR UNIQUE NOT NULL REFERENCES mssmt_roots(namespace) DEFERRABLE INITIALLY DEFERRED,

    -- This field is an enum representing the proof type stored in the given
    -- universe.
    proof_type TEXT NOT NULL CHECK(proof_type IN ('issuance', 'transfer'))
);

CREATE TABLE passive_assets (
    passive_id INTEGER PRIMARY KEY,

    transfer_id BIGINT NOT NULL REFERENCES asset_transfers(id),

    asset_id BIGINT NOT NULL REFERENCES assets(asset_id),
    
    new_anchor_utxo BIGINT NOT NULL REFERENCES managed_utxos(utxo_id),

    script_key BLOB NOT NULL,

    asset_version INTEGER NOT NULL,

    new_witness_stack BLOB,

    new_proof BLOB
);

CREATE INDEX passive_assets_idx
    ON passive_assets (transfer_id);

CREATE INDEX proof_locator_hash_index
ON proof_transfer_log (proof_locator_hash);

CREATE TABLE proof_transfer_log (
    -- The type of proof transfer attempt. The transfer is either a proof
    -- delivery to the transfer counterparty or receiving a proof from the
    -- transfer counterparty. Note that the transfer counterparty is usually
    -- the proof courier service.
    transfer_type TEXT NOT NULL CHECK(transfer_type IN ('send', 'receive')),

    proof_locator_hash BLOB NOT NULL,

    time_unix TIMESTAMP NOT NULL
);

CREATE TABLE proof_types (
    proof_type TEXT PRIMARY KEY
);

CREATE TABLE script_keys (
    script_key_id INTEGER PRIMARY KEY,

    -- The actual internal key here that we hold the private key for. Applying
    -- the tweak to this gives us the tweaked_script_key.
    internal_key_id BIGINT NOT NULL REFERENCES internal_keys(key_id),

    -- The script key after applying the tweak. This is what goes directly in
    -- the asset TLV.
    tweaked_script_key BLOB NOT NULL UNIQUE CHECK(length(tweaked_script_key) = 33),

    -- An optional tweak for the script_key. If NULL, the raw_key may be
    -- tweaked BIP-0086 style.
    tweak BLOB
, key_type SMALLINT);

CREATE INDEX status_idx ON addr_events(status);

CREATE TABLE supply_commit_state_machines (
    -- The tweaked group key identifying the asset group's state machine.
    group_key BLOB PRIMARY KEY CHECK(length(group_key) = 33),

    -- The current state of the state machine.
    current_state_id INTEGER NOT NULL REFERENCES supply_commit_states(id),

    -- The latest successfully committed supply state on chain.
    -- Can be NULL if no commitment has been made yet.
    latest_commitment_id BIGINT REFERENCES supply_commitments(commit_id)
);

CREATE TABLE supply_commit_states (
    id INTEGER PRIMARY KEY,
    state_name TEXT UNIQUE NOT NULL
);

CREATE TABLE supply_commit_transitions (
    transition_id INTEGER PRIMARY KEY,

    -- Reference back to the state machine this transition belongs to.
    state_machine_group_key BLOB NOT NULL REFERENCES supply_commit_state_machines(group_key),

    -- The commitment being replaced by this transition.
    -- Can be NULL if this is the first commitment.
    old_commitment_id BIGINT REFERENCES supply_commitments(commit_id),

    -- The new commitment that this transition aims to create.
    -- Can be NULL initially, before the commitment details are created.
    new_commitment_id BIGINT REFERENCES supply_commitments(commit_id),

    -- The chain transaction that, once confirmed, will finalize this transition.
    -- Can be NULL until the transaction is created and signed.
    pending_commit_txn_id BIGINT REFERENCES chain_txns(txn_id),

    -- Indicates if this transition has been successfully completed and committed.
    finalized BOOLEAN NOT NULL DEFAULT FALSE,

    -- Timestamp when this transition was initiated.
    creation_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX supply_commit_transitions_single_pending_idx
    ON supply_commit_transitions (state_machine_group_key) WHERE finalized = 0;

CREATE INDEX supply_commit_transitions_state_machine_group_key_idx ON supply_commit_transitions(state_machine_group_key);

CREATE TABLE supply_commit_update_types (
    id INTEGER PRIMARY KEY,
    update_type_name TEXT UNIQUE NOT NULL
);

CREATE TABLE supply_commitments (
    commit_id INTEGER PRIMARY KEY,

    -- The tweaked group key identifying the asset group this commitment belongs to.
    group_key BLOB NOT NULL CHECK(length(group_key) = 33),

    -- The chain transaction that included this commitment.
    chain_txn_id BIGINT NOT NULL REFERENCES chain_txns(txn_id),

    -- The output index within the chain_txn_id transaction for the commitment.
    output_index INTEGER,

    -- The internal key used for the commitment output.
    internal_key_id BIGINT NOT NULL REFERENCES internal_keys(key_id),

    -- The taproot output key used for the commitment output.
    output_key BLOB NOT NULL CHECK(length(output_key) = 33),

    -- The block header of the block mining the commitment transaction.
    block_header BLOB,

    -- The block height at which the commitment transaction was confirmed.
    -- Can be NULL if the transaction is not yet confirmed.
    block_height INTEGER,

    -- The merkle proof demonstrating the commitment's inclusion in the block.
    merkle_proof BLOB,

    -- The root hash of the supply commitment at this snapshot.
    supply_root_hash BLOB,

    -- The root sum of the supply commitment at this snapshot.
    supply_root_sum BIGINT
);

CREATE INDEX supply_commitments_chain_txn_id_idx ON supply_commitments(chain_txn_id);

CREATE INDEX supply_commitments_group_key_idx ON supply_commitments(group_key);

CREATE TABLE supply_update_events (
    event_id INTEGER PRIMARY KEY,

    -- Reference to the state transition this event is part of.
    transition_id BIGINT NOT NULL REFERENCES supply_commit_transitions(transition_id) ON DELETE CASCADE,

    -- The type of update (mint, burn, ignore).
    update_type_id INTEGER NOT NULL REFERENCES supply_commit_update_types(id),

    -- Opaque blob containing the serialized data for the specific
    -- SupplyUpdateEvent (NewMintEvent, NewBurnEvent, NewIgnoreEvent).
    event_data BLOB NOT NULL
);

CREATE INDEX supply_update_events_transition_id_idx ON supply_update_events(transition_id);

CREATE TABLE tapscript_edges (
        edge_id INTEGER PRIMARY KEY,

        -- The root hash of a tree that includes the referenced tapscript node.
        root_hash_id BIGINT NOT NULL REFERENCES tapscript_roots(root_id),

        -- The index of the referenced node in the tapscript tree, which is
        -- needed to correctly reconstruct the tapscript tree.
        node_index BIGINT NOT NULL,

        -- The tapscript node referenced by this edge.
        raw_node_id BIGINT NOT NULL REFERENCES tapscript_nodes(node_id)
);

CREATE UNIQUE INDEX tapscript_edges_unique ON tapscript_edges (
        root_hash_id, node_index, raw_node_id
);

CREATE TABLE tapscript_nodes (
        node_id INTEGER PRIMARY KEY,

        -- The serialized tapscript node, which may be a tapHash or tapLeaf.
        raw_node BLOB NOT NULL UNIQUE
);

CREATE TABLE tapscript_roots (
        root_id INTEGER PRIMARY KEY,

        -- The root hash of a tapscript tree.
        root_hash BLOB NOT NULL UNIQUE CHECK(length(root_hash) = 32),

        -- A flag to record if a tapscript tree was stored as two tapHashes, or
        -- a set of tapLeafs.
        branch_only BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX transfer_inputs_idx
    ON asset_transfer_inputs (transfer_id);

CREATE INDEX transfer_outputs_idx
    ON asset_transfer_outputs (transfer_id);

CREATE INDEX transfer_time_idx
    ON asset_transfers (transfer_time_unix);

CREATE INDEX transfer_txn_idx
    ON asset_transfers (anchor_txn_id);

CREATE TABLE universe_events (
    event_id INTEGER PRIMARY KEY,

    event_type VARCHAR NOT NULL CHECK (event_type IN ('SYNC', 'NEW_PROOF', 'NEW_ROOT')),

    universe_root_id BIGINT NOT NULL REFERENCES universe_roots(id),

    -- TODO(roasbeef): also add which leaf was synced?

    event_time TIMESTAMP NOT NULL
, event_timestamp BIGINT NOT NULL DEFAULT 0);

CREATE INDEX universe_events_event_time_idx ON universe_events(event_time);

CREATE INDEX universe_events_type_idx ON universe_events(event_type);

CREATE TABLE "universe_leaves" (
    id INTEGER PRIMARY KEY,
    asset_genesis_id BIGINT NOT NULL REFERENCES genesis_assets(gen_asset_id),
    minting_point BLOB NOT NULL,
    script_key_bytes BLOB NOT NULL CHECK(LENGTH(script_key_bytes) = 32),
    universe_root_id BIGINT NOT NULL REFERENCES universe_roots(id),
    leaf_node_key BLOB,
    leaf_node_namespace VARCHAR NOT NULL
);

CREATE INDEX universe_leaves_key_idx ON universe_leaves(leaf_node_key);

CREATE INDEX universe_leaves_namespace ON universe_leaves(leaf_node_namespace);

CREATE UNIQUE INDEX universe_leaves_unique_minting_script_namespace ON "universe_leaves"(minting_point, script_key_bytes, leaf_node_namespace);

CREATE TABLE universe_roots (
    id INTEGER PRIMARY KEY,

    -- For the namespace root, we set the foreign key constraint evaluation to
    -- be deferred until after the database transaction ends. Otherwise, if the
    -- root of the SMT is deleted temporarily before inserting a new root, then
    -- this constraint is violated as there's no longer a root that this
    -- universe tree can point to.
    namespace_root VARCHAR UNIQUE NOT NULL REFERENCES mssmt_roots(namespace) DEFERRABLE INITIALLY DEFERRED,

    asset_id BLOB,

    -- We use the 32 byte schnorr key here as this is what's used to derive the
    -- top-level Taproot Asset commitment key.
    group_key BLOB CHECK(LENGTH(group_key) = 32),

    -- This field is an enum representing the proof type stored in the given
    -- universe.
    proof_type TEXT REFERENCES proof_types(proof_type));

CREATE INDEX universe_roots_asset_id_idx ON universe_roots(asset_id);

CREATE INDEX universe_roots_group_key_idx ON universe_roots(group_key);

CREATE TABLE universe_servers (
    id INTEGER PRIMARY KEY,

    server_host TEXT UNIQUE NOT NULL,

    -- TODO(roasbeef): do host + port? then unique on that?

    last_sync_time TIMESTAMP NOT NULL

    -- TODO(roasbeef): can also add stuff like filters re which items to sync,
    -- etc? also sync mode, ones that should get everything pushed, etc
);

CREATE INDEX universe_servers_host ON universe_servers(server_host);

CREATE VIEW universe_stats AS
WITH sync_counts AS (
    SELECT universe_root_id, COUNT(*) AS count
    FROM universe_events
    WHERE event_type = 'SYNC'
    GROUP BY universe_root_id
), proof_counts AS (
    SELECT universe_root_id, event_type, COUNT(*) AS count
    FROM universe_events
    WHERE event_type = 'NEW_PROOF'
    GROUP BY universe_root_id, event_type
), aggregated AS (
    SELECT COALESCE(SUM(count), 0) as total_asset_syncs,
           0 AS total_asset_proofs,
           universe_root_id
    FROM sync_counts
    GROUP BY universe_root_id
    UNION ALL
    SELECT 0 AS total_asset_syncs,
           COALESCE(SUM(count), 0) as total_asset_proofs,
           universe_root_id
    FROM proof_counts
    GROUP BY universe_root_id
)
SELECT
    SUM(ag.total_asset_syncs) AS total_asset_syncs,
    SUM(ag.total_asset_proofs) AS total_asset_proofs,
    roots.asset_id,
    roots.group_key,
    roots.proof_type
FROM aggregated ag
JOIN universe_roots roots
    ON ag.universe_root_id = roots.id
GROUP BY roots.asset_id, roots.group_key, roots.proof_type
ORDER BY roots.asset_id, roots.group_key, roots.proof_type;

CREATE TABLE universe_supply_leaves (
    id INTEGER PRIMARY KEY,

    -- Reference to the root supply tree this leaf belongs to.
    supply_root_id BIGINT NOT NULL REFERENCES universe_supply_roots(id) ON DELETE CASCADE,

    -- The type of sub-tree this leaf represents (issuance, burn, ignore).
    sub_tree_type TEXT NOT NULL REFERENCES proof_types(proof_type),

    -- The key used for this leaf within the root supply tree's MS-SMT.
    -- This typically corresponds to a hash identifying the sub-tree type.
    leaf_node_key BLOB NOT NULL,

    -- The namespace within mssmt_nodes where the actual sub-tree root node resides.
    leaf_node_namespace VARCHAR NOT NULL,

    -- Ensure each supply root has only one leaf per sub-tree type.
    UNIQUE(supply_root_id, sub_tree_type)
);

CREATE INDEX universe_supply_leaves_supply_root_id_idx ON universe_supply_leaves(supply_root_id);

CREATE INDEX universe_supply_leaves_supply_root_id_type_idx ON universe_supply_leaves(supply_root_id, sub_tree_type);

CREATE TABLE universe_supply_roots (
    id INTEGER PRIMARY KEY,

    -- The namespace root of the MS-SMT representing this supply tree.
    -- We set the foreign key constraint evaluation to be deferred until after
    -- the database transaction ends. Otherwise, if the root of the SMT is
    -- deleted temporarily before inserting a new root, then this constraint
    -- is violated.
    namespace_root VARCHAR UNIQUE NOT NULL REFERENCES mssmt_roots(namespace) DEFERRABLE INITIALLY DEFERRED,

    -- The tweaked group key identifying the asset group this supply tree belongs to.
    group_key BLOB UNIQUE NOT NULL CHECK(length(group_key) = 33)
);

CREATE INDEX universe_supply_roots_group_key_idx ON universe_supply_roots(group_key);

