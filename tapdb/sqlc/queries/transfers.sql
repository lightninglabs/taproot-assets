-- name: InsertAssetTransfer :one
WITH target_txn(txn_id) AS (
    SELECT txn_id
    FROM chain_txns
    WHERE txid = @anchor_txid
)
INSERT INTO asset_transfers (
    height_hint, anchor_txn_id, transfer_time_unix, label,
    skip_anchor_tx_broadcast
) VALUES (
    @height_hint, (SELECT txn_id FROM target_txn), @transfer_time_unix, @label,
    @skip_anchor_tx_broadcast
) RETURNING id;

-- name: InsertAssetTransferInput :exec
INSERT INTO asset_transfer_inputs (
    transfer_id, anchor_point, asset_id, script_key, amount
) VALUES (
    $1, $2, $3, $4, $5
);

-- name: InsertAssetTransferOutput :exec
INSERT INTO asset_transfer_outputs (
    transfer_id, anchor_utxo, script_key, script_key_local,
    amount, serialized_witnesses, split_commitment_root_hash,
    split_commitment_root_value, proof_suffix, num_passive_assets,
    output_type, proof_courier_addr, asset_version, lock_time,
    relative_lock_time, proof_delivery_complete, position, tap_address
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17,
    $18
);

-- name: SetTransferOutputProofDeliveryStatus :exec
WITH target(output_id) AS (
    SELECT output_id
    FROM asset_transfer_outputs output
    JOIN managed_utxos
      ON output.anchor_utxo = managed_utxos.utxo_id
    WHERE managed_utxos.outpoint = @serialized_anchor_outpoint
      AND output.position = @position
)
UPDATE asset_transfer_outputs
SET proof_delivery_complete = @delivery_complete
WHERE output_id = (SELECT output_id FROM target);

-- name: QueryAssetTransfers :many
SELECT
    id, height_hint, txns.txid, txns.block_hash AS anchor_tx_block_hash,
    transfer_time_unix, transfers.label,
    transfers.skip_anchor_tx_broadcast
FROM asset_transfers transfers
JOIN chain_txns txns
    ON txns.txn_id = transfers.anchor_txn_id
WHERE
    -- Optionally filter on a given anchor_tx_hash.
    (txns.txid = sqlc.narg('anchor_tx_hash')
        OR sqlc.narg('anchor_tx_hash') IS NULL)

    -- Filter for pending transfers only if requested.
    --
    -- NOTE: This query is also executed by programmatic migrations against
    -- historical schema versions, so it MUST NOT reference columns added
    -- in later migrations (such as transfers.superseded). Superseded
    -- transfers are filtered out in Go instead.
    AND (
        @pending_transfers_only = true AND
        (
            txns.block_hash IS NULL
                OR EXISTS (
                    SELECT 1
                    FROM asset_transfer_outputs outputs
                    WHERE outputs.transfer_id = transfers.id
                      AND outputs.proof_delivery_complete = false
                )
        )
        OR @pending_transfers_only = false OR @pending_transfers_only IS NULL
    )

    -- Optionally filter on a given start time.
    AND transfers.transfer_time_unix >=
        COALESCE(sqlc.narg('start_time'), transfers.transfer_time_unix)

    -- Optionally filter on a given label.
    AND (transfers.label = sqlc.narg('filter_label') OR
            sqlc.narg('filter_label') IS NULL)

    -- Optionally filter on outputs with a specific script key.
    AND (
      EXISTS (
        SELECT 1
        FROM asset_transfer_outputs outputs
        JOIN script_keys sk ON outputs.script_key = sk.script_key_id
        WHERE outputs.transfer_id = transfers.id
          AND sk.tweaked_script_key = sqlc.arg('filter_script_key')
      )
      OR sqlc.arg('filter_script_key') IS NULL
    )
ORDER BY transfer_time_unix;

-- name: FetchTransferInputs :many
SELECT input_id, anchor_point, asset_id, script_key, amount
FROM asset_transfer_inputs inputs
WHERE transfer_id = $1
ORDER BY input_id;

-- name: QuerySupersededTransferIDs :many
SELECT id
FROM asset_transfers
WHERE superseded = true;

-- name: SupersedeConflictingTransfers :execrows
-- Mark all unconfirmed transfers that spend the given anchor point as
-- superseded, except for the given (just confirmed) transfer. Once a
-- conflicting transfer has confirmed on-chain, these transfers' anchor
-- transactions can never confirm.
UPDATE asset_transfers
SET superseded = true
WHERE id != @confirmed_transfer_id
  AND superseded = false
  AND id IN (
      SELECT inputs.transfer_id
      FROM asset_transfer_inputs inputs
      WHERE inputs.anchor_point = @anchor_point
  )
  AND anchor_txn_id IN (
      SELECT txns.txn_id
      FROM chain_txns txns
      WHERE txns.block_hash IS NULL
  );

-- name: FetchTransferOutputs :many
SELECT
    output_id, proof_suffix, amount, serialized_witnesses, script_key_local,
    split_commitment_root_hash, split_commitment_root_value, num_passive_assets,
    output_type, proof_courier_addr, proof_delivery_complete, position,
    asset_version, lock_time, relative_lock_time, tap_address,
    utxos.utxo_id AS anchor_utxo_id,
    utxos.outpoint AS anchor_outpoint,
    utxos.amt_sats AS anchor_value,
    utxos.merkle_root AS anchor_merkle_root,
    utxos.taproot_asset_root AS anchor_taproot_asset_root,
    utxos.tapscript_sibling AS anchor_tapscript_sibling,
    utxos.root_version AS anchor_commitment_version,
    utxo_internal_keys.raw_key AS internal_key_raw_key_bytes,
    utxo_internal_keys.key_family AS internal_key_family,
    utxo_internal_keys.key_index AS internal_key_index,
    sqlc.embed(script_keys),
    sqlc.embed(script_internal_keys)
FROM asset_transfer_outputs outputs
JOIN managed_utxos utxos
  ON outputs.anchor_utxo = utxos.utxo_id
JOIN script_keys
  ON outputs.script_key = script_keys.script_key_id
JOIN internal_keys script_internal_keys
  ON script_keys.internal_key_id = script_internal_keys.key_id
JOIN internal_keys utxo_internal_keys
  ON utxos.internal_key_id = utxo_internal_keys.key_id
WHERE transfer_id = $1
ORDER BY output_id;

-- name: ApplyPendingOutput :one
WITH spent_asset AS (
    SELECT genesis_id, asset_group_witness_id, script_version
    FROM assets
    WHERE assets.asset_id = @spent_asset_id
)
INSERT INTO assets (
    genesis_id, version, asset_group_witness_id, script_version, lock_time,
    relative_lock_time, script_key_id, anchor_utxo_id, amount,
    split_commitment_root_hash, split_commitment_root_value, spent
) VALUES (
    (SELECT genesis_id FROM spent_asset),
    @asset_version,
    (SELECT asset_group_witness_id FROM spent_asset),
    (SELECT script_version FROM spent_asset),
    @lock_time, @relative_lock_time, @script_key_id, @anchor_utxo_id, @amount,
    @split_commitment_root_hash, @split_commitment_root_value, @spent
)
ON CONFLICT (genesis_id, script_key_id, anchor_utxo_id)
    -- This is a NOP, anchor_utxo_id is one of the unique fields that caused the
    -- conflict.
    DO UPDATE SET anchor_utxo_id = EXCLUDED.anchor_utxo_id
RETURNING asset_id;

-- name: ReAnchorPassiveAssets :exec
UPDATE assets
SET anchor_utxo_id = @new_anchor_utxo_id,
    -- The following fields need to be the same fields we reset in
    -- Asset.CopySpendTemplate.
    split_commitment_root_hash = NULL,
    split_commitment_root_value = NULL,
    lock_time = 0,
    relative_lock_time = 0
WHERE asset_id = @asset_id;

-- name: DeleteAssetWitnesses :exec
DELETE FROM asset_witnesses
WHERE asset_id = $1;

-- name: LogProofTransferAttempt :exec
INSERT INTO proof_transfer_log (
    transfer_type, proof_locator_hash, time_unix
) VALUES (
    @transfer_type, @proof_locator_hash, @time_unix
);

-- name: QueryProofTransferAttempts :many
SELECT time_unix
FROM proof_transfer_log
WHERE proof_locator_hash = @proof_locator_hash
    AND transfer_type = @transfer_type
ORDER BY time_unix DESC;

-- name: InsertPassiveAsset :exec
WITH target_asset(asset_id) AS (
    SELECT assets.asset_id
    FROM assets
        JOIN genesis_assets
            ON assets.genesis_id = genesis_assets.gen_asset_id
        JOIN managed_utxos utxos
            ON assets.anchor_utxo_id = utxos.utxo_id
        JOIN script_keys
            ON assets.script_key_id = script_keys.script_key_id
    WHERE genesis_assets.asset_id = @asset_genesis_id
        AND utxos.outpoint = @prev_outpoint
        AND script_keys.tweaked_script_key = @script_key
)
INSERT INTO passive_assets (
    asset_id, transfer_id, new_anchor_utxo, script_key, new_witness_stack,
    new_proof, asset_version
) VALUES (
    (SELECT asset_id FROM target_asset), @transfer_id, @new_anchor_utxo,
    @script_key, @new_witness_stack, @new_proof, @asset_version
);

-- name: QueryPassiveAssets :many
SELECT passive.asset_id, passive.new_anchor_utxo, passive.script_key,
       passive.new_witness_stack, passive.new_proof,
       genesis_assets.asset_id AS genesis_id, passive.asset_version,
       utxos.outpoint
FROM passive_assets as passive
    JOIN assets
        ON passive.asset_id = assets.asset_id
    JOIN genesis_assets
        ON assets.genesis_id = genesis_assets.gen_asset_id
    JOIN managed_utxos utxos
        ON passive.new_anchor_utxo = utxos.utxo_id
WHERE passive.transfer_id = @transfer_id;

-- name: InsertBurn :one
INSERT INTO asset_burn_transfers (
    transfer_id, note, asset_id, group_key, amount
)
VALUES (
    @transfer_id, @note, @asset_id, @group_key, @amount
)
RETURNING burn_id;

-- name: QueryBurns :many
SELECT
    abt.note,
    abt.asset_id,
    abt.group_key,
    ga.asset_type,
    abt.amount,
    ct.txid AS anchor_txid -- Retrieving the txid from chain_txns.
FROM asset_burn_transfers abt
JOIN genesis_assets ga ON abt.asset_id = ga.asset_id
JOIN asset_transfers at ON abt.transfer_id = at.id
JOIN chain_txns ct ON at.anchor_txn_id = ct.txn_id
WHERE
    -- Optionally filter by asset_id.
    (abt.asset_id = @asset_id OR @asset_id IS NULL)

    -- Optionally filter by group_key.
    AND (abt.group_key = @group_key OR @group_key IS NULL)

    -- Optionally filter by anchor_txid in chain_txns.txid.
    AND (ct.txid = @anchor_txid OR @anchor_txid IS NULL)
ORDER BY abt.burn_id;

-- name: UnconfirmChainAnchorTx :exec
-- The inverse of ConfirmChainAnchorTx: the anchor transaction's
-- recorded confirmation is withdrawn (its block was re-organized
-- away and nothing has replaced it yet).
UPDATE chain_txns
SET block_hash = NULL, block_height = NULL, tx_index = NULL
WHERE txid = @txid;

-- name: SupersededTransfersSpendingPoint :many
-- The superseded rivals of an abandoned transfer at one of its anchor
-- points: the candidates for revival when it is abandoned.
--
-- Only rivalry losers are candidates. A transfer marked abandoned was
-- superseded by its own abandonment — its inputs were claimed by a
-- buried foreign transaction — so reviving it would resume a transfer
-- whose anchor can never confirm.
SELECT DISTINCT transfers.id
FROM asset_transfers transfers
JOIN asset_transfer_inputs inputs
  ON inputs.transfer_id = transfers.id
WHERE inputs.anchor_point = @anchor_point
  AND transfers.id != @abandoned_transfer_id
  AND transfers.superseded = true
  AND transfers.abandoned = false
ORDER BY transfers.id;

-- name: UnsupersedeSafeTransfer :execrows
-- The inverse of SupersedeConflictingTransfers for one rivalry loser,
-- applied when the transfer that superseded it is abandoned: the loser
-- becomes live again, provided no confirmed transfer conflicts with it
-- on any of its inputs — not merely on the input it shared with the
-- abandoned transfer. A rival that also spends an input some other
-- confirmed transfer claims can never confirm, and reviving it would
-- resume a parcel that rebroadcasts a doomed anchor.
--
-- The abandoned transfer's own confirmation is withdrawn before this
-- runs, so it cannot answer as the conflicting claimant.
UPDATE asset_transfers
SET superseded = false
WHERE asset_transfers.id = @transfer_id
  AND asset_transfers.superseded = true
  AND asset_transfers.abandoned = false
  AND NOT EXISTS (
      SELECT 1
      FROM asset_transfer_inputs own_in
      JOIN asset_transfer_inputs other_in
        ON other_in.anchor_point = own_in.anchor_point
       AND other_in.transfer_id != own_in.transfer_id
      JOIN asset_transfers other
        ON other.id = other_in.transfer_id
      JOIN chain_txns txns
        ON txns.txn_id = other.anchor_txn_id
      WHERE own_in.transfer_id = @transfer_id
        AND txns.block_hash IS NOT NULL
  );

-- name: CountLiveTransfersSpendingPoint :one
-- The live claimants of an anchor point other than the given
-- (abandoned) transfer: unconfirmed transfers, not superseded, that
-- spend the point. A revived rival is one — its replacement is still
-- in flight to spend the input — so the abandonment retains the
-- input's lease rather than releasing it.
SELECT COUNT(DISTINCT transfers.id)
FROM asset_transfers transfers
JOIN asset_transfer_inputs inputs
  ON inputs.transfer_id = transfers.id
JOIN chain_txns txns
  ON txns.txn_id = transfers.anchor_txn_id
WHERE inputs.anchor_point = @anchor_point
  AND transfers.id != @abandoned_transfer_id
  AND transfers.superseded = false
  AND txns.block_hash IS NULL;

-- name: MarkTransferSuperseded :exec
-- An abandoned transfer is permanently dead: its anchor inputs were
-- claimed by a buried foreign transaction, so its own anchor can
-- never confirm. Superseded transfers are not resumed at startup.
--
-- The abandoned flag records *why* it is superseded, so that a later
-- abandonment of a sibling sharing an input cannot revive it.
UPDATE asset_transfers
SET superseded = true, abandoned = true
WHERE id = @transfer_id;

-- name: UnsupersedeTransfer :exec
-- Lift the confirming transfer's own superseded flag. A rivalry loser
-- can still confirm — the rival that superseded it may since have been
-- re-organized out — and once it does, its confirmation supersedes the
-- rival in turn; the flag on the transfer itself must be lifted too,
-- or it is skipped at startup and never completes. An abandoned
-- transfer is left alone: it was compensated by its own abandonment.
UPDATE asset_transfers
SET superseded = false
WHERE id = @transfer_id
  AND abandoned = false;

-- name: SupersedeIfConflictingConfirmed :exec
-- Re-enter supersession for the transfer of the given anchor
-- transaction when another confirmed transfer claims one of its
-- inputs, applied when its confirmation is withdrawn. The rival's
-- confirmation did not supersede this transfer — only unconfirmed
-- rivals are superseded, and this one was confirmed at the time — so
-- without this it would sit unconfirmed and unsuperseded, be resumed
-- at startup, and rebroadcast an anchor that can never confirm.
UPDATE asset_transfers
SET superseded = true
WHERE asset_transfers.anchor_txn_id = (
      SELECT anchor.txn_id
      FROM chain_txns anchor
      WHERE anchor.txid = @txid
  )
  AND EXISTS (
      SELECT 1
      FROM asset_transfer_inputs own_in
      JOIN asset_transfer_inputs other_in
        ON other_in.anchor_point = own_in.anchor_point
       AND other_in.transfer_id != own_in.transfer_id
      JOIN asset_transfers other
        ON other.id = other_in.transfer_id
      JOIN chain_txns txns
        ON txns.txn_id = other.anchor_txn_id
      WHERE own_in.transfer_id = asset_transfers.id
        AND txns.block_hash IS NOT NULL
  );

-- name: DeleteBurnsByTransferID :exec
DELETE FROM asset_burn_transfers
WHERE transfer_id = @transfer_id;

-- name: UnsweepManagedUTXOsByTxid :exec
-- The inverse of MarkManagedUTXOAsSwept for every UTXO swept by the
-- given (now abandoned) transaction.
UPDATE managed_utxos
SET swept_txn_id = NULL
WHERE swept_txn_id = (
    SELECT txn_id FROM chain_txns WHERE txid = @txid
);

-- name: TransferOutputAssetID :one
-- The asset row a transfer output materialized into, if any: the
-- convergence guard for re-applying a confirmation, and the target
-- of compensation when the transfer is abandoned. The genesis filter
-- is necessary: distinct assets can share both script key and anchor
-- UTXO (a multi-asset HTLC swept in one transaction), so the pair
-- alone is ambiguous.
SELECT assets.asset_id
FROM assets
JOIN genesis_assets
    ON assets.genesis_id = genesis_assets.gen_asset_id
WHERE assets.script_key_id = @script_key_id
  AND assets.anchor_utxo_id = @anchor_utxo_id
  AND genesis_assets.asset_id = @asset_id;

-- name: DeletePassiveAssetsByAssetID :execrows
-- The passive re-anchor records pointing at one asset row.
--
-- A transfer records its intent to re-anchor a pre-existing holding
-- before it broadcasts, so an asset that an earlier, confirmed
-- transfer materialized as one of its outputs can already be a
-- successor's passive holding by the time that earlier transfer is
-- abandoned. passive_assets.asset_id is NOT NULL with no ON DELETE, so
-- the reference has to be shed before the row it points at; otherwise
-- the delete fails the watcher's entire delivery transaction and the
-- abandonment can never apply at all.
--
-- Discarding the successor's record is the correct reversal rather
-- than merely the expedient one. The asset is being erased because the
-- transaction that created it is gone from the surviving chain, so the
-- successor's re-anchor of it never had a subject — and the successor,
-- which spends an anchor output that no longer exists, cannot confirm
-- either. The successor's own compensation reads passive_assets by
-- transfer and simply finds nothing left to restore.
DELETE FROM passive_assets
WHERE asset_id = @asset_id;

-- name: DeleteAssetByID :exec
DELETE FROM assets
WHERE asset_id = @asset_id;

-- name: DeleteAssetProofByAssetID :exec
DELETE FROM asset_proofs
WHERE asset_id = @asset_id;

-- name: AssetProofBlobByAssetID :one
-- The proof blob keyed by the asset's primary key (not the BIPS
-- asset ID), as needed when compensating passive re-anchors.
SELECT proof_file
FROM asset_proofs
WHERE asset_id = @asset_id;

-- name: RestoreAssetSpendTemplate :exec
-- The inverse of ReAnchorPassiveAssets: restore the anchor UTXO and
-- the spend-template fields that the re-anchor reset.
UPDATE assets
SET anchor_utxo_id = @anchor_utxo_id,
    split_commitment_root_hash = @split_commitment_root_hash,
    split_commitment_root_value = @split_commitment_root_value,
    lock_time = @lock_time,
    relative_lock_time = @relative_lock_time
WHERE asset_id = @asset_id;

-- name: AnchoredAssetsByAnchorTxPrefix :many
-- The assets a receive (or mint) materialized in outputs of the given
-- transaction, each with the parts of its proof locator: managed UTXO
-- outpoints are stored as txid || index, so a prefix match on the
-- txid finds every output of the transaction.
--
-- A holding anchored in the transaction's outputs is the
-- transaction's materialization — and so this site's to re-stamp and
-- to compensate — unless the transaction's own transfer re-anchored
-- it there: a passive_assets row of a transfer anchored by this very
-- transaction marks a pre-existing holding the transfer carried
-- along, which the porter's confirmation re-stamps and the porter's
-- abandonment restores to its prior anchor. Only those are excluded.
-- A passive row of some other transfer (a successor that staked the
-- holding before broadcasting, and whose re-anchor has not yet
-- confirmed) does not change what this transaction materialized: the
-- holding still goes with it, and the compensation body sheds the
-- successor's reference first.
SELECT assets.asset_id,
       genesis_assets.asset_id AS genesis_asset_id,
       script_keys.tweaked_script_key,
       utxos.outpoint
FROM assets
JOIN genesis_assets
  ON assets.genesis_id = genesis_assets.gen_asset_id
JOIN script_keys
  ON assets.script_key_id = script_keys.script_key_id
JOIN managed_utxos utxos
  ON assets.anchor_utxo_id = utxos.utxo_id
WHERE substr(utxos.outpoint, 1, 32) = @txid
  AND NOT EXISTS (
      SELECT 1
      FROM passive_assets passives
      JOIN asset_transfers transfers
        ON passives.transfer_id = transfers.id
      JOIN chain_txns txns
        ON transfers.anchor_txn_id = txns.txn_id
      WHERE passives.asset_id = assets.asset_id
        AND txns.txid = @txid
  );
