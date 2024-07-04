-- Step 0: temporary table that sets a boolean flag (has_duplicates) based on
-- whether duplicates exist. All UPDATE and DELETE statements below are
-- contingent on this flag.
CREATE TABLE tmp_duplicate_check AS
SELECT CASE
        WHEN EXISTS (
                SELECT 1
        FROM assets
        GROUP BY genesis_id, script_key_id, amount, anchor_utxo_id
        HAVING COUNT(*) > 1
        )
        THEN 1
        ELSE 0
END AS has_duplicates;

-- Step 1: If the assets were spent, some of the duplicates might not have been
-- updated on that flag. To make sure we can properly group on the spent flag
-- below, we now update all assets that are spent.
UPDATE assets
SET spent = true
WHERE (SELECT has_duplicates
        FROM tmp_duplicate_check) = 1
        AND asset_id IN (SELECT a.asset_id
        FROM assets a
                JOIN managed_utxos mu
                ON a.anchor_utxo_id = mu.utxo_id
                JOIN chain_txns ct
                ON mu.txn_id = ct.txn_id
                LEFT JOIN asset_transfer_inputs ati
                ON ati.anchor_point = mu.outpoint
        WHERE a.spent = false
                AND ati.input_id IS NOT NULL);

-- Step 2: Create a temporary table to store the minimum asset_id for each
-- unique combination.
CREATE TABLE tmp_min_assets AS
SELECT MIN(asset_id) AS min_asset_id,
        genesis_id,
        script_key_id,
        amount,
        anchor_utxo_id,
        spent
FROM assets
GROUP BY genesis_id, script_key_id, amount, anchor_utxo_id, spent;

-- Step 3: Create a mapping table to track old and new asset_ids.
CREATE TABLE tmp_asset_id_mapping AS
SELECT a.asset_id       AS old_asset_id,
        tmp.min_asset_id AS new_asset_id
FROM assets a
        JOIN tmp_min_assets tmp
        ON a.genesis_id = tmp.genesis_id
                AND a.script_key_id = tmp.script_key_id
                AND a.amount = tmp.amount
                AND a.anchor_utxo_id = tmp.anchor_utxo_id
                AND a.spent = tmp.spent;

-- Step 4: To make the next step possible, we need to disable a unique index on
-- the asset_witnesses table. We'll re-create it later.
DROP INDEX IF EXISTS asset_witnesses_asset_id_witness_index_unique;

-- Step 5: Update the asset_witnesses and asset_proofs tables to reference the
-- new asset_ids.
UPDATE asset_witnesses
SET asset_id = tmp_asset_id_mapping.new_asset_id
FROM tmp_asset_id_mapping
WHERE (SELECT has_duplicates
        FROM tmp_duplicate_check) = 1
        AND asset_witnesses.asset_id = tmp_asset_id_mapping.old_asset_id;

-- For the proofs we need skip re-assigning them to the asset that we're going
-- to keep if it already has a proof. This is because the unique index on the
-- asset_proofs table would prevent us from doing so. And we can't disable the
-- unique index, because it is an unnamed/inline index.
UPDATE asset_proofs
SET asset_id = filtered_mapping.new_asset_id
FROM (                  
        SELECT MIN(old_asset_id) AS old_asset_id, new_asset_id
        FROM asset_proofs
                JOIN tmp_asset_id_mapping
                ON asset_proofs.asset_id = tmp_asset_id_mapping.old_asset_id
        GROUP BY new_asset_id) AS filtered_mapping
WHERE (SELECT has_duplicates
        FROM tmp_duplicate_check) = 1
        AND asset_proofs.asset_id = filtered_mapping.old_asset_id;

-- Step 6: Remove duplicates from the asset_witnesses table.
DELETE
FROM asset_witnesses
WHERE (SELECT has_duplicates
        FROM tmp_duplicate_check) = 1
        AND witness_id NOT IN (SELECT min(witness_id)
        FROM asset_witnesses
        GROUP BY asset_id, witness_index);

-- Step 7: Re-enable the unique index on the asset_witnesses table.
CREATE UNIQUE INDEX asset_witnesses_asset_id_witness_index_unique
    ON asset_witnesses (
                asset_id, witness_index
        );

-- Step 8: Delete any duplicate proofs.
DELETE
FROM asset_proofs
WHERE (SELECT has_duplicates
        FROM tmp_duplicate_check) = 1
        AND asset_id NOT IN (SELECT min_asset_id
        FROM tmp_min_assets);

-- Step 9: Delete the duplicates from the assets table. This will then also
-- delete dangling asset_witnesses.
DELETE
FROM assets
WHERE (SELECT has_duplicates
        FROM tmp_duplicate_check) = 1
        AND asset_id NOT IN (SELECT min_asset_id
        FROM tmp_min_assets);

-- Step 10: Clean up temporary tables.
DROP TABLE IF EXISTS tmp_min_assets;
DROP TABLE IF EXISTS tmp_asset_id_mapping;
DROP TABLE IF EXISTS tmp_duplicate_check;

-- Step 11: Create the unique index on the assets table.
CREATE UNIQUE INDEX assets_genesis_id_script_key_id_anchor_utxo_id_unique
    ON assets (
               genesis_id, script_key_id, anchor_utxo_id
        );
