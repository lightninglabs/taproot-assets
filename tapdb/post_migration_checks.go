package tapdb

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/tapscript"
	"github.com/lightningnetwork/lnd/clock"
)

const (
	// Migration50ScriptKeyType is the version of the programmatic migration
	// that runs the script key type detection/backfill.
	Migration50ScriptKeyType = 50

	// Migration51InsertAssetBurns is the version of the programmatic
	// migration that inserts the asset burns into the specific asset burns
	// table by querying all assets and detecting burns from their
	// witnesses.
	Migration51InsertAssetBurns = 51
)

// postMigrationCheck is a function type for a function that performs a
// post-migration check on the database.
type postMigrationCheck func(context.Context, sqlc.Querier) error

var (
	// postMigrationChecks is a map of functions that are run after the
	// database migration with the version specified in the key has been
	// applied. These functions are used to perform additional checks on the
	// database state that are not fully expressible in SQL.
	postMigrationChecks = map[uint]postMigrationCheck{
		Migration50ScriptKeyType:    determineAndAssignScriptKeyType,
		Migration51InsertAssetBurns: insertAssetBurns,
	}
)

// makePostStepCallbacks turns the post migration checks into a map of post
// step callbacks that can be used with the migrate package. The keys of the map
// are the migration versions, and the values are the callbacks that will be
// executed after the migration with the corresponding version is applied.
func makePostStepCallbacks(db DatabaseBackend,
	checks map[uint]postMigrationCheck) map[uint]migrate.PostStepCallback {

	var (
		ctx  = context.Background()
		txDb = NewTransactionExecutor(
			db, func(tx *sql.Tx) sqlc.Querier {
				return db.WithTx(tx)
			},
		)
		writeTxOpts AssetStoreTxOptions
	)

	postStepCallbacks := make(map[uint]migrate.PostStepCallback)
	for version, check := range checks {
		runCheck := func(m *migrate.Migration, q sqlc.Querier) error {
			log.Infof("Running post-migration check for version %d",
				version)
			start := time.Now()

			err := check(ctx, q)
			if err != nil {
				return fmt.Errorf("post-migration "+
					"check failed for version %d: "+
					"%w", version, err)
			}

			log.Infof("Post-migration check for version %d "+
				"completed in %v", version, time.Since(start))

			return nil
		}

		// We ignore the actual driver that's being returned here, since
		// we use migrate.NewWithInstance() to create the migration
		// instance from our already instantiated database backend that
		// is also passed into this function.
		postStepCallbacks[version] = func(m *migrate.Migration,
			_ database.Driver) error {

			return txDb.ExecTx(
				ctx, &writeTxOpts, func(q sqlc.Querier) error {
					return runCheck(m, q)
				},
			)
		}
	}

	return postStepCallbacks
}

// determineAndAssignScriptKeyType attempts to detect the type of the script
// keys that don't have a type set yet.
func determineAndAssignScriptKeyType(ctx context.Context,
	q sqlc.Querier) error {

	defaultClock := clock.NewDefaultClock()

	log.Debugf("Detecting script key types")

	// We start by fetching all assets, even the spent ones. We then collect
	// a list of the burn keys from the assets (because burn keys can only
	// be calculated from the asset's witness).
	assetFilter := QueryAssetFilters{
		Now: sqlTime(defaultClock.Now().UTC()),
	}
	dbAssets, assetWitnesses, err := fetchAssetsWithWitness(
		ctx, q, assetFilter,
	)
	if err != nil {
		return fmt.Errorf("error fetching assets: %w", err)
	}

	chainAssets, err := dbAssetsToChainAssets(
		dbAssets, assetWitnesses, defaultClock,
	)
	if err != nil {
		return fmt.Errorf("error converting assets: %w", err)
	}

	burnAssets := fn.Filter(chainAssets, func(a *asset.ChainAsset) bool {
		return a.IsBurn()
	})
	burnKeys := make(map[asset.SerializedKey]struct{})
	for _, a := range burnAssets {
		serializedKey := asset.ToSerialized(a.ScriptKey.PubKey)
		burnKeys[serializedKey] = struct{}{}
	}

	untypedKeys, err := q.FetchUnknownTypeScriptKeys(ctx)
	if err != nil {
		return fmt.Errorf("error fetching script keys: %w", err)
	}

	channelFundingKey := asset.NewScriptKey(
		tapscript.NewChannelFundingScriptTree().TaprootKey,
	).PubKey

	for _, k := range untypedKeys {
		scriptKey, err := parseScriptKey(k.InternalKey, k.ScriptKey)
		if err != nil {
			return fmt.Errorf("error parsing script key: %w", err)
		}

		// We ignore the parity bit when comparing it to other keys, as
		// we generally don't know how it might be stored in the DB.
		schnorrScriptKey, _ := schnorr.ParsePubKey(
			schnorr.SerializePubKey(scriptKey.PubKey),
		)

		serializedKey := asset.ToSerialized(scriptKey.PubKey)
		newType := asset.ScriptKeyUnknown

		if _, ok := burnKeys[serializedKey]; ok {
			newType = asset.ScriptKeyBurn
		} else {
			assumedType := scriptKey.DetermineType(nil)

			switch {
			// If we're sure that a key is BIP-86 or the well-known
			// NUMS (tombstone) key, we mark it as such.
			case assumedType == asset.ScriptKeyBip86 ||
				assumedType == asset.ScriptKeyTombstone:

				newType = assumedType

			// Previous channel funding script keys (OP_TRUE) can
			// be detected, since they are the same key. New, unique
			// script keys for grouped asset channels are only
			// introduced with the same version as this migration
			// ships in, so they should be stored with the correct
			// type already.
			case assumedType == asset.ScriptKeyScriptPathExternal &&
				schnorrScriptKey.IsEqual(channelFundingKey):

				newType = asset.ScriptKeyScriptPathChannel

			// We'll want to not show scripted keys by default in
			// the balances. So any key that is not a burn key and
			// not a channel funding key, but has a script path, we
			// mark as external script path.
			case assumedType == asset.ScriptKeyScriptPathExternal:
				newType = asset.ScriptKeyScriptPathExternal
			}
		}

		// If we weren't able to identify the key type, we can't do much
		// more than log it. We won't update the key type, since
		// "unknown" is already the default value.
		if newType == asset.ScriptKeyUnknown {
			log.Warnf("Unable to determine script key type for "+
				"key %x, internal key %x", serializedKey[:],
				scriptKey.RawKey.PubKey.SerializeCompressed())

			continue
		}

		// If we were able to identify the key type, we update the key
		// in the database.
		_, err = q.UpsertScriptKey(ctx, NewScriptKey{
			InternalKeyID:    k.InternalKey.KeyID,
			TweakedScriptKey: k.ScriptKey.TweakedScriptKey,
			Tweak:            k.ScriptKey.Tweak,
			KeyType:          sqlInt16(newType),
		})
		if err != nil {
			return fmt.Errorf("error updating script key type: %w",
				err)
		}
	}

	return nil
}

// insertAssetBurns queries all assets and detects burns from their witnesses,
// then inserts the asset burns into the specific asset burns table.
func insertAssetBurns(ctx context.Context, q sqlc.Querier) error {
	defaultClock := clock.NewDefaultClock()

	log.Debugf("Detecting script key types")

	// We start by fetching all assets, even the spent ones. We then collect
	// a list of the burn keys from the assets (because burn keys can only
	// be calculated from the asset's witness).
	assetFilter := QueryAssetFilters{
		Now: sqlTime(defaultClock.Now().UTC()),
	}
	dbAssets, assetWitnesses, err := fetchAssetsWithWitness(
		ctx, q, assetFilter,
	)
	if err != nil {
		return fmt.Errorf("error fetching assets: %w", err)
	}

	chainAssets, err := dbAssetsToChainAssets(
		dbAssets, assetWitnesses, defaultClock,
	)
	if err != nil {
		return fmt.Errorf("error converting assets: %w", err)
	}

	burnAssets := fn.Filter(chainAssets, func(a *asset.ChainAsset) bool {
		return a.IsBurn()
	})

	burnsInTable, err := q.QueryBurns(ctx, sqlc.QueryBurnsParams{})
	if err != nil {
		return err
	}

	burnsMatch := func(b sqlc.QueryBurnsRow, a *asset.ChainAsset) bool {
		txMatch := (chainhash.Hash(b.AnchorTxid)) == a.AnchorTx.TxHash()
		assetIDMatch := (asset.ID(b.AssetID)) == a.ID()
		amountMatch := uint64(b.Amount) == a.Amount
		return txMatch && assetIDMatch && amountMatch
	}
	burnAssetsNotInTable := fn.Filter(
		burnAssets, func(a *asset.ChainAsset) bool {
			return fn.NotAny(
				burnsInTable, func(b sqlc.QueryBurnsRow) bool {
					return burnsMatch(b, a)
				},
			)
		},
	)

	log.Debugf("Found %d asset burns not in burn table, adding them now",
		len(burnAssetsNotInTable))
	for _, burnAsset := range burnAssetsNotInTable {
		assetTransfers, err := q.QueryAssetTransfers(ctx, TransferQuery{
			AnchorTxHash: fn.ByteSlice(burnAsset.AnchorTx.TxHash()),
		})
		if err != nil {
			return fmt.Errorf("unable to query asset transfers: %w",
				err)
		}
		if len(assetTransfers) != 1 {
			log.Warnf("Found %d asset transfers for burn asset "+
				"%s, expected 1: %v", len(assetTransfers),
				burnAsset.ID(), assetTransfers)

			continue
		}
		assetTransfer := assetTransfers[0]

		var groupKeyBytes []byte
		if burnAsset.GroupKey != nil {
			gk := burnAsset.GroupKey.GroupPubKey
			groupKeyBytes = gk.SerializeCompressed()
		}

		_, err = q.InsertBurn(ctx, sqlc.InsertBurnParams{
			TransferID: assetTransfer.ID,
			AssetID:    fn.ByteSlice(burnAsset.ID()),
			GroupKey:   groupKeyBytes,
			Amount:     int64(burnAsset.Amount),
		})
		if err != nil {
			return fmt.Errorf("error inserting burn: %w", err)
		}
	}

	return nil
}
