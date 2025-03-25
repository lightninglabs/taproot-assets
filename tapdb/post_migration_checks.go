package tapdb

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/tapscript"
	"github.com/lightningnetwork/lnd/clock"
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
		31: detectScriptKeyType,
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

// detectScriptKeyType attempts to detect the type of the script keys that don't
// have a type set yet.
func detectScriptKeyType(ctx context.Context, q sqlc.Querier) error {
	defaultClock := clock.NewDefaultClock()

	log.Debugf("Detecting script key types")

	// We start by fetching all assets, even the spent ones. We then collect
	// a list of the burn keys from the assets (because burn keys can only
	// be calculated from the asset's witness).
	assetFilter := QueryAssetFilters{
		Now: sql.NullTime{
			Time:  defaultClock.Now().UTC(),
			Valid: true,
		},
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

		serializedKey := asset.ToSerialized(scriptKey.PubKey)
		newType := asset.ScriptKeyUnknown

		if _, ok := burnKeys[serializedKey]; ok {
			newType = asset.ScriptKeyBurn
		} else {
			guessedType := scriptKey.GuessType()

			// If we're sure that a key is BIP-86, we mark it as
			// such.
			if guessedType == asset.ScriptKeyBip86 {
				newType = asset.ScriptKeyBip86
			}

			switch {
			// Previous channel funding script keys (OP_TRUE) can
			// be detected, since they are the same key. New, unique
			// script keys for grouped asset channels are only
			// introduced with the same version as this migration
			// ships in, so they should be stored with the correct
			// type already.
			case guessedType == asset.ScriptKeyScriptPathExternal &&
				scriptKey.PubKey.IsEqual(channelFundingKey):

				newType = asset.ScriptKeyScriptPathChannel

			// We'll want to not show scripted keys by default in
			// the balances. So any key that is not a burn key and
			// not a channel funding key, but has a script path, we
			// mark as external script path.
			case guessedType == asset.ScriptKeyScriptPathExternal:
				newType = asset.ScriptKeyScriptPathExternal
			}
		}

		// If we were able to identify the key type, we update the key
		// in the database.
		if newType != asset.ScriptKeyUnknown {
			_, err := q.UpsertScriptKey(ctx, NewScriptKey{
				InternalKeyID:    k.InternalKey.KeyID,
				TweakedScriptKey: k.ScriptKey.TweakedScriptKey,
				Tweak:            k.ScriptKey.Tweak,
				DeclaredKnown:    k.ScriptKey.DeclaredKnown,
				KeyType:          sqlInt16(newType),
			})
			if err != nil {
				return fmt.Errorf("error updating script key "+
					"type: %w", err)
			}
		}
	}

	return nil
}
