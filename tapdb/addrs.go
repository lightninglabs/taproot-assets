package tapdb

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"net/url"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightningnetwork/lnd/clock"
	"github.com/lightningnetwork/lnd/keychain"
)

type (
	// AddrQuery as a type alias for a query into the set of known
	// addresses.
	AddrQuery = sqlc.FetchAddrsParams

	// NewAddr is a type alias for the params to create a new address.
	NewAddr = sqlc.UpsertAddrParams

	// Addresses is a type alias for the full address row with key locator
	// information.
	Addresses = sqlc.FetchAddrsRow

	// SingleAddrQuery is a type alias for returning an address by its
	// Taproot output key, x-only script key or version (or a combination of
	// those).
	SingleAddrQuery = sqlc.QueryAddrParams

	// SingleAddrRow is a type alias for returning an address by either its
	// Taproot output key, x-only script key or version (or a combination
	// of those).
	SingleAddrRow = sqlc.QueryAddrRow

	// AddrManaged is a type alias for setting an address as managed.
	AddrManaged = sqlc.SetAddrManagedParams

	// UpsertAddrEvent is a type alias for creating a new address event or
	// updating an existing one.
	UpsertAddrEvent = sqlc.UpsertAddrEventParams

	// UpsertAddrEventOutput is a type alias for creating a new address
	// event output or updating an existing one.
	UpsertAddrEventOutput = sqlc.UpsertAddrEventOutputParams

	// UpsertAddrEventProof is a type alias for creating a new address
	// event proof or updating an existing one.
	UpsertAddrEventProof = sqlc.UpsertAddrEventProofParams

	// AddrEvent is a type alias for fetching an address event row.
	AddrEvent = sqlc.FetchAddrEventRow

	// AddrEventOutput is a type alias for fetching the outputs of an
	// address event.
	AddrEventOutput = sqlc.FetchAddrEventOutputsRow

	// AddrEventProof is a type alias for fetching the proofs of an address
	// event.
	AddrEventProof = sqlc.FetchAddrEventProofsRow

	// FetchAddrEventByOutpoint is a type alias for the params to fetch an
	// address event by address and outpoint.
	FetchAddrEventByOutpoint = sqlc.FetchAddrEventByAddrKeyAndOutpointParams

	// AddrEventByOutpoint is a type alias for fetching an address event
	// row by outpoint.
	AddrEventByOutpoint = sqlc.FetchAddrEventByAddrKeyAndOutpointRow

	// AddrEventQuery is a type alias for a query into the set of known
	// address events.
	AddrEventQuery = sqlc.QueryEventIDsParams

	// AddrEventID is a type alias for fetching the ID of an address event
	// and its corresponding address.
	AddrEventID = sqlc.QueryEventIDsRow

	// Genesis is a type alias for fetching the genesis asset information.
	Genesis = sqlc.FetchGenesisByIDRow

	// ScriptKey is a type alias for fetching the script key information.
	ScriptKey = sqlc.FetchScriptKeyByTweakedKeyRow

	// KeyLocator is a type alias for fetching the key locator information
	// for an internal key.
	KeyLocator = sqlc.FetchInternalKeyLocatorRow

	// AssetMeta is the metadata record for an asset.
	AssetMeta = sqlc.FetchAssetMetaForAssetRow

	// AllAssetMetaRow is a type alias for fetching all asset metadata
	// records.
	AllAssetMetaRow = sqlc.FetchAllAssetMetaRow
)

var (
	// ErrConflictingAddress is returned when an address (with the same
	// output key) already exists in the database and we're attempting to
	// re-insert it but at least one of the fields (except creation_time)
	// is different.
	ErrConflictingAddress = errors.New("failed to add conflicting address")
)

// AddrBook is an interface that represents the storage backed needed to create
// the TapAddressBook book. We need to be able to insert/fetch addresses, and
// also make internal keys since each address has an internal key and a script
// key (tho they can be the same).
type AddrBook interface {
	// UpsertAssetStore houses the methods related to inserting/updating
	// assets.
	UpsertAssetStore

	// GroupStore houses the methods related to fetching genesis assets and
	// asset groups related to them.
	GroupStore

	// FetchScriptKeyStore houses the methods related to fetching all
	// information about a script key.
	FetchScriptKeyStore

	// FetchAddrs returns all the addresses based on the constraints of the
	// passed AddrQuery.
	FetchAddrs(ctx context.Context, arg AddrQuery) ([]Addresses, error)

	// QueryAddr returns a single address based on its Taproot output key,
	// its x-only script key or version, or a sql.ErrNoRows error if no such
	// address exists.
	QueryAddr(ctx context.Context, arg SingleAddrQuery) (SingleAddrRow,
		error)

	// UpsertAddr upserts a new address into the database returning the
	// primary key.
	UpsertAddr(ctx context.Context, arg NewAddr) (int64, error)

	// UpsertInternalKey inserts a new or updates an existing internal key
	// into the database and returns the primary key.
	UpsertInternalKey(ctx context.Context, arg InternalKey) (int64, error)

	// UpsertScriptKey inserts a new script key on disk into the DB.
	UpsertScriptKey(context.Context, NewScriptKey) (int64, error)

	// SetAddrManaged sets an address as being managed by the internal
	// wallet.
	SetAddrManaged(ctx context.Context, arg AddrManaged) error

	// UpsertManagedUTXO inserts a new or updates an existing managed UTXO
	// to disk and returns the primary key.
	UpsertManagedUTXO(ctx context.Context, arg RawManagedUTXO) (int64,
		error)

	// UpsertChainTx inserts a new or updates an existing chain tx into the
	// DB.
	UpsertChainTx(ctx context.Context, arg ChainTxParams) (int64, error)

	// UpsertAddrEvent inserts a new or updates an existing address event
	// and returns the primary key.
	UpsertAddrEvent(ctx context.Context, arg UpsertAddrEvent) (int64, error)

	// UpsertAddrEventOutput inserts a new or updates an existing address
	// event output and returns the primary key.
	UpsertAddrEventOutput(ctx context.Context,
		arg UpsertAddrEventOutput) (int64, error)

	// UpsertAddrEventProof inserts a new or updates an existing address
	// event proof and returns the primary key.
	UpsertAddrEventProof(ctx context.Context,
		arg UpsertAddrEventProof) (int64, error)

	// FetchAddrEvent returns a single address event based on its primary
	// key.
	FetchAddrEvent(ctx context.Context, id int64) (AddrEvent, error)

	// FetchAddrEventOutputs returns the outputs of an address event.
	FetchAddrEventOutputs(ctx context.Context,
		addrEventID int64) ([]AddrEventOutput, error)

	// FetchAddrEventProofs returns the proofs of an address event.
	FetchAddrEventProofs(ctx context.Context,
		addrEventID int64) ([]AddrEventProof, error)

	// FetchAddrEventByAddrKeyAndOutpoint returns a single address event
	// based on its address Taproot output key and outpoint.
	FetchAddrEventByAddrKeyAndOutpoint(ctx context.Context,
		arg FetchAddrEventByOutpoint) (AddrEventByOutpoint, error)

	// QueryEventIDs returns a list of event IDs and their corresponding
	// address IDs that match the given query parameters.
	QueryEventIDs(ctx context.Context, query AddrEventQuery) ([]AddrEventID,
		error)

	// FetchAssetProof fetches the asset proof for a given asset identified
	// by its script key.
	FetchAssetProof(ctx context.Context,
		arg FetchAssetProof) ([]AssetProofI, error)

	// FetchGenesisByAssetID attempts to fetch asset genesis information
	// for a given asset ID.
	FetchGenesisByAssetID(ctx context.Context,
		assetID []byte) (sqlc.GenesisInfoView, error)

	// FetchGenesisByGroupKey attempts to fetch asset genesis information
	// for a given group key.
	FetchGenesisByGroupKey(ctx context.Context,
		tweakedGroupKey []byte) (sqlc.GenesisInfoView, error)

	// FetchInternalKeyLocator fetches the key locator for an internal key.
	FetchInternalKeyLocator(ctx context.Context, rawKey []byte) (KeyLocator,
		error)

	// FetchAssetMetaByHash fetches the asset meta for a given meta hash.
	FetchAssetMetaByHash(ctx context.Context,
		metaDataHash []byte) (sqlc.FetchAssetMetaByHashRow, error)

	// FetchAssetMetaForAsset fetches the asset meta for a given asset.
	FetchAssetMetaForAsset(ctx context.Context,
		assetID []byte) (AssetMeta, error)

	// FetchAllAssetMeta fetches all asset metadata records from the
	// database.
	FetchAllAssetMeta(ctx context.Context) ([]AllAssetMetaRow, error)

	// QueryLastEventHeight queries the last event height for a given
	// address version.
	QueryLastEventHeight(ctx context.Context,
		version int16) (int64, error)
}

// AddrBookTxOptions defines the set of db txn options the AddrBook
// understands.
type AddrBookTxOptions struct {
	// readOnly governs if a read only transaction is needed or not.
	readOnly bool
}

// ReadOnly returns true if the transaction should be read only.
//
// NOTE: This implements the TxOptions
func (a *AddrBookTxOptions) ReadOnly() bool {
	return a.readOnly
}

// NewAddrBookReadTx creates a new read transaction option set.
func NewAddrBookReadTx() AssetStoreTxOptions {
	return AssetStoreTxOptions{
		readOnly: true,
	}
}

// BatchedAddrBook is a version of the AddrBook that's capable of batched
// database operations.
type BatchedAddrBook interface {
	AddrBook

	BatchedTx[AddrBook]
}

// TapAddressBook represents a storage backend for all the Taproot Asset
// addresses a daemon has created.
type TapAddressBook struct {
	db     BatchedAddrBook
	params *address.ChainParams
	clock  clock.Clock
}

// NewTapAddressBook creates a new TapAddressBook instance given a open
// BatchedAddrBook storage backend.
func NewTapAddressBook(db BatchedAddrBook, params *address.ChainParams,
	clock clock.Clock) *TapAddressBook {

	return &TapAddressBook{
		db:     db,
		params: params,
		clock:  clock,
	}
}

// insertInternalKey inserts a new internal key into the DB and returns the
// primary key of the internal key.
func insertInternalKey(ctx context.Context, a AddrBook,
	desc keychain.KeyDescriptor) (int64, error) {

	return a.UpsertInternalKey(ctx, InternalKey{
		RawKey:    desc.PubKey.SerializeCompressed(),
		KeyFamily: int32(desc.Family),
		KeyIndex:  int32(desc.Index),
	})
}

// InsertAddrs inserts a new address into the database.
func (t *TapAddressBook) InsertAddrs(ctx context.Context,
	addrs ...address.AddrWithKeyInfo) error {

	var writeTxOpts AddrBookTxOptions
	return t.db.ExecTx(ctx, &writeTxOpts, func(db AddrBook) error {
		// For each of the addresses listed, we'll insert the two new
		// internal keys, then use those returned primary key IDs to
		// returned to insert the address itself.
		for idx := range addrs {
			// The asset genesis should already be known at this
			// point, so we'll just fetch it so we can obtain the
			// genAssetID.
			addr := addrs[idx]

			// If this is an address for a grouped asset, then we
			// need to fetch the genesis from the group key.
			// TODO(guggero): We should use an asset specifier in
			// the address and remove the need for the embedded
			// genesis struct. Then we can have a
			// QueryAssetBySpecifier method that we can use here.
			var (
				assetGen sqlc.GenesisInfoView
				err      error
			)
			switch {
			case addr.GroupKey != nil && addr.AssetID == asset.ID{}:
				gkBytes := addr.GroupKey.SerializeCompressed()
				assetGen, err = db.FetchGenesisByGroupKey(
					ctx, gkBytes,
				)
			default:
				assetGen, err = db.FetchGenesisByAssetID(
					ctx, addr.AssetID[:],
				)
			}
			if err != nil {
				return err
			}

			genAssetID := assetGen.GenAssetID

			rawScriptKeyID, err := insertInternalKey(
				ctx, db, addr.ScriptKeyTweak.RawKey,
			)
			if err != nil {
				return fmt.Errorf("unable to insert internal "+
					"script key: %w", err)
			}
			scriptKeyID, err := db.UpsertScriptKey(ctx, NewScriptKey{
				InternalKeyID:    rawScriptKeyID,
				TweakedScriptKey: addr.ScriptKey.SerializeCompressed(),
				Tweak:            addr.ScriptKeyTweak.Tweak,
				KeyType: sqlInt16(
					addr.ScriptKeyTweak.Type,
				),
			})
			if err != nil {
				return fmt.Errorf("unable to insert script "+
					"key: %w", err)
			}

			taprootKeyID, err := insertInternalKey(
				ctx, db, addr.InternalKeyDesc,
			)
			if err != nil {
				return fmt.Errorf("unable to insert internal "+
					"taproot key: %w", err)
			}

			siblingBytes, _, err := commitment.MaybeEncodeTapscriptPreimage(
				addr.TapscriptSibling,
			)
			if err != nil {
				return fmt.Errorf("unable to encode tapscript "+
					"sibling: %w", err)
			}

			var groupKeyBytes []byte
			if addr.GroupKey != nil {
				groupKeyBytes = addr.GroupKey.SerializeCompressed()
			}

			proofCourierAddrBytes := []byte(
				addr.Tap.ProofCourierAddr.String(),
			)

			_, err = db.UpsertAddr(ctx, NewAddr{
				Version:          int16(addr.Version),
				AssetVersion:     int16(addr.AssetVersion),
				GenesisAssetID:   genAssetID,
				GroupKey:         groupKeyBytes,
				ScriptKeyID:      scriptKeyID,
				TaprootKeyID:     taprootKeyID,
				TapscriptSibling: siblingBytes,
				TaprootOutputKey: schnorr.SerializePubKey(
					&addr.TaprootOutputKey,
				),
				Amount:           int64(addr.Amount),
				AssetType:        assetGen.AssetType,
				CreationTime:     addr.CreationTime.UTC(),
				ProofCourierAddr: proofCourierAddrBytes,
			})
			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return ErrConflictingAddress
				}

				return fmt.Errorf("unable to insert addr: %w",
					err)
			}
		}

		return nil
	})
}

// QueryAddrs attempts to query for the set of addresses on disk given the
// passed set of query params.
func (t *TapAddressBook) QueryAddrs(ctx context.Context,
	params address.QueryParams) ([]address.AddrWithKeyInfo, error) {

	var addrs []address.AddrWithKeyInfo

	// If the created before time is zero, then we'll use a very large date
	// to ensure that we don't restrict based on this field.
	if params.CreatedBefore.IsZero() {
		params.CreatedBefore = MaxValidSQLTime
	}

	// Similarly, for sqlite using LIMIT with a value of -1 means no rows
	// should be limited. But that is not compatible with Postgres which
	// either wants NULL or the ALL keyword. So the most portable thing we
	// can do to _not_ limit the number of records is to use the int32 max
	// value (which works for both systems).
	limit := int32(math.MaxInt32)
	if params.Limit != 0 {
		limit = params.Limit
	}

	readOpts := NewAddrBookReadTx()
	err := t.db.ExecTx(ctx, &readOpts, func(db AddrBook) error {
		// First, fetch the set of addresses based on the set of query
		// parameters.
		dbAddrs, err := db.FetchAddrs(ctx, AddrQuery{
			CreatedAfter:  params.CreatedAfter.UTC(),
			CreatedBefore: params.CreatedBefore.UTC(),
			NumOffset:     params.Offset,
			NumLimit:      limit,
			UnmanagedOnly: params.UnmanagedOnly,
		})
		if err != nil {
			return err
		}

		// Next, we'll need to map each of the addresses into an
		// AddrWithKeyInfo struct that can be used in a general
		// context.
		for _, addr := range dbAddrs {
			assetGenesis, err := fetchGenesis(
				ctx, db, addr.GenesisAssetID,
			)
			if err != nil {
				return fmt.Errorf("error fetching genesis: %w",
					err)
			}

			var (
				groupKey     *btcec.PublicKey
				groupWitness wire.TxWitness
			)

			if addr.GroupKey != nil {
				groupKey, err = btcec.ParsePubKey(addr.GroupKey)
				if err != nil {
					return fmt.Errorf("unable to decode "+
						"group key: %w", err)
				}

				group, err := db.FetchGroupByGenesis(
					ctx, addr.GenesisAssetID,
				)
				if err != nil {
					return fmt.Errorf("unable to locate"+
						"group sig: %w", err)
				}

				groupWitness, err = asset.ParseGroupWitness(
					group.WitnessStack,
				)
				if err != nil {
					return fmt.Errorf("unable to decode"+
						"group sig: %w", err)
				}
			}

			scriptKey, err := parseScriptKey(
				addr.InternalKey, addr.ScriptKey,
			)
			if err != nil {
				return fmt.Errorf("unable to decode "+
					"script key: %w", err)
			}

			internalKey, err := btcec.ParsePubKey(addr.RawTaprootKey)
			if err != nil {
				return fmt.Errorf("unable to decode "+
					"taproot key: %w", err)
			}
			internalKeyDesc := keychain.KeyDescriptor{
				KeyLocator: keychain.KeyLocator{
					Family: keychain.KeyFamily(
						addr.TaprootKeyFamily,
					),
					Index: uint32(addr.TaprootKeyIndex),
				},
				PubKey: internalKey,
			}

			taprootOutputKey, err := schnorr.ParsePubKey(
				addr.TaprootOutputKey,
			)
			if err != nil {
				return fmt.Errorf("unable to parse taproot "+
					"output key: %w", err)
			}

			tapscriptSibling, _, err := commitment.MaybeDecodeTapscriptPreimage(
				addr.TapscriptSibling,
			)
			if err != nil {
				return fmt.Errorf("unable to decode tapscript "+
					"sibling: %w", err)
			}

			proofCourierAddr, err := url.ParseRequestURI(
				string(addr.ProofCourierAddr),
			)
			if err != nil {
				return fmt.Errorf("unable to parse proof "+
					"courier address: %w", err)
			}

			tapAddr, err := address.New(
				address.Version(addr.Version), assetGenesis,
				groupKey, groupWitness, *scriptKey.PubKey,
				*internalKey, uint64(addr.Amount),
				tapscriptSibling, t.params, *proofCourierAddr,
				address.WithAssetVersion(
					asset.Version(addr.AssetVersion),
				),
			)
			if err != nil {
				return fmt.Errorf("unable to make addr: %w", err)
			}

			addrs = append(addrs, address.AddrWithKeyInfo{
				Tap:              tapAddr,
				ScriptKeyTweak:   *scriptKey.TweakedScriptKey,
				InternalKeyDesc:  internalKeyDesc,
				TaprootOutputKey: *taprootOutputKey,
				CreationTime:     addr.CreationTime.UTC(),
				ManagedAfter:     addr.ManagedFrom.Time.UTC(),
			})
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return addrs, nil
}

// AddrByTaprootOutput returns a single address based on its Taproot output
// key or a sql.ErrNoRows error if no such address exists.
func (t *TapAddressBook) AddrByTaprootOutput(ctx context.Context,
	key *btcec.PublicKey) (*address.AddrWithKeyInfo, error) {

	var (
		addr     *address.AddrWithKeyInfo
		readOpts = NewAddrBookReadTx()
	)
	err := t.db.ExecTx(ctx, &readOpts, func(db AddrBook) error {
		row, err := db.QueryAddr(ctx, SingleAddrQuery{
			TaprootOutputKey: schnorr.SerializePubKey(key),
		})
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return address.ErrNoAddr

		case err != nil:
			return err
		}

		addr, err = parseAddr(
			ctx, db, t.params, row.Addr, row.ScriptKey,
			row.InternalKey, row.InternalKey_2,
		)
		return err
	})
	if err != nil {
		return nil, err
	}

	return addr, nil
}

// AddrByScriptKeyAndVersion returns a single address based on its script key
// and version or a sql.ErrNoRows error if no such address exists.
func (t *TapAddressBook) AddrByScriptKeyAndVersion(ctx context.Context,
	scriptKey *btcec.PublicKey,
	version address.Version) (*address.AddrWithKeyInfo, error) {

	var (
		addr     *address.AddrWithKeyInfo
		readOpts = NewAddrBookReadTx()
	)
	err := t.db.ExecTx(ctx, &readOpts, func(db AddrBook) error {
		row, err := db.QueryAddr(ctx, SingleAddrQuery{
			XOnlyScriptKey: schnorr.SerializePubKey(scriptKey),
			Version:        sqlInt16(version),
		})
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return address.ErrNoAddr

		case err != nil:
			return err
		}

		addr, err = parseAddr(
			ctx, db, t.params, row.Addr, row.ScriptKey,
			row.InternalKey, row.InternalKey_2,
		)
		return err
	})
	if err != nil {
		return nil, err
	}

	return addr, nil
}

// fetchAddr fetches a single address identified by its taproot output key from
// the database and populates all its fields.
func parseAddr(ctx context.Context, db AddrBook, params *address.ChainParams,
	dbAddr sqlc.Addr, dbScriptKey sqlc.ScriptKey, dbInternalKey,
	dbTaprootKey sqlc.InternalKey) (*address.AddrWithKeyInfo, error) {

	genesis, err := fetchGenesis(ctx, db, dbAddr.GenesisAssetID)
	if err != nil {
		return nil, fmt.Errorf("error fetching genesis: %w", err)
	}

	var (
		groupKey     *btcec.PublicKey
		groupWitness wire.TxWitness
	)

	if dbAddr.GroupKey != nil {
		groupKey, err = btcec.ParsePubKey(dbAddr.GroupKey)
		if err != nil {
			return nil, fmt.Errorf("unable to decode group key: %w",
				err)
		}

		group, err := db.FetchGroupByGenesis(ctx, dbAddr.GenesisAssetID)
		if err != nil {
			return nil, fmt.Errorf("unable to locate group sig: %w",
				err)
		}

		groupWitness, err = asset.ParseGroupWitness(group.WitnessStack)
		if err != nil {
			return nil, fmt.Errorf("unable to decode group sig: %w",
				err)
		}
	}

	scriptKey, err := parseScriptKey(dbInternalKey, dbScriptKey)
	if err != nil {
		return nil, fmt.Errorf("unable to decode script key: %w", err)
	}

	internalKey, err := btcec.ParsePubKey(dbTaprootKey.RawKey)
	if err != nil {
		return nil, fmt.Errorf("unable to decode taproot key: %w", err)
	}
	internalKeyDesc := keychain.KeyDescriptor{
		KeyLocator: keychain.KeyLocator{
			Family: keychain.KeyFamily(
				dbTaprootKey.KeyFamily,
			),
			Index: uint32(dbTaprootKey.KeyIndex),
		},
		PubKey: internalKey,
	}

	tapscriptSibling, _, err := commitment.MaybeDecodeTapscriptPreimage(
		dbAddr.TapscriptSibling,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to decode tapscript sibling: %w",
			err)
	}

	proofCourierAddr, err := url.ParseRequestURI(
		string(dbAddr.ProofCourierAddr),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to parse proof courier "+
			"address: %w", err)
	}

	tapAddr, err := address.New(
		address.Version(dbAddr.Version), genesis, groupKey,
		groupWitness, *scriptKey.PubKey, *internalKey,
		uint64(dbAddr.Amount), tapscriptSibling, params,
		*proofCourierAddr,
		address.WithAssetVersion(asset.Version(dbAddr.AssetVersion)),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to make addr: %w", err)
	}

	taprootOutputKey, err := tapAddr.TaprootOutputKey()
	if err != nil {
		return nil, fmt.Errorf("unable to get taproot output key: %w",
			err)
	}

	return &address.AddrWithKeyInfo{
		Tap:              tapAddr,
		ScriptKeyTweak:   *scriptKey.TweakedScriptKey,
		InternalKeyDesc:  internalKeyDesc,
		TaprootOutputKey: *taprootOutputKey,
		CreationTime:     dbAddr.CreationTime.UTC(),
	}, nil
}

// SetAddrManaged sets an address as being managed by the internal
// wallet.
func (t *TapAddressBook) SetAddrManaged(ctx context.Context,
	addr *address.AddrWithKeyInfo, managedFrom time.Time) error {

	var writeTxOpts AddrBookTxOptions
	return t.db.ExecTx(ctx, &writeTxOpts, func(db AddrBook) error {
		return db.SetAddrManaged(ctx, AddrManaged{
			ManagedFrom: sql.NullTime{
				Time:  managedFrom.UTC(),
				Valid: true,
			},
			TaprootOutputKey: schnorr.SerializePubKey(
				&addr.TaprootOutputKey,
			),
		})
	})
}

// InsertInternalKey inserts an internal key into the database to make sure it
// is identified as a local key later on when importing proofs. The key can be
// an internal key for an asset script key or the internal key of an anchor
// output.
func (t *TapAddressBook) InsertInternalKey(ctx context.Context,
	keyDesc keychain.KeyDescriptor) error {

	var writeTxOpts AddrBookTxOptions
	return t.db.ExecTx(ctx, &writeTxOpts, func(q AddrBook) error {
		_, err := insertInternalKey(
			ctx, q, keyDesc,
		)
		if err != nil {
			return fmt.Errorf("error inserting internal key: %w",
				err)
		}

		return nil
	})
}

// InsertScriptKey inserts an address related script key into the database, so
// it can be recognized as belonging to the wallet when a transfer comes in
// later on.
func (t *TapAddressBook) InsertScriptKey(ctx context.Context,
	scriptKey asset.ScriptKey, keyType asset.ScriptKeyType) error {

	var writeTxOpts AddrBookTxOptions
	return t.db.ExecTx(ctx, &writeTxOpts, func(q AddrBook) error {
		internalKeyID, err := insertInternalKey(
			ctx, q, scriptKey.RawKey,
		)
		if err != nil {
			return fmt.Errorf("error inserting internal key: %w",
				err)
		}

		_, err = q.UpsertScriptKey(ctx, NewScriptKey{
			InternalKeyID:    internalKeyID,
			TweakedScriptKey: scriptKey.PubKey.SerializeCompressed(),
			Tweak:            scriptKey.Tweak,
			KeyType:          sqlInt16(keyType),
		})
		return err
	})
}

// GetOrCreateEvent creates a new address event for the given status, address
// and transaction. If an event for that address and transaction already exists,
// then the status and transaction information is updated instead.
func (t *TapAddressBook) GetOrCreateEvent(ctx context.Context,
	status address.Status, xfer address.IncomingTransfer) (*address.Event,
	error) {

	var (
		writeTxOpts AddrBookTxOptions
		event       *address.Event
		txHash      = xfer.Tx.TxHash()
	)
	txBytes, err := fn.Serialize(xfer.Tx)
	if err != nil {
		return nil, fmt.Errorf("error serializing tx: %w", err)
	}
	outpoint := wire.OutPoint{
		Hash:  txHash,
		Index: xfer.OutputIdx,
	}
	outpointBytes, err := encodeOutpoint(outpoint)
	if err != nil {
		return nil, fmt.Errorf("error encoding outpoint: %w", err)
	}
	txOut := xfer.Tx.TxOut[xfer.OutputIdx]

	siblingBytes, siblingHash, err := commitment.MaybeEncodeTapscriptPreimage(
		xfer.Addr.TapscriptSibling,
	)
	if err != nil {
		return nil, fmt.Errorf("error encoding tapscript sibling: %w",
			err)
	}

	dbErr := t.db.ExecTx(ctx, &writeTxOpts, func(db AddrBook) error {
		// The first step is to make sure we already track the on-chain
		// transaction in our DB.
		txUpsert := ChainTxParams{
			Txid:  txHash[:],
			RawTx: txBytes,
		}
		if xfer.BlockHeight > 0 && xfer.BlockHash != nil {
			txUpsert.BlockHeight = sqlInt32(xfer.BlockHeight)
			txUpsert.BlockHash = xfer.BlockHash[:]
		}
		chainTxID, err := db.UpsertChainTx(ctx, txUpsert)
		if err != nil {
			return fmt.Errorf("error upserting chain TX: %w", err)
		}

		merkleRoot := xfer.TaprootAssetRoot
		if siblingHash != nil {
			merkleRoot = asset.TapBranchHash(
				xfer.TaprootAssetRoot, *siblingHash,
			)
		}

		internalKey := xfer.Addr.InternalKey
		utxoUpsert := RawManagedUTXO{
			RawKey:           internalKey.SerializeCompressed(),
			Outpoint:         outpointBytes,
			AmtSats:          txOut.Value,
			TaprootAssetRoot: xfer.TaprootAssetRoot[:],
			RootVersion:      sqlInt16(xfer.CommitmentVersion),
			MerkleRoot:       merkleRoot[:],
			TapscriptSibling: siblingBytes,
			TxnID:            chainTxID,
		}
		managedUtxoID, err := db.UpsertManagedUTXO(ctx, utxoUpsert)
		if err != nil {
			return fmt.Errorf("error upserting utxo: %w", err)
		}

		eventID, err := db.UpsertAddrEvent(ctx, UpsertAddrEvent{
			TaprootOutputKey: schnorr.SerializePubKey(
				&xfer.Addr.TaprootOutputKey,
			),
			CreationTime:        t.clock.Now().UTC(),
			Status:              int16(status),
			Txid:                txHash[:],
			ChainTxnOutputIndex: int32(xfer.OutputIdx),
			ManagedUtxoID:       managedUtxoID,
		})
		if err != nil {
			return fmt.Errorf("error fetching existing events: %w",
				err)
		}

		// Upsert the address event outputs.
		for assetID, output := range xfer.Outputs {
			scriptKey := output.ScriptKey
			scriptKeyBytes := scriptKey.PubKey.SerializeCompressed()
			internalKeyID, err := insertInternalKey(
				ctx, db, scriptKey.RawKey,
			)
			if err != nil {
				return fmt.Errorf("error inserting internal "+
					"key: %w", err)
			}

			scriptKeyID, err := db.UpsertScriptKey(
				ctx, NewScriptKey{
					InternalKeyID:    internalKeyID,
					TweakedScriptKey: scriptKeyBytes,
					Tweak:            scriptKey.Tweak,
					KeyType: sqlInt16(
						scriptKey.Type,
					),
				},
			)
			if err != nil {
				return fmt.Errorf("error upserting script "+
					"key: %w", err)
			}

			_, err = db.UpsertAddrEventOutput(
				ctx, UpsertAddrEventOutput{
					AddrEventID: eventID,
					Amount:      int64(output.Amount),
					AssetID:     assetID[:],
					ScriptKeyID: scriptKeyID,
				},
			)
			if err != nil {
				return fmt.Errorf("error upserting address "+
					"event output: %w", err)
			}
		}

		event, err = fetchEvent(ctx, db, eventID, xfer.Addr)
		return err
	})
	if dbErr != nil {
		return nil, dbErr
	}

	return event, nil
}

// QueryEvent returns a single address event by its address and outpoint.
func (t *TapAddressBook) QueryEvent(ctx context.Context,
	addr *address.AddrWithKeyInfo, outpoint wire.OutPoint) (*address.Event,
	error) {

	var (
		readTxOpts = NewAssetStoreReadTx()
		event      *address.Event
	)
	dbErr := t.db.ExecTx(ctx, &readTxOpts, func(db AddrBook) error {
		var err error
		event, err = fetchEventByOutpoint(ctx, db, addr, outpoint)
		return err
	})
	switch {
	case errors.Is(dbErr, sql.ErrNoRows):
		return nil, address.ErrNoEvent

	case dbErr != nil:
		return nil, dbErr
	}

	return event, nil
}

// QueryAddrEvents returns a list of event that match the given query
// parameters.
func (t *TapAddressBook) QueryAddrEvents(
	ctx context.Context, params address.EventQueryParams) ([]*address.Event,
	error) {

	sqlQuery := AddrEventQuery{
		StatusFrom:   int16(address.StatusTransactionDetected),
		StatusTo:     int16(address.StatusCompleted),
		CreatedAfter: time.Unix(0, 0).UTC(),
	}
	if len(params.AddrTaprootOutputKey) > 0 {
		sqlQuery.AddrTaprootKey = params.AddrTaprootOutputKey
	}
	if params.StatusFrom != nil {
		sqlQuery.StatusFrom = int16(*params.StatusFrom)
	}
	if params.StatusTo != nil {
		sqlQuery.StatusTo = int16(*params.StatusTo)
	}
	if params.CreationTimeFrom != nil && !params.CreationTimeFrom.IsZero() {
		sqlQuery.CreatedAfter = params.CreationTimeFrom.UTC()
	}

	var (
		readTxOpts = NewAssetStoreReadTx()
		events     []*address.Event
	)
	err := t.db.ExecTx(ctx, &readTxOpts, func(db AddrBook) error {
		dbIDs, err := db.QueryEventIDs(ctx, sqlQuery)
		if err != nil {
			return fmt.Errorf("error fetching event IDs: %w", err)
		}

		events = make([]*address.Event, len(dbIDs))
		for idx, ids := range dbIDs {
			taprootOutputKey, err := schnorr.ParsePubKey(
				ids.TaprootOutputKey,
			)
			if err != nil {
				return fmt.Errorf("error parsing taproot "+
					"output key: %w", err)
			}

			row, err := db.QueryAddr(ctx, SingleAddrQuery{
				TaprootOutputKey: schnorr.SerializePubKey(
					taprootOutputKey,
				),
			})
			switch {
			case errors.Is(err, sql.ErrNoRows):
				return address.ErrNoAddr

			case err != nil:
				return err
			}

			addr, err := parseAddr(
				ctx, db, t.params, row.Addr, row.ScriptKey,
				row.InternalKey, row.InternalKey_2,
			)
			if err != nil {
				return fmt.Errorf("error parsing address: %w",
					err)
			}

			event, err := fetchEvent(ctx, db, ids.EventID, addr)
			if err != nil {
				return fmt.Errorf("error fetching address "+
					"event: %w", err)
			}

			events[idx] = event
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return events, nil
}

// fetchEvent fetches a single address event identified by its primary ID and
// address.
func fetchEvent(ctx context.Context, db AddrBook, eventID int64,
	addr *address.AddrWithKeyInfo) (*address.Event, error) {

	dbEvent, err := db.FetchAddrEvent(ctx, eventID)
	if err != nil {
		return nil, fmt.Errorf("error fetching addr event: %w", err)
	}

	internalKey, err := btcec.ParsePubKey(dbEvent.InternalKey)
	if err != nil {
		return nil, fmt.Errorf("error parsing internal key: %w", err)
	}

	hash, err := chainhash.NewHash(dbEvent.Txid)
	if err != nil {
		return nil, fmt.Errorf("error parsing txid: %w", err)
	}
	op := wire.OutPoint{
		Hash:  *hash,
		Index: uint32(dbEvent.OutputIndex),
	}

	outputs, err := fetchEventOutputs(ctx, db, eventID)
	if err != nil {
		return nil, fmt.Errorf("error fetching event outputs: %w", err)
	}

	return &address.Event{
		ID:                 eventID,
		CreationTime:       dbEvent.CreationTime.UTC(),
		Addr:               addr,
		Status:             address.Status(dbEvent.Status),
		Outpoint:           op,
		Amt:                btcutil.Amount(dbEvent.AmtSats.Int64),
		InternalKey:        internalKey,
		ConfirmationHeight: uint32(dbEvent.ConfirmationHeight.Int32),
		Outputs:            outputs,
		HasAllProofs:       dbEvent.NumProofs == int64(len(outputs)),
	}, nil
}

// fetchEventByOutpoint fetches a single address event identified by its address
// and outpoint.
func fetchEventByOutpoint(ctx context.Context, db AddrBook,
	addr *address.AddrWithKeyInfo, outpoint wire.OutPoint) (*address.Event,
	error) {

	dbEvent, err := db.FetchAddrEventByAddrKeyAndOutpoint(
		ctx, FetchAddrEventByOutpoint{
			TaprootOutputKey: schnorr.SerializePubKey(
				&addr.TaprootOutputKey,
			),
			Txid:                outpoint.Hash[:],
			ChainTxnOutputIndex: int32(outpoint.Index),
		},
	)
	if err != nil {
		return nil, fmt.Errorf("error fetching addr event: %w", err)
	}

	internalKey, err := btcec.ParsePubKey(dbEvent.InternalKey)
	if err != nil {
		return nil, fmt.Errorf("error parsing internal key: %w", err)
	}

	hash, err := chainhash.NewHash(dbEvent.Txid)
	if err != nil {
		return nil, fmt.Errorf("error parsing txid: %w", err)
	}
	op := wire.OutPoint{
		Hash:  *hash,
		Index: uint32(dbEvent.OutputIndex),
	}

	outputs, err := fetchEventOutputs(ctx, db, dbEvent.ID)
	if err != nil {
		return nil, fmt.Errorf("error fetching event outputs: %w", err)
	}

	return &address.Event{
		ID:                 dbEvent.ID,
		CreationTime:       dbEvent.CreationTime.UTC(),
		Addr:               addr,
		Status:             address.Status(dbEvent.Status),
		Outpoint:           op,
		Amt:                btcutil.Amount(dbEvent.AmtSats.Int64),
		InternalKey:        internalKey,
		Outputs:            outputs,
		ConfirmationHeight: uint32(dbEvent.ConfirmationHeight.Int32),
		HasAllProofs:       dbEvent.NumProofs == int64(len(outputs)),
	}, nil
}

// fetchEventOutputs fetches the set of outputs for a given address event ID.
func fetchEventOutputs(ctx context.Context, db AddrBook,
	eventID int64) (map[asset.ID]address.AssetOutput, error) {

	dbOutputs, err := db.FetchAddrEventOutputs(ctx, eventID)
	if err != nil {
		return nil, fmt.Errorf("error fetching addr event outputs: %w",
			err)
	}

	outputs := make(map[asset.ID]address.AssetOutput, len(dbOutputs))
	for _, dbOutput := range dbOutputs {
		assetID, err := asset.NewIDFromBytes(dbOutput.AssetID)
		if err != nil {
			return nil, fmt.Errorf("error parsing asset ID: %w",
				err)
		}

		sk, err := parseScriptKey(
			dbOutput.InternalKey, dbOutput.ScriptKey,
		)
		if err != nil {
			return nil, fmt.Errorf("error parsing script key: %w",
				err)
		}

		outputs[assetID] = address.AssetOutput{
			Amount:    uint64(dbOutput.Amount),
			ScriptKey: sk,
		}
	}

	return outputs, nil
}

// CompleteEvent updates an address event as being complete and links it with
// the proof and asset that was imported/created for it.
func (t *TapAddressBook) CompleteEvent(ctx context.Context,
	event *address.Event, status address.Status,
	anchorPoint wire.OutPoint) error {

	outpoint, err := encodeOutpoint(anchorPoint)
	if err != nil {
		return fmt.Errorf("unable to encode outpoint: %w", err)
	}

	var writeTxOpts AddrBookTxOptions
	return t.db.ExecTx(ctx, &writeTxOpts, func(db AddrBook) error {
		// We first update the event status and TXID/outpoint. This also
		// gives us the event ID that we can use to insert the proof
		// data.
		eventID, err := db.UpsertAddrEvent(ctx, UpsertAddrEvent{
			TaprootOutputKey: schnorr.SerializePubKey(
				&event.Addr.TaprootOutputKey,
			),
			Status:              int16(status),
			Txid:                anchorPoint.Hash[:],
			ChainTxnOutputIndex: int32(anchorPoint.Index),
		})
		if err != nil {
			return fmt.Errorf("error updating addr event: %w", err)
		}

		for _, output := range event.Outputs {
			scriptPubKey := output.ScriptKey.PubKey
			scriptPubKeyBytes := scriptPubKey.SerializeCompressed()
			args := FetchAssetProof{
				TweakedScriptKey: scriptPubKeyBytes,
				Outpoint:         outpoint,
			}

			proofData, err := db.FetchAssetProof(ctx, args)
			if err != nil {
				return fmt.Errorf("error fetching asset "+
					"proof: %w", err)
			}

			switch {
			// We have no proof for this script key and outpoint.
			case len(proofData) == 0:
				return fmt.Errorf("proof for script key %x "+
					"and outpoint %v not found: %w",
					args.TweakedScriptKey, anchorPoint,
					proof.ErrProofNotFound)

			// Something is quite wrong if we have multiple proofs
			// for the same script key and outpoint.
			case len(proofData) > 1:
				return fmt.Errorf("expected exactly one "+
					"proof, got %d: %w", len(proofData),
					proof.ErrMultipleProofs)
			}

			_, err = db.UpsertAddrEventProof(
				ctx, UpsertAddrEventProof{
					AddrEventID:  eventID,
					AssetProofID: proofData[0].ProofID,
					AssetIDFk: sqlInt64(
						proofData[0].AssetID,
					),
				},
			)
			if err != nil {
				return fmt.Errorf("error inserting addr event "+
					"proof: %w", err)
			}
		}

		return nil
	})
}

// LastEventHeightByVersion returns the last event height for a given address
// version.
func (t *TapAddressBook) LastEventHeightByVersion(ctx context.Context,
	version address.Version) (uint32, error) {

	var lastHeight int64

	readOpts := NewAssetStoreReadTx()
	err := t.db.ExecTx(ctx, &readOpts, func(db AddrBook) error {
		var err error
		lastHeight, err = db.QueryLastEventHeight(ctx, int16(version))
		return err
	})
	if err != nil {
		return 0, err
	}

	return uint32(lastHeight), nil
}

// QueryAssetGroup attempts to fetch an asset group by its asset ID. If the
// asset group cannot be found, then ErrAssetGroupUnknown is returned.
func (t *TapAddressBook) QueryAssetGroup(ctx context.Context,
	assetID asset.ID) (*asset.AssetGroup, error) {

	var assetGroup asset.AssetGroup

	readOpts := NewAddrBookReadTx()
	err := t.db.ExecTx(ctx, &readOpts, func(db AddrBook) error {
		assetGen, err := db.FetchGenesisByAssetID(ctx, assetID[:])
		if err != nil {
			return err
		}

		var genesisPrevOut wire.OutPoint
		err = readOutPoint(
			bytes.NewReader(assetGen.PrevOut), 0, 0, &genesisPrevOut,
		)
		if err != nil {
			return fmt.Errorf("unable to read outpoint: %w", err)
		}

		assetGroup.Genesis = &asset.Genesis{
			FirstPrevOut: genesisPrevOut,
			Tag:          assetGen.AssetTag,
			MetaHash: fn.ToArray[[32]byte](
				assetGen.MetaHash,
			),
			OutputIndex: uint32(assetGen.OutputIndex),
			Type:        asset.Type(assetGen.AssetType),
		}

		// If there's no group associated with this asset, then we'll
		// return early as not all assets have a group.
		groupInfo, err := db.FetchGroupByGenesis(
			ctx, assetGen.GenAssetID,
		)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return nil
		case err != nil:
			return err
		}

		assetGroup.GroupKey, err = parseGroupKeyInfo(
			groupInfo.Version, groupInfo.TweakedGroupKey,
			groupInfo.RawKey, groupInfo.WitnessStack,
			groupInfo.TapscriptRoot, groupInfo.KeyFamily,
			groupInfo.KeyIndex, groupInfo.CustomSubtreeRoot,
		)

		return err
	})
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, address.ErrAssetGroupUnknown

	case err != nil:
		return nil, err
	}

	return &assetGroup, nil
}

// QueryAssetGroupByGroupKey fetches the asset group with a matching tweaked
// key, including the genesis information used to create the group.
func (t *TapAddressBook) QueryAssetGroupByGroupKey(ctx context.Context,
	groupKey *btcec.PublicKey) (*asset.AssetGroup, error) {

	var (
		dbGroup *asset.AssetGroup
		err     error
	)

	readOpts := NewAssetStoreReadTx()
	dbErr := t.db.ExecTx(ctx, &readOpts, func(a AddrBook) error {
		dbGroup, err = fetchGroupByGroupKey(ctx, a, groupKey)
		return err
	})

	if dbErr != nil {
		return nil, dbErr
	}

	return dbGroup, nil
}

// FetchAssetMetaByHash attempts to fetch an asset meta based on an asset hash.
func (t *TapAddressBook) FetchAssetMetaByHash(ctx context.Context,
	metaHash [asset.MetaHashLen]byte) (*proof.MetaReveal, error) {

	var assetMeta *proof.MetaReveal

	readOpts := NewAssetStoreReadTx()
	dbErr := t.db.ExecTx(ctx, &readOpts, func(q AddrBook) error {
		dbMeta, err := q.FetchAssetMetaByHash(ctx, metaHash[:])
		if err != nil {
			return err
		}

		// If no record is present, we should get a sql.ErrNoRows error
		// above.
		metaOpt, err := parseAssetMetaReveal(dbMeta.AssetsMetum)
		if err != nil {
			return fmt.Errorf("unable to parse asset meta: %w", err)
		}

		metaOpt.WhenSome(func(meta proof.MetaReveal) {
			assetMeta = &meta
		})

		return nil
	})
	switch {
	case errors.Is(dbErr, sql.ErrNoRows):
		return nil, address.ErrAssetMetaNotFound
	case dbErr != nil:
		return nil, dbErr
	}

	return assetMeta, nil
}

// FetchAssetMetaForAsset attempts to fetch an asset meta based on an asset ID.
func (t *TapAddressBook) FetchAssetMetaForAsset(ctx context.Context,
	assetID asset.ID) (*proof.MetaReveal, error) {

	var assetMeta *proof.MetaReveal

	readOpts := NewAssetStoreReadTx()
	dbErr := t.db.ExecTx(ctx, &readOpts, func(q AddrBook) error {
		dbMeta, err := q.FetchAssetMetaForAsset(ctx, assetID[:])
		if err != nil {
			return err
		}

		// If no record is present, we should get a sql.ErrNoRows error
		// above.
		metaOpt, err := parseAssetMetaReveal(dbMeta.AssetsMetum)
		if err != nil {
			return fmt.Errorf("unable to parse asset meta: %w", err)
		}

		metaOpt.WhenSome(func(meta proof.MetaReveal) {
			assetMeta = &meta
		})

		return nil
	})
	switch {
	case errors.Is(dbErr, sql.ErrNoRows):
		return nil, address.ErrAssetMetaNotFound
	case dbErr != nil:
		return nil, dbErr
	}

	return assetMeta, nil
}

// FetchAllAssetMeta attempts to fetch all asset meta known to the database.
func (t *TapAddressBook) FetchAllAssetMeta(
	ctx context.Context) (map[asset.ID]*proof.MetaReveal, error) {

	var assetMetas map[asset.ID]*proof.MetaReveal

	readOpts := NewAssetStoreReadTx()
	dbErr := t.db.ExecTx(ctx, &readOpts, func(q AddrBook) error {
		dbMetas, err := q.FetchAllAssetMeta(ctx)
		if err != nil {
			return err
		}

		assetMetas = make(map[asset.ID]*proof.MetaReveal, len(dbMetas))
		for _, dbMeta := range dbMetas {
			// If no record is present, we should get a
			// sql.ErrNoRows error
			// above.
			metaOpt, err := parseAssetMetaReveal(dbMeta.AssetsMetum)
			if err != nil {
				return fmt.Errorf("unable to parse asset "+
					"meta: %w", err)
			}

			metaOpt.WhenSome(func(meta proof.MetaReveal) {
				var id asset.ID
				copy(id[:], dbMeta.AssetID)
				assetMetas[id] = &meta
			})
		}

		return nil
	})
	switch {
	case errors.Is(dbErr, sql.ErrNoRows):
		return nil, address.ErrAssetMetaNotFound
	case dbErr != nil:
		return nil, dbErr
	}

	return assetMetas, nil
}

// insertFullAssetGen inserts a new asset genesis and optional asset group
// into the database. A placeholder for the asset meta inserted as well.
func insertFullAssetGen(ctx context.Context,
	gen *asset.Genesis, group *asset.GroupKey) func(AddrBook) error {

	return func(db AddrBook) error {
		_, err := maybeUpsertAssetMeta(
			ctx, db, gen, nil,
		)
		if err != nil {
			return err
		}

		genesisPointID, err := upsertGenesisPoint(
			ctx, db, gen.FirstPrevOut,
		)
		if err != nil {
			return fmt.Errorf("unable to upsert genesis "+
				"point: %w", err)
		}

		genAssetID, err := upsertGenesis(
			ctx, db, genesisPointID, *gen,
		)
		if err != nil {
			return fmt.Errorf("unable to upsert genesis: %w", err)
		}

		_, err = upsertGroupKey(
			ctx, group, db, genesisPointID, genAssetID,
		)
		if err != nil {
			return fmt.Errorf("unable to upsert group: %w", err)
		}

		return nil
	}
}

// InsertAssetGen inserts a new asset genesis into the database. This is
// exported primarily for external tests so a genesis can be in place before
// addr insertion.
func (t *TapAddressBook) InsertAssetGen(ctx context.Context,
	gen *asset.Genesis, group *asset.GroupKey) error {

	var writeTxOpts AddrBookTxOptions
	return t.db.ExecTx(ctx, &writeTxOpts, func(db AddrBook) error {
		return insertFullAssetGen(ctx, gen, group)(db)
	})
}

// FetchScriptKey attempts to fetch the full tweaked script key struct
// (including the key descriptor) for the given tweaked script key. If the key
// cannot be found, then ErrScriptKeyNotFound is returned.
func (t *TapAddressBook) FetchScriptKey(ctx context.Context,
	tweakedScriptKey *btcec.PublicKey) (*asset.TweakedScriptKey, error) {

	var (
		scriptKey *asset.TweakedScriptKey
		err       error
	)

	readOpts := NewAddrBookReadTx()
	dbErr := t.db.ExecTx(ctx, &readOpts, func(db AddrBook) error {
		scriptKey, err = fetchScriptKey(ctx, db, tweakedScriptKey)
		return err
	})

	switch {
	case errors.Is(dbErr, sql.ErrNoRows):
		return nil, address.ErrScriptKeyNotFound

	case dbErr != nil:
		return nil, err
	}

	return scriptKey, nil
}

// FetchInternalKeyLocator attempts to fetch the key locator information for the
// given raw internal key. If the key cannot be found, then
// ErrInternalKeyNotFound is returned.
func (t *TapAddressBook) FetchInternalKeyLocator(ctx context.Context,
	rawKey *btcec.PublicKey) (keychain.KeyLocator, error) {

	var (
		readOpts = NewAddrBookReadTx()
		keyLoc   keychain.KeyLocator
	)
	err := t.db.ExecTx(ctx, &readOpts, func(db AddrBook) error {
		dbKey, err := db.FetchInternalKeyLocator(
			ctx, rawKey.SerializeCompressed(),
		)
		if err != nil {
			return err
		}

		keyLoc = keychain.KeyLocator{
			Family: keychain.KeyFamily(dbKey.KeyFamily),
			Index:  uint32(dbKey.KeyIndex),
		}

		return nil
	})
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return keyLoc, address.ErrInternalKeyNotFound

	case err != nil:
		return keyLoc, err
	}

	return keyLoc, nil
}

// A set of compile-time assertions to ensure that TapAddressBook meets the
// address.Storage and address.EventStorage interface.
var _ address.Storage = (*TapAddressBook)(nil)
var _ address.EventStorage = (*TapAddressBook)(nil)
