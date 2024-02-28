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
	"github.com/lightninglabs/lndclient"
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
	NewAddr = sqlc.InsertAddrParams

	// Addresses is a type alias for the full address row with key locator
	// information.
	Addresses = sqlc.FetchAddrsRow

	// AddrByTaprootOutput is a type alias for returning an address by its
	// Taproot output key.
	AddrByTaprootOutput = sqlc.FetchAddrByTaprootOutputKeyRow

	// AddrManaged is a type alias for setting an address as managed.
	AddrManaged = sqlc.SetAddrManagedParams

	// UpsertAddrEvent is a type alias for creating a new address event or
	// updating an existing one.
	UpsertAddrEvent = sqlc.UpsertAddrEventParams

	// AddrEvent is a type alias for fetching an address event row.
	AddrEvent = sqlc.FetchAddrEventRow

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

	// FetchAddrs returns all the addresses based on the constraints of the
	// passed AddrQuery.
	FetchAddrs(ctx context.Context, arg AddrQuery) ([]Addresses, error)

	// FetchAddrByTaprootOutputKey returns a single address based on its
	// Taproot output key or a sql.ErrNoRows error if no such address
	// exists.
	FetchAddrByTaprootOutputKey(ctx context.Context,
		arg []byte) (AddrByTaprootOutput, error)

	// InsertAddr inserts a new address into the database.
	InsertAddr(ctx context.Context, arg NewAddr) (int64, error)

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

	// FetchAddrEvent returns a single address event based on its primary
	// key.
	FetchAddrEvent(ctx context.Context, id int64) (AddrEvent, error)

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

	// FetchScriptKeyByTweakedKey attempts to fetch the script key and
	// corresponding internal key from the database.
	FetchScriptKeyByTweakedKey(ctx context.Context,
		tweakedScriptKey []byte) (ScriptKey, error)

	// FetchInternalKeyLocator fetches the key locator for an internal key.
	FetchInternalKeyLocator(ctx context.Context, rawKey []byte) (KeyLocator,
		error)
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
			assetGen, err := db.FetchGenesisByAssetID(
				ctx, addr.AssetID[:],
			)
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

			_, err = db.InsertAddr(ctx, NewAddr{
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

			rawScriptKey, err := btcec.ParsePubKey(
				addr.RawScriptKey,
			)
			if err != nil {
				return fmt.Errorf("unable to decode "+
					"script key: %w", err)
			}
			rawScriptKeyDesc := keychain.KeyDescriptor{
				KeyLocator: keychain.KeyLocator{
					Family: keychain.KeyFamily(
						addr.ScriptKeyFamily,
					),
					Index: uint32(addr.ScriptKeyIndex),
				},
				PubKey: rawScriptKey,
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

			scriptKey, err := btcec.ParsePubKey(addr.TweakedScriptKey)
			if err != nil {
				return err
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
				groupKey, groupWitness,
				*scriptKey, *internalKey, uint64(addr.Amount),
				tapscriptSibling, t.params, *proofCourierAddr,
				address.WithAssetVersion(
					asset.Version(addr.AssetVersion),
				),
			)
			if err != nil {
				return fmt.Errorf("unable to make addr: %w", err)
			}

			addrs = append(addrs, address.AddrWithKeyInfo{
				Tap: tapAddr,
				ScriptKeyTweak: asset.TweakedScriptKey{
					RawKey: rawScriptKeyDesc,
					Tweak:  addr.ScriptKeyTweak,
				},
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
		var err error
		addr, err = fetchAddr(ctx, db, t.params, key)
		return err
	})
	if err != nil {
		return nil, err
	}

	return addr, nil
}

// fetchAddr fetches a single address identified by its taproot output key from
// the database and populates all its fields.
func fetchAddr(ctx context.Context, db AddrBook, params *address.ChainParams,
	taprootOutputKey *btcec.PublicKey) (*address.AddrWithKeyInfo, error) {

	dbAddr, err := db.FetchAddrByTaprootOutputKey(
		ctx, schnorr.SerializePubKey(taprootOutputKey),
	)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, address.ErrNoAddr

	case err != nil:
		return nil, err
	}

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

	rawScriptKey, err := btcec.ParsePubKey(dbAddr.RawScriptKey)
	if err != nil {
		return nil, fmt.Errorf("unable to decode script key: %w", err)
	}
	scriptKeyDesc := keychain.KeyDescriptor{
		KeyLocator: keychain.KeyLocator{
			Family: keychain.KeyFamily(
				dbAddr.ScriptKeyFamily,
			),
			Index: uint32(dbAddr.ScriptKeyIndex),
		},
		PubKey: rawScriptKey,
	}

	scriptKey, err := btcec.ParsePubKey(dbAddr.TweakedScriptKey)
	if err != nil {
		return nil, fmt.Errorf("unable to decode script key: %w", err)
	}

	internalKey, err := btcec.ParsePubKey(dbAddr.RawTaprootKey)
	if err != nil {
		return nil, fmt.Errorf("unable to decode taproot key: %w", err)
	}
	internalKeyDesc := keychain.KeyDescriptor{
		KeyLocator: keychain.KeyLocator{
			Family: keychain.KeyFamily(
				dbAddr.TaprootKeyFamily,
			),
			Index: uint32(dbAddr.TaprootKeyIndex),
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
		groupWitness, *scriptKey, *internalKey, uint64(dbAddr.Amount),
		tapscriptSibling, params, *proofCourierAddr,
		address.WithAssetVersion(asset.Version(dbAddr.AssetVersion)),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to make addr: %w", err)
	}

	return &address.AddrWithKeyInfo{
		Tap: tapAddr,
		ScriptKeyTweak: asset.TweakedScriptKey{
			RawKey: scriptKeyDesc,
			Tweak:  dbAddr.ScriptKeyTweak,
		},
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
	scriptKey asset.ScriptKey) error {

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
		})
		return err
	})
}

// GetOrCreateEvent creates a new address event for the given status, address
// and transaction. If an event for that address and transaction already exists,
// then the status and transaction information is updated instead.
func (t *TapAddressBook) GetOrCreateEvent(ctx context.Context,
	status address.Status, addr *address.AddrWithKeyInfo,
	walletTx *lndclient.Transaction, outputIdx uint32) (*address.Event,
	error) {

	var (
		writeTxOpts AddrBookTxOptions
		event       *address.Event
		txHash      = walletTx.Tx.TxHash()
		txBuf       bytes.Buffer
	)
	if err := walletTx.Tx.Serialize(&txBuf); err != nil {
		return nil, fmt.Errorf("error serializing tx: %w", err)
	}
	outpoint := wire.OutPoint{
		Hash:  txHash,
		Index: outputIdx,
	}
	outpointBytes, err := encodeOutpoint(outpoint)
	if err != nil {
		return nil, fmt.Errorf("error encoding outpoint: %w", err)
	}
	outputDetails := walletTx.OutputDetails[outputIdx]

	siblingBytes, siblingHash, err := commitment.MaybeEncodeTapscriptPreimage(
		addr.TapscriptSibling,
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
			RawTx: txBuf.Bytes(),
		}
		if walletTx.Confirmations > 0 {
			txUpsert.BlockHeight = sqlInt32(walletTx.BlockHeight)

			// We're missing the transaction index within the block,
			// we need to update that from the proof. Fortunately we
			// only update fields that aren't nil in the upsert.
			blockHash, err := chainhash.NewHashFromStr(
				walletTx.BlockHash,
			)
			if err != nil {
				return fmt.Errorf("error parsing block hash: "+
					"%w", err)
			}
			txUpsert.BlockHash = blockHash[:]
		}
		chainTxID, err := db.UpsertChainTx(ctx, txUpsert)
		if err != nil {
			return fmt.Errorf("error upserting chain TX: %w", err)
		}

		tapCommitment, err := addr.TapCommitment()
		if err != nil {
			return fmt.Errorf("error deriving commitment: %w", err)
		}
		merkleRoot := tapCommitment.TapscriptRoot(siblingHash)
		taprootAssetRoot := tapCommitment.TapscriptRoot(nil)

		utxoUpsert := RawManagedUTXO{
			RawKey:           addr.InternalKey.SerializeCompressed(),
			Outpoint:         outpointBytes,
			AmtSats:          outputDetails.Amount,
			TaprootAssetRoot: taprootAssetRoot[:],
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
				&addr.TaprootOutputKey,
			),
			CreationTime:        t.clock.Now().UTC(),
			Status:              int16(status),
			Txid:                txHash[:],
			ChainTxnOutputIndex: int32(outputIdx),
			ManagedUtxoID:       managedUtxoID,
		})
		if err != nil {
			return fmt.Errorf("error fetching existing events: %w",
				err)
		}

		event, err = fetchEvent(ctx, db, eventID, addr)
		return err
	})
	if dbErr != nil {
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
		StatusFrom: int16(address.StatusTransactionDetected),
		StatusTo:   int16(address.StatusCompleted),
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

			addr, err := fetchAddr(
				ctx, db, t.params, taprootOutputKey,
			)
			if err != nil {
				return fmt.Errorf("error fetching address: %w",
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

	return &address.Event{
		ID:                 eventID,
		CreationTime:       dbEvent.CreationTime.UTC(),
		Addr:               addr,
		Status:             address.Status(dbEvent.Status),
		Outpoint:           op,
		Amt:                btcutil.Amount(dbEvent.AmtSats.Int64),
		InternalKey:        internalKey,
		ConfirmationHeight: uint32(dbEvent.ConfirmationHeight.Int32),
		HasProof:           dbEvent.AssetProofID.Valid,
	}, nil
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

	args := FetchAssetProof{
		TweakedScriptKey: event.Addr.ScriptKey.SerializeCompressed(),
		Outpoint:         outpoint,
	}

	var writeTxOpts AddrBookTxOptions
	return t.db.ExecTx(ctx, &writeTxOpts, func(db AddrBook) error {
		proofData, err := db.FetchAssetProof(ctx, args)
		if err != nil {
			return fmt.Errorf("error fetching asset proof: %w", err)
		}

		switch {
		// We have no proof for this script key and outpoint.
		case len(proofData) == 0:
			return fmt.Errorf("proof for script key %x and "+
				"outpoint %v not found: %w",
				args.TweakedScriptKey, anchorPoint,
				proof.ErrProofNotFound)

		// Something is quite wrong if we have multiple proofs for the
		// same script key and outpoint.
		case len(proofData) > 1:
			return fmt.Errorf("expected exactly one proof, got "+
				"%d: %w", len(proofData),
				proof.ErrMultipleProofs)
		}

		_, err = db.UpsertAddrEvent(ctx, UpsertAddrEvent{
			TaprootOutputKey: schnorr.SerializePubKey(
				&event.Addr.TaprootOutputKey,
			),
			Status:              int16(status),
			Txid:                anchorPoint.Hash[:],
			ChainTxnOutputIndex: int32(anchorPoint.Index),
			AssetProofID:        sqlInt64(proofData[0].ProofID),
			AssetID:             sqlInt64(proofData[0].AssetID),
		})
		return err
	})
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
			groupInfo.TweakedGroupKey, groupInfo.RawKey,
			groupInfo.WitnessStack, groupInfo.TapscriptRoot,
			groupInfo.KeyFamily, groupInfo.KeyIndex,
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

// insertFullAssetGen inserts a new asset genesis and optional asset group
// into the database. A place holder for the asset meta inserted as well.
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
		readOpts  = NewAddrBookReadTx()
		scriptKey *asset.TweakedScriptKey
	)
	err := t.db.ExecTx(ctx, &readOpts, func(db AddrBook) error {
		dbKey, err := db.FetchScriptKeyByTweakedKey(
			ctx, tweakedScriptKey.SerializeCompressed(),
		)
		if err != nil {
			return err
		}

		rawKey, err := btcec.ParsePubKey(dbKey.RawKey)
		if err != nil {
			return fmt.Errorf("unable to parse raw key: %w", err)
		}

		scriptKey = &asset.TweakedScriptKey{
			Tweak: dbKey.Tweak,
			RawKey: keychain.KeyDescriptor{
				PubKey: rawKey,
				KeyLocator: keychain.KeyLocator{
					Family: keychain.KeyFamily(
						dbKey.KeyFamily,
					),
					Index: uint32(dbKey.KeyIndex),
				},
			},
		}

		return nil
	})
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, address.ErrScriptKeyNotFound

	case err != nil:
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
