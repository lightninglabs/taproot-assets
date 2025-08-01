package address

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/keychain"
)

var (
	// ErrAssetGroupUnknown is returned when the asset genesis is not known.
	// This means an address can't be created until a Universe bootstrap or
	// manual issuance proof insertion.
	ErrAssetGroupUnknown = fmt.Errorf("asset group is unknown")

	// ErrAssetMetaNotFound is returned when an asset meta is not found in
	// the database.
	ErrAssetMetaNotFound = fmt.Errorf("asset meta not found")
)

// AddrWithKeyInfo wraps a normal Taproot Asset struct with key descriptor
// information.
type AddrWithKeyInfo struct {
	*Tap

	// ScriptKeyTweak houses the wallet specific information related to a
	// tweak key. This includes the raw key desc information along with the
	// tweak used to create the address.
	ScriptKeyTweak asset.TweakedScriptKey

	// InternalKeyDesc is the key desc for the internal key.
	InternalKeyDesc keychain.KeyDescriptor

	// TaprootOutputKey is the tweaked taproot output key that assets must
	// be sent to on chain to be received.
	TaprootOutputKey btcec.PublicKey

	// CreationTime is the time the address was created in the database.
	CreationTime time.Time

	// ManagedAfter is the time at which the address was imported into the
	// wallet.
	ManagedAfter time.Time
}

// QueryParams holds the set of query params for the address book.
type QueryParams struct {
	// CreatedAfter if set, only addresses created after the time will be
	// returned.
	CreatedAfter time.Time

	// CreatedBefore is set, only the addresses created before the time
	// will be returned.
	CreatedBefore time.Time

	// Limit if set, only this many addresses will be returned.
	Limit int32

	// Offset if set, then the final result will be offset by this many
	// addresses.
	Offset int32

	// UnmanagedOnly is a boolean pointer indicating whether only addresses
	// should be returned that are not yet managed by the wallet.
	UnmanagedOnly bool
}

// AssetSyncer is an interface that allows the address.Book to look up asset
// genesis and group information from both the local asset store and assets
// known to universe servers in our federation.
type AssetSyncer interface {
	// SyncAssetInfo queries the universes in our federation for genesis
	// and asset group information about the given asset.
	SyncAssetInfo(ctx context.Context, specifier asset.Specifier) error

	// EnableAssetSync updates the sync config for the given asset so that
	// we sync future issuance proofs.
	EnableAssetSync(ctx context.Context, groupInfo *asset.AssetGroup) error
}

// Storage is the main storage interface for the address book.
type Storage interface {
	EventStorage

	// InsertAddrs inserts a series of addresses into the database.
	InsertAddrs(ctx context.Context, addrs ...AddrWithKeyInfo) error

	// QueryAddrs attempts to query for a set of addresses.
	QueryAddrs(ctx context.Context,
		params QueryParams) ([]AddrWithKeyInfo, error)

	// QueryAssetGroup attempts to locate the asset group information
	// (genesis + group key) associated with a given asset.
	QueryAssetGroup(context.Context, asset.ID) (*asset.AssetGroup, error)

	// QueryAssetGroupByGroupKey fetches the asset group with a matching
	// tweaked key, including the genesis information used to create the
	// group.
	QueryAssetGroupByGroupKey(context.Context,
		*btcec.PublicKey) (*asset.AssetGroup, error)

	// FetchAssetMetaByHash attempts to fetch an asset meta based on an
	// asset hash.
	FetchAssetMetaByHash(ctx context.Context,
		metaHash [asset.MetaHashLen]byte) (*proof.MetaReveal, error)

	// FetchAssetMetaForAsset attempts to fetch an asset meta based on an
	// asset ID.
	FetchAssetMetaForAsset(ctx context.Context,
		assetID asset.ID) (*proof.MetaReveal, error)

	// AddrByTaprootOutput returns a single address based on its Taproot
	// output key or a sql.ErrNoRows error if no such address exists.
	AddrByTaprootOutput(ctx context.Context,
		key *btcec.PublicKey) (*AddrWithKeyInfo, error)

	// AddrByScriptKeyAndVersion returns a single address based on its
	// script key and version or a sql.ErrNoRows error if no such address
	// exists.
	AddrByScriptKeyAndVersion(context.Context, *btcec.PublicKey,
		Version) (*AddrWithKeyInfo, error)

	// SetAddrManaged sets an address as being managed by the internal
	// wallet.
	SetAddrManaged(ctx context.Context, addr *AddrWithKeyInfo,
		managedFrom time.Time) error

	// LastEventHeightByVersion returns the last event height for a given
	// address version.
	LastEventHeightByVersion(ctx context.Context,
		version Version) (uint32, error)

	// InsertInternalKey inserts an internal key into the database to make
	// sure it is identified as a local key later on when importing proofs.
	// The key can be an internal key for an asset script key or the
	// internal key of an anchor output.
	InsertInternalKey(ctx context.Context,
		keyDesc keychain.KeyDescriptor) error

	// InsertScriptKey inserts an address related script key into the
	// database, so it can be recognized as belonging to the wallet when a
	// transfer comes in later on.
	InsertScriptKey(ctx context.Context, scriptKey asset.ScriptKey,
		keyType asset.ScriptKeyType) error

	// FetchAllAssetMeta attempts to fetch all asset meta known to the
	// database.
	FetchAllAssetMeta(
		ctx context.Context) (map[asset.ID]*proof.MetaReveal, error)
}

// KeyRing is used to create script and internal keys for Taproot Asset
// addresses.
type KeyRing interface {
	// DeriveNextTaprootAssetKey attempts to derive the *next* key within
	// the TaprootAsset key family.
	DeriveNextTaprootAssetKey(context.Context) (keychain.KeyDescriptor,
		error)

	// DeriveNextKey attempts to derive the *next* key within the key
	// family (account in BIP43) specified. This method should return the
	// next external child within this branch.
	DeriveNextKey(context.Context,
		keychain.KeyFamily) (keychain.KeyDescriptor, error)

	// IsLocalKey returns true if the key is under the control of the wallet
	// and can be derived by it.
	IsLocalKey(ctx context.Context, desc keychain.KeyDescriptor) bool
}

// BookConfig is the main config for the address.Book.
type BookConfig struct {
	// Store holds the set of created addresses.
	Store Storage

	// Syncer allows the address.Book to sync issuance information for
	// assets from universe servers in our federation.
	Syncer AssetSyncer

	// KeyRing points to an active key ring instance.
	KeyRing KeyRing

	// Chain points to the chain the address.Book is active on.
	Chain ChainParams

	// StoreTimeout is the default timeout to use for any storage
	// interaction.
	StoreTimeout time.Duration
}

// Book is used to create and also look up the set of created Taproot Asset
// addresses.
type Book struct {
	cfg BookConfig

	// subscribers is a map of components that want to be notified on new
	// address events, keyed by their subscription ID.
	subscribers map[uint64]*fn.EventReceiver[*AddrWithKeyInfo]

	// subscriberMtx guards the subscribers map and access to the
	// subscriptionID.
	subscriberMtx sync.Mutex

	// decimalDisplayCache is a cache for the decimal display value of
	// assets. This is used to avoid repeated database queries for the same
	// asset ID.
	decimalDisplayCache map[asset.ID]fn.Option[uint32]

	// decDisplayCacheMtx guards the decimalDisplayCache map.
	decDisplayCacheMtx sync.Mutex
}

// A compile-time assertion to make sure Book satisfies the
// fn.EventPublisher interface.
var _ fn.EventPublisher[*AddrWithKeyInfo, QueryParams] = (*Book)(nil)

// NewBook creates a new Book instance from the config.
func NewBook(cfg BookConfig) *Book {
	return &Book{
		cfg: cfg,
		subscribers: make(
			map[uint64]*fn.EventReceiver[*AddrWithKeyInfo],
		),
		decimalDisplayCache: make(map[asset.ID]fn.Option[uint32]),
	}
}

// QueryAssetInfo attempts to locate asset genesis information by querying
// geneses already known to this node. If asset issuance was not previously
// verified, we then query universes in our federation for issuance proofs.
func (b *Book) QueryAssetInfo(ctx context.Context,
	specifier asset.Specifier) (asset.AssetGroup, error) {

	switch {
	case specifier.HasGroupPubKey():
		return fn.MapOptionZ(
			specifier.GroupKey(),
			func(gk btcec.PublicKey) lfn.Result[asset.AssetGroup] {
				return b.queryAssetInfoByGroupKey(ctx, gk)
			},
		).Unpack()

	case specifier.HasId():
		return fn.MapOptionZ(
			specifier.ID(),
			func(id asset.ID) lfn.Result[asset.AssetGroup] {
				return b.queryAssetInfoByID(ctx, id)
			},
		).Unpack()

	default:
		return asset.AssetGroup{}, fmt.Errorf("invalid specifier: %s",
			&specifier)
	}
}

// queryAssetInfoByID attempts to locate asset genesis information by querying
// geneses by ID already known to this node. If asset issuance was not
// previously verified, we then query universes in our federation for issuance
// proofs.
func (b *Book) queryAssetInfoByID(ctx context.Context,
	id asset.ID) lfn.Result[asset.AssetGroup] {

	// Check if we know of this asset ID already.
	assetGroup, err := b.cfg.Store.QueryAssetGroup(ctx, id)
	switch {
	case assetGroup != nil:
		return lfn.Ok(*assetGroup)

	// Asset lookup failed gracefully; continue to asset lookup using the
	// AssetSyncer if enabled.
	case errors.Is(err, ErrAssetGroupUnknown):
		if b.cfg.Syncer == nil {
			return lfn.Err[asset.AssetGroup](ErrAssetGroupUnknown)
		}

	case err != nil:
		return lfn.Err[asset.AssetGroup](err)
	}

	log.Debugf("Asset %v is unknown, attempting to bootstrap", id.String())

	// Use the AssetSyncer to query our universe federation for the asset.
	err = b.cfg.Syncer.SyncAssetInfo(ctx, asset.NewSpecifierFromId(id))
	if err != nil {
		return lfn.Err[asset.AssetGroup](err)
	}

	// The asset genesis info may have been synced from a universe
	// server; query for the asset ID again.
	assetGroup, err = b.cfg.Store.QueryAssetGroup(ctx, id)
	if err != nil {
		return lfn.Err[asset.AssetGroup](err)
	}

	log.Debugf("Bootstrap succeeded for asset %v", id.String())

	// If the asset was found after sync, and has an asset group, update our
	// universe sync config to ensure that we sync future issuance proofs.
	// Ungrouped assets will have no new issuance proofs so do not need a
	// universe sync config at all.
	if assetGroup.GroupKey != nil {
		log.Debugf("enabling asset sync for asset group %x",
			schnorr.SerializePubKey(
				&assetGroup.GroupKey.GroupPubKey,
			))
		err = b.cfg.Syncer.EnableAssetSync(ctx, assetGroup)
		if err != nil {
			return lfn.Err[asset.AssetGroup](err)
		}
	}

	return lfn.Ok(*assetGroup)
}

// queryAssetInfoByID attempts to locate asset genesis information by querying
// geneses by group key already known to this node. If asset issuance was not
// previously verified, we then query universes in our federation for issuance
// proofs.
func (b *Book) queryAssetInfoByGroupKey(ctx context.Context,
	gk btcec.PublicKey) lfn.Result[asset.AssetGroup] {

	// Check if we know of this group key already.
	gkBytes := gk.SerializeCompressed()
	assetGroup, err := b.cfg.Store.QueryAssetGroupByGroupKey(ctx, &gk)
	switch {
	case assetGroup != nil:
		return lfn.Ok(*assetGroup)

	// Asset lookup failed gracefully; continue to asset lookup using the
	// AssetSyncer if enabled.
	case errors.Is(err, ErrAssetGroupUnknown):
		if b.cfg.Syncer == nil {
			return lfn.Err[asset.AssetGroup](ErrAssetGroupUnknown)
		}

	case err != nil:
		return lfn.Err[asset.AssetGroup](err)
	}

	log.Debugf("Asset group %x is unknown, attempting to bootstrap",
		gkBytes)

	// Use the AssetSyncer to query our universe federation for the asset.
	err = b.SyncAssetGroup(ctx, gk)
	if err != nil {
		return lfn.Err[asset.AssetGroup](err)
	}

	// The asset genesis info may have been synced from a universe
	// server; query for the group key again.
	assetGroup, err = b.cfg.Store.QueryAssetGroupByGroupKey(ctx, &gk)
	if err != nil {
		return lfn.Err[asset.AssetGroup](err)
	}

	log.Debugf("Bootstrap succeeded for group %x", gkBytes)

	return lfn.Ok(*assetGroup)
}

// SyncAssetGroup attempts to enable asset sync for the given asset group, then
// perform an initial sync with the federation for that group.
func (b *Book) SyncAssetGroup(ctx context.Context,
	groupKey btcec.PublicKey) error {

	groupInfo := &asset.AssetGroup{
		GroupKey: &asset.GroupKey{
			GroupPubKey: groupKey,
		},
	}
	err := b.cfg.Syncer.EnableAssetSync(ctx, groupInfo)
	if err != nil {
		return fmt.Errorf("unable to enable asset sync: %w", err)
	}

	// Use the AssetSyncer to query our universe federation for the asset.
	return b.cfg.Syncer.SyncAssetInfo(
		ctx, asset.NewSpecifierFromGroupKey(groupKey),
	)
}

// FetchAssetMetaByHash attempts to fetch an asset meta based on an asset hash.
func (b *Book) FetchAssetMetaByHash(ctx context.Context,
	metaHash [asset.MetaHashLen]byte) (*proof.MetaReveal, error) {

	return b.cfg.Store.FetchAssetMetaByHash(ctx, metaHash)
}

// FetchAssetMetaForAsset attempts to fetch an asset meta based on an asset ID.
func (b *Book) FetchAssetMetaForAsset(ctx context.Context,
	assetID asset.ID) (*proof.MetaReveal, error) {

	// Check if we know of this meta hash already.
	meta, err := b.cfg.Store.FetchAssetMetaForAsset(ctx, assetID)
	switch {
	case meta != nil:
		return meta, nil

	// Asset lookup failed gracefully; continue to asset lookup using the
	// AssetSyncer if enabled.
	case errors.Is(err, ErrAssetMetaNotFound):
		if b.cfg.Syncer == nil {
			return nil, ErrAssetMetaNotFound
		}

	case err != nil:
		return nil, err
	}

	log.Debugf("Asset %v is unknown, attempting to bootstrap",
		assetID.String())

	// Use the AssetSyncer to query our universe federation for the asset.
	err = b.cfg.Syncer.SyncAssetInfo(ctx, asset.NewSpecifierFromId(assetID))
	if err != nil {
		return nil, err
	}

	// The asset meta info may have been synced from a universe server;
	// query for the asset ID again.
	meta, err = b.cfg.Store.FetchAssetMetaForAsset(ctx, assetID)
	if err != nil {
		return nil, err
	}

	log.Debugf("Bootstrap succeeded for asset %v", assetID.String())

	return meta, nil
}

// DecDisplayForAssetID attempts to fetch the meta reveal for a specific asset
// ID and extract the decimal display value from it.
func (b *Book) DecDisplayForAssetID(ctx context.Context,
	id asset.ID) (fn.Option[uint32], error) {

	b.decDisplayCacheMtx.Lock()
	defer b.decDisplayCacheMtx.Unlock()

	// If we don't have anything in the cache, we'll attempt to load it.
	// This will be re-attempted every time if there are no assets in the
	// database. But this isn't expected to remain the case for long.
	if len(b.decimalDisplayCache) == 0 {
		// If the cache is empty, we'll populate it with all asset
		// metas known to the database.
		allMeta, err := b.cfg.Store.FetchAllAssetMeta(ctx)
		if err != nil {
			return fn.None[uint32](), fmt.Errorf("unable to fetch "+
				"all asset meta: %v", err)
		}

		for assetID, meta := range allMeta {
			if meta == nil {
				continue
			}

			displayOpt, err := meta.DecDisplayOption()
			if err != nil {
				return fn.None[uint32](), fmt.Errorf("unable "+
					"to extract decimal display option "+
					"for asset %v: %v", assetID, err)
			}

			b.decimalDisplayCache[assetID] = displayOpt
		}
	}

	// If we have the value in the cache, return it from there.
	if displayOpt, ok := b.decimalDisplayCache[id]; ok {
		return displayOpt, nil
	}

	// If we don't have the value in the cache, it was added after we filled
	// the cache, and we'll attempt to fetch the asset meta from the
	// database instead.
	meta, err := b.FetchAssetMetaForAsset(ctx, id)
	if err != nil {
		return fn.None[uint32](), fmt.Errorf("unable to fetch asset "+
			"meta for asset_id=%v :%v", id, err)
	}

	opt, err := meta.DecDisplayOption()
	if err != nil {
		return fn.None[uint32](), fmt.Errorf("unable to extract "+
			"decimal display option for asset %v: %v", id, err)
	}

	// Store the value in the cache for future lookups.
	b.decimalDisplayCache[id] = opt

	return opt, nil
}

// NewAddress creates a new Taproot Asset address based on the input parameters.
func (b *Book) NewAddress(ctx context.Context, addrVersion Version,
	specifier asset.Specifier, amount uint64,
	tapscriptSibling *commitment.TapscriptPreimage,
	proofCourierAddr url.URL, addrOpts ...NewAddrOpt) (*AddrWithKeyInfo,
	error) {

	// Before we proceed and make new keys, make sure that we actually know
	// of this asset ID, or can import it.
	if _, err := b.QueryAssetInfo(ctx, specifier); err != nil {
		return nil, fmt.Errorf("unable to make address for unknown "+
			"asset %s: %w", &specifier, err)
	}

	rawScriptKeyDesc, err := b.cfg.KeyRing.DeriveNextTaprootAssetKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to gen key: %w", err)
	}

	// Given the raw key desc for the script key, we'll map this to a
	// BIP-0086 tweaked key as by default we'll generate keys that can be
	// used with a plain key spend.
	scriptKey := asset.NewScriptKeyBip86(rawScriptKeyDesc)

	internalKeyDesc, err := b.cfg.KeyRing.DeriveNextTaprootAssetKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to gen key: %w", err)
	}

	return b.NewAddressWithKeys(
		ctx, addrVersion, specifier, amount, scriptKey, internalKeyDesc,
		tapscriptSibling, proofCourierAddr, addrOpts...,
	)
}

// NewAddressWithKeys creates a new Taproot Asset address based on the input
// parameters that include pre-derived script and internal keys.
func (b *Book) NewAddressWithKeys(ctx context.Context, addrVersion Version,
	specifier asset.Specifier, amount uint64, scriptKey asset.ScriptKey,
	internalKeyDesc keychain.KeyDescriptor,
	tapscriptSibling *commitment.TapscriptPreimage,
	proofCourierAddr url.URL, addrOpts ...NewAddrOpt) (*AddrWithKeyInfo,
	error) {

	// Before we proceed, we'll make sure that the asset group is known to
	// the local store. Otherwise, we can't make an address as we haven't
	// bootstrapped it.
	assetGroup, err := b.QueryAssetInfo(ctx, specifier)
	if err != nil {
		return nil, err
	}

	var (
		groupKey     *btcec.PublicKey
		groupWitness wire.TxWitness
	)

	if assetGroup.GroupKey != nil {
		groupKey = &assetGroup.GroupPubKey
		groupWitness = assetGroup.Witness
	}

	baseAddr, err := New(
		addrVersion, *assetGroup.Genesis, groupKey, groupWitness,
		*scriptKey.PubKey, *internalKeyDesc.PubKey, amount,
		tapscriptSibling, &b.cfg.Chain, proofCourierAddr,
		addrOpts...,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to make new addr: %w", err)
	}

	taprootOutputKey, err := baseAddr.TaprootOutputKey()
	if err != nil {
		return nil, fmt.Errorf("unable to derive Taproot output key:"+
			" %w", err)
	}

	// We also want to import the two keys, so we can identify them as
	// belonging to the wallet later on.
	err = b.cfg.Store.InsertInternalKey(ctx, internalKeyDesc)
	if err != nil {
		return nil, fmt.Errorf("unable to insert internal key: %w", err)
	}

	// We might not know the type of script key, if it was given to us
	// through an RPC call. So we make a guess here.
	keyType := scriptKey.DetermineType(fn.Ptr(assetGroup.Genesis.ID()))

	err = b.cfg.Store.InsertScriptKey(ctx, scriptKey, keyType)
	if err != nil {
		return nil, fmt.Errorf("unable to insert script key: %w", err)
	}

	addr := AddrWithKeyInfo{
		Tap:              baseAddr,
		ScriptKeyTweak:   *scriptKey.TweakedScriptKey,
		InternalKeyDesc:  internalKeyDesc,
		TaprootOutputKey: *taprootOutputKey,
		CreationTime:     time.Now(),
	}

	if err := b.cfg.Store.InsertAddrs(ctx, addr); err != nil {
		return nil, fmt.Errorf("unable to insert addr: %w", err)
	}

	// Inform our subscribers about the new address.
	b.subscriberMtx.Lock()
	for _, sub := range b.subscribers {
		sub.NewItemCreated.ChanIn() <- &addr
	}
	b.subscriberMtx.Unlock()

	return &addr, nil
}

// IsLocalKey returns true if the key is under the control of the wallet and can
// be derived by it.
func (b *Book) IsLocalKey(ctx context.Context,
	key keychain.KeyDescriptor) bool {

	return b.cfg.KeyRing.IsLocalKey(ctx, key)
}

// InsertScriptKey inserts an address related script key into the database.
func (b *Book) InsertScriptKey(ctx context.Context, scriptKey asset.ScriptKey,
	keyType asset.ScriptKeyType) error {

	return b.cfg.Store.InsertScriptKey(ctx, scriptKey, keyType)
}

// NextInternalKey derives then inserts an internal key into the database to
// make sure it is identified as a local key later on when importing proofs. The
// key can be an internal key for an asset script key or the internal key of an
// anchor output.
func (b *Book) NextInternalKey(ctx context.Context,
	family keychain.KeyFamily) (keychain.KeyDescriptor, error) {

	internalKey, err := b.cfg.KeyRing.DeriveNextKey(ctx, family)
	if err != nil {
		return keychain.KeyDescriptor{}, fmt.Errorf("error deriving "+
			"next key: %w", err)
	}

	if err := b.cfg.Store.InsertInternalKey(ctx, internalKey); err != nil {
		return keychain.KeyDescriptor{}, err
	}

	return internalKey, nil
}

// NextScriptKey derives then inserts a script key into the database to make
// sure it is identified as a local key later on when importing proofs.
func (b *Book) NextScriptKey(ctx context.Context,
	family keychain.KeyFamily) (asset.ScriptKey, error) {

	keyDesc, err := b.cfg.KeyRing.DeriveNextKey(ctx, family)
	if err != nil {
		return asset.ScriptKey{}, fmt.Errorf("error deriving next "+
			"key: %w", err)
	}

	scriptKey := asset.NewScriptKeyBip86(keyDesc)
	err = b.cfg.Store.InsertScriptKey(ctx, scriptKey, asset.ScriptKeyBip86)
	if err != nil {
		return asset.ScriptKey{}, err
	}

	return scriptKey, nil
}

// ListAddrs lists a set of addresses based on the expressed query params.
func (b *Book) ListAddrs(ctx context.Context,
	params QueryParams) ([]AddrWithKeyInfo, error) {

	return b.cfg.Store.QueryAddrs(ctx, params)
}

// AddrByTaprootOutput returns a single address based on its Taproot output key
// or a sql.ErrNoRows error if no such address exists.
func (b *Book) AddrByTaprootOutput(ctx context.Context,
	key *btcec.PublicKey) (*AddrWithKeyInfo, error) {

	return b.cfg.Store.AddrByTaprootOutput(ctx, key)
}

// AddrByScriptKeyAndVersion returns a single address based on its script key
// and version or a sql.ErrNoRows error if no such address exists.
func (b *Book) AddrByScriptKeyAndVersion(ctx context.Context,
	scriptKey *btcec.PublicKey, version Version) (*AddrWithKeyInfo, error) {

	return b.cfg.Store.AddrByScriptKeyAndVersion(ctx, scriptKey, version)
}

// SetAddrManaged sets an address as being managed by the internal
// wallet.
func (b *Book) SetAddrManaged(ctx context.Context, addr *AddrWithKeyInfo,
	managedFrom time.Time) error {

	return b.cfg.Store.SetAddrManaged(ctx, addr, managedFrom)
}

// LastEventHeightByVersion returns the last event height for a given address
// version.
func (b *Book) LastEventHeightByVersion(ctx context.Context,
	version Version) (uint32, error) {

	return b.cfg.Store.LastEventHeightByVersion(ctx, version)
}

// GetOrCreateEvent creates a new address event for the given status, address
// and transaction. If an event for that address and transaction already exists,
// then the status and transaction information is updated instead.
func (b *Book) GetOrCreateEvent(ctx context.Context, status Status,
	addr *AddrWithKeyInfo, walletTx *lndclient.Transaction,
	outputIdx uint32) (*Event, error) {

	return b.cfg.Store.GetOrCreateEvent(
		ctx, status, addr, walletTx, outputIdx,
	)
}

// QueryEvent returns a single address event by its address and outpoint.
func (b *Book) QueryEvent(ctx context.Context,
	addr *AddrWithKeyInfo, outpoint wire.OutPoint) (*Event, error) {

	return b.cfg.Store.QueryEvent(ctx, addr, outpoint)
}

// GetPendingEvents returns all events that are not yet in status complete from
// the database.
func (b *Book) GetPendingEvents(ctx context.Context) ([]*Event, error) {
	from := StatusTransactionDetected
	to := StatusProofReceived
	query := EventQueryParams{
		StatusFrom: &from,
		StatusTo:   &to,
	}
	return b.cfg.Store.QueryAddrEvents(ctx, query)
}

// QueryEvents returns all events that match the given query.
func (b *Book) QueryEvents(ctx context.Context,
	query EventQueryParams) ([]*Event, error) {

	return b.cfg.Store.QueryAddrEvents(ctx, query)
}

// CompleteEvent updates an address event as being complete and links it with
// the proof and asset that was imported/created for it.
func (b *Book) CompleteEvent(ctx context.Context, event *Event,
	status Status, anchorPoint wire.OutPoint) error {

	return b.cfg.Store.CompleteEvent(ctx, event, status, anchorPoint)
}

// RegisterSubscriber adds a new subscriber for receiving events. The
// deliverExisting boolean indicates whether already existing items should be
// sent to the NewItemCreated channel when the subscription is started. An
// optional deliverFrom can be specified to indicate from which timestamp/index/
// marker onward existing items should be delivered on startup. If deliverFrom
// is nil/zero/empty then all existing items will be delivered.
func (b *Book) RegisterSubscriber(
	receiver *fn.EventReceiver[*AddrWithKeyInfo],
	deliverExisting bool, deliverFrom QueryParams) error {

	b.subscriberMtx.Lock()
	defer b.subscriberMtx.Unlock()

	b.subscribers[receiver.ID()] = receiver

	// No delivery of existing items requested, we're done here.
	if !deliverExisting {
		return nil
	}

	ctxt, cancel := context.WithTimeout(
		context.Background(), b.cfg.StoreTimeout,
	)
	defer cancel()

	existingAddrs, err := b.ListAddrs(ctxt, deliverFrom)
	if err != nil {
		return fmt.Errorf("error listing existing addresses: %w", err)
	}

	// Deliver each existing address to the new item queue of the
	// subscriber.
	for i := range existingAddrs {
		receiver.NewItemCreated.ChanIn() <- &existingAddrs[i]
	}

	return nil
}

// RemoveSubscriber removes the given subscriber and also stops it from
// processing events.
func (b *Book) RemoveSubscriber(
	subscriber *fn.EventReceiver[*AddrWithKeyInfo]) error {

	b.subscriberMtx.Lock()
	defer b.subscriberMtx.Unlock()

	_, ok := b.subscribers[subscriber.ID()]
	if !ok {
		return fmt.Errorf("subscriber with ID %d not found",
			subscriber.ID())
	}

	subscriber.Stop()
	delete(b.subscribers, subscriber.ID())

	return nil
}
