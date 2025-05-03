package addressbook

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
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightningnetwork/lnd/keychain"
)

// BookConfig is the main config for the address.Book.
type BookConfig struct {
	// Store holds the set of created addresses.
	Store Storage

	// Syncer allows the address.Book to sync issuance information for
	// assets from universe servers in our federation.
	Syncer address.AssetSyncer

	// KeyRing points to an active key ring instance.
	KeyRing address.KeyRing

	// Chain points to the chain the address.Book is active on.
	Chain address.ChainParams

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
	subscribers map[uint64]*fn.EventReceiver[*address.AddrWithKeyInfo]

	// subscriberMtx guards the subscribers map and access to the
	// subscriptionID.
	subscriberMtx sync.Mutex
}

// A compile-time assertion to make sure Book satisfies the
// fn.EventPublisher interface.
var _ fn.EventPublisher[*address.AddrWithKeyInfo, address.QueryParams] = (*Book)(nil)

// NewBook creates a new Book instance from the config.
func NewBook(cfg BookConfig) *Book {
	return &Book{
		cfg: cfg,
		subscribers: make(
			map[uint64]*fn.EventReceiver[*address.AddrWithKeyInfo],
		),
	}
}

// QueryAssetInfo attempts to locate asset genesis information by querying
// geneses already known to this node. If asset issuance was not previously
// verified, we then query universes in our federation for issuance proofs.
func (b *Book) QueryAssetInfo(ctx context.Context,
	id asset.ID) (*asset.AssetGroup, error) {

	// Check if we know of this asset ID already.
	assetGroup, err := b.cfg.Store.QueryAssetGroup(ctx, id)
	switch {
	case assetGroup != nil:
		return assetGroup, nil

	// Asset lookup failed gracefully; continue to asset lookup using the
	// AssetSyncer if enabled.
	case errors.Is(err, address.ErrAssetGroupUnknown):
		if b.cfg.Syncer == nil {
			return nil, address.ErrAssetGroupUnknown
		}

	case err != nil:
		return nil, err
	}

	log.Debugf("Asset %v is unknown, attempting to bootstrap", id.String())

	// Use the AssetSyncer to query our universe federation for the asset.
	err = b.cfg.Syncer.SyncAssetInfo(ctx, &id)
	if err != nil {
		return nil, err
	}

	// The asset genesis info may have been synced from a universe
	// server; query for the asset ID again.
	assetGroup, err = b.cfg.Store.QueryAssetGroup(ctx, id)
	if err != nil {
		return nil, err
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
			return nil, err
		}
	}

	return assetGroup, nil
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
	case errors.Is(err, address.ErrAssetMetaNotFound):
		if b.cfg.Syncer == nil {
			return nil, address.ErrAssetMetaNotFound
		}

	case err != nil:
		return nil, err
	}

	log.Debugf("Asset %v is unknown, attempting to bootstrap",
		assetID.String())

	// Use the AssetSyncer to query our universe federation for the asset.
	err = b.cfg.Syncer.SyncAssetInfo(ctx, &assetID)
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

// NewAddress creates a new Taproot Asset address based on the input parameters.
func (b *Book) NewAddress(ctx context.Context, addrVersion address.Version,
	assetID asset.ID, amount uint64,
	tapscriptSibling *commitment.TapscriptPreimage,
	proofCourierAddr url.URL,
	addrOpts ...address.NewAddrOpt) (*address.AddrWithKeyInfo, error) {

	// Before we proceed and make new keys, make sure that we actually know
	// of this asset ID, or can import it.
	if _, err := b.QueryAssetInfo(ctx, assetID); err != nil {
		return nil, fmt.Errorf("unable to make address for unknown "+
			"asset %x: %w", assetID[:], err)
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
		ctx, addrVersion, assetID, amount, scriptKey, internalKeyDesc,
		tapscriptSibling, proofCourierAddr, addrOpts...,
	)
}

// NewAddressWithKeys creates a new Taproot Asset address based on the input
// parameters that include pre-derived script and internal keys.
func (b *Book) NewAddressWithKeys(ctx context.Context,
	addrVersion address.Version, assetID asset.ID, amount uint64,
	scriptKey asset.ScriptKey, internalKeyDesc keychain.KeyDescriptor,
	tapscriptSibling *commitment.TapscriptPreimage,
	proofCourierAddr url.URL,
	addrOpts ...address.NewAddrOpt) (*address.AddrWithKeyInfo, error) {

	// Before we proceed, we'll make sure that the asset group is known to
	// the local store. Otherwise, we can't make an address as we haven't
	// bootstrapped it.
	assetGroup, err := b.QueryAssetInfo(ctx, assetID)
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

	baseAddr, err := address.New(
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
	keyType := scriptKey.DetermineType()

	err = b.cfg.Store.InsertScriptKey(ctx, scriptKey, keyType)
	if err != nil {
		return nil, fmt.Errorf("unable to insert script key: %w", err)
	}

	addr := address.AddrWithKeyInfo{
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
	params address.QueryParams) ([]address.AddrWithKeyInfo, error) {

	return b.cfg.Store.QueryAddrs(ctx, params)
}

// AddrByTaprootOutput returns a single address based on its Taproot output key
// or a sql.ErrNoRows error if no such address exists.
func (b *Book) AddrByTaprootOutput(ctx context.Context,
	key *btcec.PublicKey) (*address.AddrWithKeyInfo, error) {

	return b.cfg.Store.AddrByTaprootOutput(ctx, key)
}

// SetAddrManaged sets an address as being managed by the internal
// wallet.
func (b *Book) SetAddrManaged(ctx context.Context,
	addr *address.AddrWithKeyInfo, managedFrom time.Time) error {

	return b.cfg.Store.SetAddrManaged(ctx, addr, managedFrom)
}

// GetOrCreateEvent creates a new address event for the given status, address
// and transaction. If an event for that address and transaction already exists,
// then the status and transaction information is updated instead.
func (b *Book) GetOrCreateEvent(ctx context.Context, status address.Status,
	addr *address.AddrWithKeyInfo, walletTx *lndclient.Transaction,
	outputIdx uint32) (*address.Event, error) {

	return b.cfg.Store.GetOrCreateEvent(
		ctx, status, addr, walletTx, outputIdx,
	)
}

// QueryEvent returns a single address event by its address and outpoint.
func (b *Book) QueryEvent(ctx context.Context, addr *address.AddrWithKeyInfo,
	outpoint wire.OutPoint) (*address.Event, error) {

	return b.cfg.Store.QueryEvent(ctx, addr, outpoint)
}

// GetPendingEvents returns all events that are not yet in status complete from
// the database.
func (b *Book) GetPendingEvents(ctx context.Context) ([]*address.Event, error) {
	from := address.StatusTransactionDetected
	to := address.StatusProofReceived
	query := address.EventQueryParams{
		StatusFrom: &from,
		StatusTo:   &to,
	}
	return b.cfg.Store.QueryAddrEvents(ctx, query)
}

// QueryEvents returns all events that match the given query.
func (b *Book) QueryEvents(ctx context.Context,
	query address.EventQueryParams) ([]*address.Event, error) {

	return b.cfg.Store.QueryAddrEvents(ctx, query)
}

// CompleteEvent updates an address event as being complete and links it with
// the proof and asset that was imported/created for it.
func (b *Book) CompleteEvent(ctx context.Context, event *address.Event,
	status address.Status, anchorPoint wire.OutPoint) error {

	return b.cfg.Store.CompleteEvent(ctx, event, status, anchorPoint)
}

// RegisterSubscriber adds a new subscriber for receiving events. The
// deliverExisting boolean indicates whether already existing items should be
// sent to the NewItemCreated channel when the subscription is started. An
// optional deliverFrom can be specified to indicate from which timestamp/index/
// marker onward existing items should be delivered on startup. If deliverFrom
// is nil/zero/empty then all existing items will be delivered.
func (b *Book) RegisterSubscriber(
	receiver *fn.EventReceiver[*address.AddrWithKeyInfo],
	deliverExisting bool, deliverFrom address.QueryParams) error {

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
	subscriber *fn.EventReceiver[*address.AddrWithKeyInfo]) error {

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
