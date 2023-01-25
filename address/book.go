package address

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/chanutils"
	"github.com/lightningnetwork/lnd/keychain"
)

// AddrWithKeyInfo wraps a normal Taro struct with key descriptor
// information.
type AddrWithKeyInfo struct {
	*Taro

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

// Storage is the main storage interface for the address book.
type Storage interface {
	EventStorage

	// InsertAddrs inserts a series of addresses into the database.
	InsertAddrs(ctx context.Context, addrs ...AddrWithKeyInfo) error

	// QueryAddrs attemps to query for a set of addresses.
	QueryAddrs(ctx context.Context,
		params QueryParams) ([]AddrWithKeyInfo, error)

	// AddrByTaprootOutput returns a single address based on its Taproot
	// output key or a sql.ErrNoRows error if no such address exists.
	AddrByTaprootOutput(ctx context.Context,
		key *btcec.PublicKey) (*AddrWithKeyInfo, error)

	// SetAddrManaged sets an address as being managed by the internal
	// wallet.
	SetAddrManaged(ctx context.Context, addr *AddrWithKeyInfo,
		managedFrom time.Time) error
}

// KeyRing is used to create script and internal keys for Taro addresses.
type KeyRing interface {
	// DeriveNextTaroKey attempts to derive the *next* key within the Taro
	// key family.
	DeriveNextTaroKey(context.Context) (keychain.KeyDescriptor, error)
}

// BookConfig is the main config for the address.Book.
type BookConfig struct {
	// Store holds the set of created addresses.
	Store Storage

	// KeyRing points to an active key ring instance.
	KeyRing KeyRing

	// Chain points to the chain the address.Book is active on.
	Chain ChainParams

	// StoreTimeout is the default timeout to use for any storage
	// interaction.
	StoreTimeout time.Duration
}

// Book is used to create and also look up the set of created Taro addresses.
type Book struct {
	cfg BookConfig

	// subscribers is a map of components that want to be notified on new
	// address events, keyed by their subscription ID.
	subscribers map[uint64]*chanutils.EventReceiver[*AddrWithKeyInfo]

	// subscriberMtx guards the subscribers map and access to the
	// subscriptionID.
	subscriberMtx sync.Mutex
}

// A compile-time assertion to make sure Book satisfies the
// chanutils.EventPublisher interface.
var _ chanutils.EventPublisher[*AddrWithKeyInfo, QueryParams] = (*Book)(nil)

// NewBook creates a new Book instance from the config.
func NewBook(cfg BookConfig) *Book {
	return &Book{
		cfg: cfg,
		subscribers: make(
			map[uint64]*chanutils.EventReceiver[*AddrWithKeyInfo],
		),
	}
}

// NewAddress creates a new Taro address based on the input parameters.
func (b *Book) NewAddress(ctx context.Context, genesis asset.Genesis,
	groupKey *btcec.PublicKey, amount uint64) (*AddrWithKeyInfo, error) {

	rawScriptKeyDesc, err := b.cfg.KeyRing.DeriveNextTaroKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to gen key: %w", err)
	}

	// Given the raw key desc for the script key, we'll map this to a BIP
	// 86 tweaked key as by default we'll generate keys that can be used
	// with a plain key spend.
	scriptKey := asset.NewScriptKeyBIP0086(rawScriptKeyDesc)

	internalKeyDesc, err := b.cfg.KeyRing.DeriveNextTaroKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to gen key: %w", err)
	}

	return b.NewAddressWithKeys(
		ctx, genesis, groupKey, amount, scriptKey, internalKeyDesc,
	)
}

// NewAddressWithKeys creates a new Taro address based on the input parameters
// that include pre-derived script and internal keys.
func (b *Book) NewAddressWithKeys(ctx context.Context, genesis asset.Genesis,
	groupKey *btcec.PublicKey, amount uint64, scriptKey asset.ScriptKey,
	internalKeyDesc keychain.KeyDescriptor) (*AddrWithKeyInfo, error) {

	baseAddr, err := New(
		genesis, groupKey, *scriptKey.PubKey, *internalKeyDesc.PubKey,
		amount, &b.cfg.Chain,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to make new addr: %w", err)
	}

	taprootOutputKey, err := baseAddr.TaprootOutputKey(nil)
	if err != nil {
		return nil, fmt.Errorf("unable to derive Taproot output key:"+
			" %w", err)
	}

	addr := AddrWithKeyInfo{
		Taro:             baseAddr,
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

// SetAddrManaged sets an address as being managed by the internal
// wallet.
func (b *Book) SetAddrManaged(ctx context.Context, addr *AddrWithKeyInfo,
	managedFrom time.Time) error {

	return b.cfg.Store.SetAddrManaged(ctx, addr, managedFrom)
}

// GetOrCreateEvent creates a new address event for the given status, address
// and transaction. If an event for that address and transaction already exists,
// then the status and transaction information is updated instead.
func (b *Book) GetOrCreateEvent(ctx context.Context, status Status,
	addr *AddrWithKeyInfo, walletTx *lndclient.Transaction,
	outputIdx uint32, tapscriptSibling *chainhash.Hash) (*Event, error) {

	return b.cfg.Store.GetOrCreateEvent(
		ctx, status, addr, walletTx, outputIdx, tapscriptSibling,
	)
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
	receiver *chanutils.EventReceiver[*AddrWithKeyInfo],
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
	subscriber *chanutils.EventReceiver[*AddrWithKeyInfo]) error {

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
