package address

import (
	"context"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightningnetwork/lnd/keychain"
)

// AddrWithKeyInfo wraps a normal AddressTaro struct with key descriptor
// information.
type AddrWithKeyInfo struct {
	*AddressTaro

	// ScriptKeyDesc is the key desc for the script key.
	ScriptKeyDesc keychain.KeyDescriptor

	// InternalKeyDesc is the key desc for the internal key.
	InternalKeyDesc keychain.KeyDescriptor
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
}

// Store is the main storage interface for the address book.
type Storage interface {
	// InsertAddrs inserts a series of addresses into the database.
	InsertAddrs(ctx context.Context, addrs ...AddrWithKeyInfo) error

	// QueryAddrs attemps to query for a set of addresses.
	QueryAddrs(ctx context.Context,
		params QueryParams) ([]AddrWithKeyInfo, error)
}

// KeyRing is used to create script and internal keys for Taro addresses.
type KeyRing interface {
	// DeriveNexTarotKey attempts to derive the *next* key within the Taro
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
}

// Book is used to create and also look up the set of created Taro addresses.
type Book struct {
	cfg BookConfig
}

// NewBook creates a new Book instance from the config.
func NewBook(cfg BookConfig) *Book {
	return &Book{
		cfg: cfg,
	}
}

// NewAddress creates a new Taro address based on the input parameters.
func (b *Book) NewAddress(ctx context.Context, assetID asset.ID,
	famKey *btcec.PublicKey, amount uint64,
	assetType asset.Type) (*AddrWithKeyInfo, error) {

	scriptKeyDesc, err := b.cfg.KeyRing.DeriveNextTaroKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to gen key: %w", err)
	}
	internalKeyDesc, err := b.cfg.KeyRing.DeriveNextTaroKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to gen key: %w", err)
	}

	baseAddr, err := New(
		assetID, famKey, *scriptKeyDesc.PubKey, *internalKeyDesc.PubKey,
		amount, assetType, &b.cfg.Chain,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to make new addr: %w", err)
	}
	addr := AddrWithKeyInfo{
		AddressTaro:     baseAddr,
		ScriptKeyDesc:   scriptKeyDesc,
		InternalKeyDesc: internalKeyDesc,
	}

	if err := b.cfg.Store.InsertAddrs(ctx, addr); err != nil {
		return nil, fmt.Errorf("unable to insert addr: %w", err)
	}

	return &addr, nil
}

// ListAddrs lists a set of addresses based on the expressed query params.
func (b *Book) ListAddrs(ctx context.Context,
	params QueryParams) ([]AddrWithKeyInfo, error) {

	return b.cfg.Store.QueryAddrs(ctx, params)
}
