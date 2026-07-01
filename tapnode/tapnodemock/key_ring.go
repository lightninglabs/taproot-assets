package tapnodemock

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/tapnode"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/mock"
)

// KeyRing is an in-memory mock implementation of tapnode.KeyRing.
type KeyRing struct {
	mock.Mock

	sync.RWMutex

	KeyIndex uint32

	Keys map[keychain.KeyLocator]*btcec.PrivateKey

	deriveNextKeyCallCount atomic.Uint64
}

// NewKeyRing returns a freshly-initialised mock KeyRing with the default
// DeriveNextKey / DeriveNextTaprootAssetKey expectations registered.
func NewKeyRing() *KeyRing {
	keyRing := &KeyRing{
		Keys: make(map[keychain.KeyLocator]*btcec.PrivateKey),
	}

	keyRing.On(
		"DeriveNextKey", mock.Anything,
		keychain.KeyFamily(asset.TaprootAssetsKeyFamily),
	).Return(keychain.KeyDescriptor{}, nil)

	keyRing.On(
		"DeriveNextTaprootAssetKey", mock.Anything,
	).Return(keychain.KeyDescriptor{}, nil)

	return keyRing
}

// DeriveNextTaprootAssetKey attempts to derive the *next* key within the
// Taproot Asset key family.
func (m *KeyRing) DeriveNextTaprootAssetKey(
	ctx context.Context) (keychain.KeyDescriptor, error) {

	// No need to lock mutex here, DeriveNextKey does that for us.
	m.Called(ctx)

	return m.DeriveNextKey(ctx, asset.TaprootAssetsKeyFamily)
}

// DeriveNextKey returns a fresh keychain descriptor backed by a newly-
// generated private key, recorded in m.Keys.
func (m *KeyRing) DeriveNextKey(ctx context.Context,
	keyFam keychain.KeyFamily) (keychain.KeyDescriptor, error) {

	m.Lock()
	defer func() {
		m.KeyIndex++
		m.Unlock()
	}()

	m.Called(ctx, keyFam)
	m.deriveNextKeyCallCount.Add(1)

	select {
	case <-ctx.Done():
		return keychain.KeyDescriptor{}, fmt.Errorf("shutting down")
	default:
	}

	priv, err := btcec.NewPrivateKey()
	if err != nil {
		return keychain.KeyDescriptor{}, err
	}

	loc := keychain.KeyLocator{
		Index:  m.KeyIndex,
		Family: keyFam,
	}

	m.Keys[loc] = priv

	desc := keychain.KeyDescriptor{
		PubKey:     priv.PubKey(),
		KeyLocator: loc,
	}

	return desc, nil
}

// IsLocalKey reports whether the given descriptor is for a key the mock
// previously derived.
func (m *KeyRing) IsLocalKey(ctx context.Context,
	d keychain.KeyDescriptor) bool {

	m.Lock()
	defer m.Unlock()

	m.Called(ctx, d)

	priv, ok := m.Keys[d.KeyLocator]
	if ok && priv.PubKey().IsEqual(d.PubKey) {
		return true
	}

	for _, key := range m.Keys {
		if key.PubKey().IsEqual(d.PubKey) {
			return true
		}
	}

	return false
}

// PubKeyAt returns the public key at the given index within the Taproot Assets
// key family, failing the test if no key has been derived at that index.
func (m *KeyRing) PubKeyAt(t *testing.T, idx uint32) *btcec.PublicKey {
	m.Lock()
	defer m.Unlock()

	loc := keychain.KeyLocator{
		Index:  idx,
		Family: asset.TaprootAssetsKeyFamily,
	}

	priv, ok := m.Keys[loc]
	if !ok {
		t.Fatalf("script key not found at index %d", idx)
	}

	return priv.PubKey()
}

// ScriptKeyAt returns the BIP-86 script key at the given index within the
// Taproot Assets key family.
func (m *KeyRing) ScriptKeyAt(t *testing.T, idx uint32) asset.ScriptKey {
	m.Lock()
	defer m.Unlock()

	loc := keychain.KeyLocator{
		Index:  idx,
		Family: asset.TaprootAssetsKeyFamily,
	}

	priv, ok := m.Keys[loc]
	if !ok {
		t.Fatalf("script key not found at index %d", idx)
	}

	return asset.NewScriptKeyBip86(keychain.KeyDescriptor{
		KeyLocator: loc,
		PubKey:     priv.PubKey(),
	})
}

// DeriveSharedKey performs DH between the given public key and the
// locator-identified private key in the mock's ring.
func (m *KeyRing) DeriveSharedKey(_ context.Context, key *btcec.PublicKey,
	locator *keychain.KeyLocator) ([sha256.Size]byte, error) {

	m.Lock()
	defer m.Unlock()

	if locator == nil {
		return [32]byte{}, fmt.Errorf("locator is nil")
	}

	priv, ok := m.Keys[*locator]
	if !ok {
		return [32]byte{}, fmt.Errorf("script key not found at index "+
			"%d", locator.Index)
	}

	ecdh := &keychain.PrivKeyECDH{
		PrivKey: priv,
	}
	return ecdh.ECDH(key)
}

// DeriveNextKeyCallCount returns the number of calls to DeriveNextKey.
func (m *KeyRing) DeriveNextKeyCallCount() int {
	return int(m.deriveNextKeyCallCount.Load())
}

// ResetDeriveNextKeyCallCount resets the call counter for DeriveNextKey to
// zero.
func (m *KeyRing) ResetDeriveNextKeyCallCount() {
	m.deriveNextKeyCallCount.Store(0)
}

var _ tapnode.KeyRing = (*KeyRing)(nil)
