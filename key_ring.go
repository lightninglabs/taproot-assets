package taprootassets

import (
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightningnetwork/lnd/keychain"
)

// LndRpcKeyRing is an implementation of the keychain.KeyRing interface backed
// by an active remote lnd node.
type LndRpcKeyRing struct {
	lnd *lndclient.LndServices
}

// NewLndRpcKeyRing creates a new instance of the LndRpcKeyRing based on the
// passed ln client.
func NewLndRpcKeyRing(lnd *lndclient.LndServices) *LndRpcKeyRing {
	return &LndRpcKeyRing{
		lnd: lnd,
	}
}

// DeriveNextKey attempts to derive the *next* key within the key family
// (account in BIP-0043) specified. This method should return the next external
// child within this branch.
func (l *LndRpcKeyRing) DeriveNextKey(ctx context.Context,
	keyFam keychain.KeyFamily) (keychain.KeyDescriptor, error) {

	tapdLog.Debugf("Deriving new key for fam_family=%v", keyFam)

	keyDesc, err := l.lnd.WalletKit.DeriveNextKey(ctx, int32(keyFam))
	if err != nil {
		return keychain.KeyDescriptor{}, fmt.Errorf("unable to "+
			"derive key ring: %w", err)
	}

	return *keyDesc, nil
}

// DeriveNextTaprootAssetKey attempts to derive the *next* key within the
// Taproot Asset key family.
func (l *LndRpcKeyRing) DeriveNextTaprootAssetKey(
	ctx context.Context) (keychain.KeyDescriptor, error) {

	keyFam := int32(asset.TaprootAssetsKeyFamily)

	tapdLog.Debugf("Deriving new key for fam_family=%v", keyFam)

	keyDesc, err := l.lnd.WalletKit.DeriveNextKey(ctx, keyFam)
	if err != nil {
		return keychain.KeyDescriptor{}, fmt.Errorf("unable to "+
			"derive next key: %w", err)
	}

	return *keyDesc, nil
}

// IsLocalKey returns true if the key is under the control of the wallet
// and can be derived by it.
func (l *LndRpcKeyRing) IsLocalKey(ctx context.Context,
	desc keychain.KeyDescriptor) bool {

	// We can't identify the key as belonging to us if the public key is not
	// set, as we have nothing to compare a derived key to.
	if desc.PubKey == nil {
		return false
	}

	// An external software could use a key outside the Taproot Asset key
	// family, so we can only be sure that it's definitely not a key known
	// by the wallet if both family and index are 0. That should only be the
	// case for keys that are imported from a proof for example.
	if desc.Family == 0 && desc.Index == 0 {
		return false
	}

	// Since we have a non-zero family or index, we should ask the lnd we
	// are connected to, if it knows the key.
	derived, err := l.lnd.WalletKit.DeriveKey(ctx, &desc.KeyLocator)
	if err != nil {
		return false
	}

	return derived.PubKey.IsEqual(desc.PubKey)
}

// DeriveSharedKey returns a shared secret key by performing
// Diffie-Hellman key derivation between the ephemeral public key and
// the key specified by the key locator (or the node's identity private
// key if no key locator is specified):
//
//	P_shared = privKeyNode * ephemeralPubkey
//
// The resulting shared public key is serialized in the compressed
// format and hashed with SHA256, resulting in a final key length of 256
// bits.
func (l *LndRpcKeyRing) DeriveSharedKey(ctx context.Context,
	ephemeralPubKey *btcec.PublicKey,
	keyLocator *keychain.KeyLocator) ([sha256.Size]byte, error) {

	return l.lnd.Signer.DeriveSharedKey(ctx, ephemeralPubKey, keyLocator)
}

// A compile time assertion to ensure LndRpcKeyRing meets the
// tapgarden.KeyRing interface.
var _ tapgarden.KeyRing = (*LndRpcKeyRing)(nil)
