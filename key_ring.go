package taprootassets

import (
	"context"
	"fmt"

	"github.com/davecgh/go-spew/spew"
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

// DeriveKey attempts to derive an arbitrary key specified by the passed
// KeyLocator. This may be used in several recovery scenarios, or when manually
// rotating something like our current default node key.
func (l *LndRpcKeyRing) DeriveKey(ctx context.Context,
	keyLoc keychain.KeyLocator) (keychain.KeyDescriptor, error) {

	tapdLog.Debugf("Deriving new key, key_loc=%v", spew.Sdump(keyLoc))

	keyDesc, err := l.lnd.WalletKit.DeriveKey(ctx, &keyLoc)
	if err != nil {
		return keychain.KeyDescriptor{}, fmt.Errorf("unable to "+
			"derive key ring: %w", err)
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

// A compile time assertion to ensure LndRpcKeyRing meets the
// tapgarden.KeyRing interface.
var _ tapgarden.KeyRing = (*LndRpcKeyRing)(nil)
