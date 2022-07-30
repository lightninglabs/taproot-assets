package taro

import (
	"context"
	"fmt"

	"github.com/davecgh/go-spew/spew"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taro/tarogarden"
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
// (account in BIP43) specified. This method should return the next external
// child within this branch.
func (l *LndRpcKeyRing) DeriveNextKey(ctx context.Context,
	keyFam keychain.KeyFamily) (keychain.KeyDescriptor, error) {

	taroLog.Debugf("Deriving new key for fam_family=%v", keyFam)

	keyDesc, err := l.lnd.WalletKit.DeriveNextKey(ctx, int32(keyFam))
	if err != nil {
		return keychain.KeyDescriptor{}, fmt.Errorf("unable to "+
			"derive key ring: %w", err)
	}

	return *keyDesc, nil
}

// DeriveNextTaroKey attempts to derive the *next* key within the Taro key
// family.
func (l *LndRpcKeyRing) DeriveNextTaroKey(ctx context.Context,
) (keychain.KeyDescriptor, error) {

	keyFam := int32(tarogarden.TaroKeyFamily)

	taroLog.Debugf("Deriving new key for fam_family=%v", keyFam)

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

	taroLog.Debugf("Deriving new key, key_loc=%v", spew.Sdump(keyLoc))

	keyDesc, err := l.lnd.WalletKit.DeriveKey(ctx, &keyLoc)
	if err != nil {
		return keychain.KeyDescriptor{}, fmt.Errorf("unable to "+
			"derive key ring: %w", err)
	}

	return *keyDesc, nil
}

// A compile time assertion to ensure LndRpcKeyRing meets the
// tarogarden.KeyRing interface.
var _ tarogarden.KeyRing = (*LndRpcKeyRing)(nil)
