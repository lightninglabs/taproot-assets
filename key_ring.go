package taro

import (
	"context"
	"fmt"

	"github.com/davecgh/go-spew/spew"
	"github.com/lightninglabs/lndclient"
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
func (l *LndRpcKeyRing) DeriveNextKey(keyFam keychain.KeyFamily) (keychain.KeyDescriptor, error) {
	taroLog.Debugf("Deriving new key for fam_family=%v", keyFam)

	keyDesc, err := l.lnd.WalletKit.DeriveNextKey(
		context.Background(), int32(keyFam),
	)
	if err != nil {
		return keychain.KeyDescriptor{}, fmt.Errorf("unable to "+
			"derive key ring: %w", err)
	}

	return *keyDesc, nil
}

// DeriveKey attempts to derive an arbitrary key specified by the passed
// KeyLocator. This may be used in several recovery scenarios, or when manually
// rotating something like our current default node key.
func (l *LndRpcKeyRing) DeriveKey(keyLoc keychain.KeyLocator) (keychain.KeyDescriptor, error) {
	taroLog.Debugf("Deriving new key, key_loc=%v", spew.Sdump(keyLoc))

	keyDesc, err := l.lnd.WalletKit.DeriveKey(context.Background(), &keyLoc)
	if err != nil {
		return keychain.KeyDescriptor{}, fmt.Errorf("unable to "+
			"derive key ring: %w", err)
	}

	return *keyDesc, nil
}

// A compile time assertion to ensure LndRpcKeyRing meets the keychain.KeyRing
// interface.
var _ keychain.KeyRing = (*LndRpcKeyRing)(nil)
