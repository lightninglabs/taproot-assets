package tapnode

import (
	"context"
	"crypto/sha256"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightningnetwork/lnd/keychain"
)

// KeyRing is a mirror of the keychain.KeyRing interface, with the
// addition of a passed context which allows for cancellation of
// requests.
type KeyRing interface {
	// DeriveNextKey attempts to derive the *next* key within the key
	// family (account in BIP-0043) specified. This method should
	// return the next external child within this branch.
	DeriveNextKey(context.Context,
		keychain.KeyFamily) (keychain.KeyDescriptor, error)

	// IsLocalKey returns true if the key is under the control of the
	// wallet and can be derived by it.
	IsLocalKey(context.Context, keychain.KeyDescriptor) bool

	// DeriveSharedKey returns a shared secret key by performing
	// Diffie-Hellman key derivation between the ephemeral public key
	// and the key specified by the key locator (or the node's
	// identity private key if no key locator is specified):
	//
	//	P_shared = privKeyNode * ephemeralPubkey
	//
	// The resulting shared public key is serialized in the
	// compressed format and hashed with SHA256, resulting in a final
	// key length of 256 bits.
	DeriveSharedKey(context.Context, *btcec.PublicKey,
		*keychain.KeyLocator) ([sha256.Size]byte, error)
}
