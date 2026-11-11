package asset

import (
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
)

// SignDescriptor houses the information a signer needs to produce a signature
// for a single input of a virtual transaction.
type SignDescriptor struct {
	// KeyDesc describes which key to sign with, either by its raw public
	// key or by its derivation path.
	KeyDesc keychain.KeyDescriptor

	// SingleTweak is a scalar that is added to the private key before
	// signing. At most one of SingleTweak and DoubleTweak is set.
	SingleTweak []byte

	// DoubleTweak is a private key that is combined with the signing key
	// in a revocation style derivation before signing. At most one of
	// SingleTweak and DoubleTweak is set.
	DoubleTweak *btcec.PrivateKey

	// TapTweak is the input to the taproot tweak that turns the internal
	// key into the output key. It is empty for a BIP-0086 spend and the
	// tapscript root hash otherwise.
	TapTweak []byte

	// WitnessScript is the raw leaf script being spent in a script path
	// spend.
	WitnessScript []byte

	// SignMethod selects between the BIP-0086 key spend, the key spend
	// with a tapscript root and the script spend path.
	SignMethod input.SignMethod

	// Output is the previous output being spent. Both its value and its
	// pkScript are committed to by the signature.
	Output *wire.TxOut

	// HashType is the sighash type the signature commits to.
	HashType txscript.SigHashType

	// InputIndex is the index of the input to sign within the
	// transaction.
	InputIndex int
}
