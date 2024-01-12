package asset

import (
	"context"
	"errors"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/lightninglabs/lndclient"
)

// GenesisSigner is used to sign the assetID using the group key public key
// for a given asset.
type GenesisSigner interface {
	// SignVirtualTx generates a signature according to the passed signing
	// descriptor and TX.
	SignVirtualTx(signDesc *lndclient.SignDescriptor, tx *wire.MsgTx,
		prevOut *wire.TxOut) (*schnorr.Signature, error)
}

// GenesisTxBuilder is used to construct the virtual transaction that represents
// asset minting for grouped assets. This transaction is used to generate a
// group witness that authorizes the minting of an asset into the asset group.
type GenesisTxBuilder interface {
	// BuildGenesisTx constructs a virtual transaction and prevOut that
	// represent the genesis state transition for a grouped asset. This
	// output is used to create a group witness for the grouped asset.
	BuildGenesisTx(newAsset *Asset) (*wire.MsgTx, *wire.TxOut, error)
}

// TapscriptTreeStore is used to persist a Tapscript tree associated with an
// internal key. The resulting tweaked key can be an asset script key, group
// key, or on-chain Taproot output key. The internal key does not need to be
// stored prior to storing the associated Tapscript tree. The associated
// Tapscript tree cannot be updated once stored.
type TapscriptTreeStore interface {
	// StoreTapscriptTree persists a Tapscript tree associated with an
	// internal key. Storing an empty Tapscript tree is a no-op, and storing
	// a Tapscript tree for a key that already has a stored Tapscript tree
	// returns a concrete error. The internal key for the control block of
	// the Tapscript object must be set to the internal key.
	StoreTapscriptTree(ctx context.Context, pubKey SerializedKey,
		tapTree *waddrmgr.Tapscript) error

	// LoadTapscriptTree loads a Tapscript tree associated with an internal
	// key. Loading a Tapscript tree for a key that does not have a stored
	// Tapscript tree returns a concrete error.
	LoadTapscriptTree(ctx context.Context,
		pubKey SerializedKey) (*waddrmgr.Tapscript, error)
}

var (
	TreeNotFound      = errors.New("tapscript tree not found")
	TreeAlreadyStored = errors.New("tapscript tree already stored")
)
