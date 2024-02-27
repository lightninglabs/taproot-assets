package asset

import (
	"context"
	"errors"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
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

// TapscriptTreeManager is used to persist a Tapscript tree, represented as
// either a slice of TapLeafs or a TapBranch. After a tree is stored, it can be
// referenced by its root hash. This root hash can be stored as a tweak for keys
// such as a batch internal key, group key, or asset script key.
type TapscriptTreeManager interface {
	// StoreTapscriptTree persists a Tapscript tree given a validated set of
	// TapLeafs or a TapBranch. If the store succeeds, the root hash of the
	// Tapscript tree is returned.
	StoreTapscriptTree(ctx context.Context,
		treeNodes TapscriptTreeNodes) (*chainhash.Hash, error)

	// LoadTapscriptTree loads the Tapscript tree with the given root hash,
	// and decodes the tree into a TapscriptTreeNodes object.
	LoadTapscriptTree(ctx context.Context,
		rootHash chainhash.Hash) (*TapscriptTreeNodes, error)

	// DeleteTapscriptTree deletes the Tapscript tree with the given root
	// hash.
	DeleteTapscriptTree(ctx context.Context, rootHash chainhash.Hash) error
}

var (
	// ErrTreeNotFound is returned when a TapscriptTreeManager attempts to
	// load a Tapscript tree, but found no tree nodes.
	ErrTreeNotFound = errors.New("tapscript tree not found")

	// ErrInvalidTapBranch is returned when decoding a slice of byte slices
	// to a TapBranch, and there are not exactly two slices.
	ErrInvalidTapBranch = errors.New(
		"tapscript tree branch must be 2 nodes",
	)
)
