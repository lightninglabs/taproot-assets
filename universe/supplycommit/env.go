package supplycommit

import (
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightninglabs/taproot-assets/tapsend"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
)

// SupplySubTree is an enum that represents the different types of supply sub
// trees within the main supply tree. The sub trees are used to track how the
// supply shifts in response to: mints, burns, and ignores.
type SupplySubTree uint8

const (
	// MintTreeType is the sub tree that tracks mints.
	MintTreeType SupplySubTree = iota

	// BurnTreeType is the sub tree that tracks burns.
	BurnTreeType

	// IgnoreTreeType is the sub tree that tracks ignores.
	IgnoreTreeType
)

// String returns the string representation of the supply sub tree.
func (s SupplySubTree) String() string {
	switch s {
	case MintTreeType:
		return "mint"
	case BurnTreeType:
		return "burn"
	case IgnoreTreeType:
		return "ignore"
	default:
		return "unknown"
	}
}

// UniverseKey is the key used to identify the universe in the supply tree. This
// is scoped to a root supply tree for a given asset specifier.
func (s SupplySubTree) UniverseKey() [32]byte {
	treeName := s.String()
	treeKey := sha256.Sum256([]byte(treeName))

	return treeKey
}

// SupplyTrees is a map of the different supply sub trees. The keys are the sub
// trees, and the values are the actual trees.
type SupplyTrees map[SupplySubTree]mssmt.Tree

// FetchOrCreate fetches the sub tree for the given asset spec. If the sub tree
// doesn't exist, it will be created and returned.
func (s SupplyTrees) FetchOrCreate(treeType SupplySubTree) mssmt.Tree {
	tree, ok := s[treeType]
	if ok {
		return tree
	}

	// If the tree doesn't exist, we'll create it.
	tree = mssmt.NewCompactedTree(mssmt.NewDefaultStore())
	s[treeType] = tree

	return tree
}

// SupplyTreeView is an interface that allows the state machine to obtain an up
// to date snapshot of the root supply tree, as the sub trees (ignore, burn,
// mint) committed in the main supply tree.
type SupplyTreeView interface {
	// FetchSubStree returns the sub tree for the given asset spec. This
	// instance returned should be a copy, as mutations make take place in
	// the tree.
	FetchSubTree(assetSpec asset.Specifier,
		treeType SupplySubTree) lfn.Result[mssmt.Tree]

	// FetchSubTrees returns all the sub trees for the given asset spec.
	FetchSubTrees(assetSpec asset.Specifier) lfn.Result[SupplyTrees]

	// FetchRootSupplyTree returns the root supply tree which contains a
	// commitment to each of the sub trees.
	FetchRootSupplyTree(assetSpec asset.Specifier) lfn.Result[mssmt.Tree]
}

// PreCommitment is a struct that represents a pre-commitment to an asset
// commitment. A pre-commitment is an extra transaction that exists in the same
// on-chain transaction as a new issuance event.
//
// TODO(roasbeef): expand to burns?
type PreCommitment struct {
	// MintedAssetID is the asset ID of the asset that was minted.
	MintedAssetID asset.ID

	// BlockHeight is the block height of the transaction that contains the
	// pre-commitment.
	BlockHeight uint32

	// MintingTxn is the minting transaction itself that created the pre
	// commitment.
	MintingTxn *wire.MsgTx

	tapgarden.PreCommitmentOutput
}

// TxIn returns the transaction input that corresponds to the pre-commitment.
func (p *PreCommitment) TxIn() *wire.TxIn {
	return &wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  p.MintingTxn.TxHash(),
			Index: p.OutIdx,
		},
	}
}

// PreCommits is a slice of pre-commitments.
type PreCommits = []PreCommitment

// RootCommitment is the root commitment that contains the commitment to the the
// sub-supply trees for a given asset.
type RootCommitment struct {
	// Txn is the transaction that created the root commitment.
	Txn *wire.MsgTx

	// TxOutIdx is the index of the output in the transaction where the
	// commitment resides.
	TxOutIdx uint32

	// InternalKey is the internal key used to create the commitment output.
	InternalKey *btcec.PublicKey

	// Output key is the taproot output key used to create the commitment
	// output.
	OutputKey *btcec.PublicKey

	// SupplyRoot is the root of the supply tree that contains the set of
	// sub-commitments. The sum value of this tree is the outstanding supply
	// value.
	SupplyRoot *mssmt.BranchNode
}

// TxIn returns the transaction input that corresponds to the root commitment.
// This is used to spend the old commitment output, and create a new one.
func (r *RootCommitment) TxIn() *wire.TxIn {
	return &wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  r.Txn.TxHash(),
			Index: r.TxOutIdx,
		},
	}
}

// TxOut returns the transaction output that corresponds to the root commitment.
// This is used to create a new commitment output.
//
// TODO(roasbeef): expand, add support for tapscript as well
func (r *RootCommitment) TxOut() (*wire.TxOut, error) {
	// First, obtain the root hash of the supply tree.
	supplyRootHash := r.SupplyRoot.NodeHash()

	// We'll create a new unspendable output that contains a commitment to
	// the root.
	//
	// TODO(roasbeef): need other version info here/
	tapLeaf, err := asset.NewNonSpendableScriptLeaf(
		asset.PedersenVersion, supplyRootHash[:],
	)
	if err != nil {
		return nil, fmt.Errorf("unable to create leaf: %w", err)
	}

	var taprootKey *btcec.PublicKey
	if r.OutputKey == nil {
		tapscriptTree := txscript.AssembleTaprootScriptTree(tapLeaf)

		rootHash := tapscriptTree.RootNode.TapHash()
		taprootKey = txscript.ComputeTaprootOutputKey(
			r.InternalKey, rootHash[:],
		)
	} else {
		taprootKey = r.OutputKey
	}

	pkScript, err := txscript.PayToTaprootScript(taprootKey)
	if err != nil {
		return nil, fmt.Errorf("unable to create pk script: %w", err)
	}

	return &wire.TxOut{
		Value:    int64(tapsend.DummyAmtSats),
		PkScript: pkScript,
	}, nil
}

// RootCommitResp is the response type for the root commitment. It captures the
// fact that there may not be a root commitment yet for a given asset.
type RootCommitResp = lfn.Result[lfn.Option[RootCommitment]]

// CommitmentTracker is used to track the state of the pre-commitment and
// commitment outputs that are currently confirmed on-chain for a given asset
// specifier.
type CommitmentTracker interface {
	// UnspentPrecommits returns the set of unspent pre-commitments for a
	// given asset spec. The asset spec will only specify a group key, and
	// not also an asset ID.
	UnspentPrecommits(assetSpec asset.Specifier) lfn.Result[PreCommits]

	// SupplyCommit returns the root commitment for a given asset spec. From
	// the PoV of the chain, this is a singleton instance.
	SupplyCommit(assetSpec asset.Specifier) RootCommitResp
}

// Wallet the main wallet interface used to managed PSBT packets, and
// import public keys into the wallet.
type Wallet interface {
	// FundPsbt attaches enough inputs to the target PSBT packet for it to
	// be valid.
	FundPsbt(ctx context.Context, packet *psbt.Packet, minConfs uint32,
		feeRate chainfee.SatPerKWeight,
		changeIdx int32) (*tapsend.FundedPsbt, error)

	// SignAndFinalizePsbt fully signs and finalizes the target PSBT
	// packet.
	SignAndFinalizePsbt(context.Context, *psbt.Packet) (*psbt.Packet, error)

	// ImportTaprootOutput imports a new public key into the wallet, as a
	// P2TR output.
	ImportTaprootOutput(context.Context, *btcec.PublicKey) (btcutil.Address,
		error)

	// UnlockInput unlocks the set of target inputs after a batch or send
	// transaction is abandoned.
	UnlockInput(context.Context, wire.OutPoint) error

	// DeriveNextKey attempts to derive the *next* key within the keychain.
	// This method should return the next external child within this branch.
	DeriveNextKey(context.Context) (keychain.KeyDescriptor, error)
}

// Environment is a set of dependencies that a state machine may need to carry
// out the logic for a given state transition. All fields are to be considered
// immutable, and will be fixed for the lifetime of the state machine.
type Environment struct {
	// AssetSpec is the asset specifier that is used to identify the asset
	// that we're maintaining a supply commit for.
	AssetSpec asset.Specifier

	// TreeView is the interface that allows the state machine to obtain an
	// up to date snapshot of the root supply tree, and the relevant set of
	// subtrees.
	TreeView SupplyTreeView

	// Commitments is used to track the state of the pre-commitment and
	// commitment outputs that are currently confirmed on-chain.
	Commitments CommitmentTracker

	// Wallet is the main wallet interface used to managed PSBT packets, and
	// generate new keys.
	Wallet Wallet

	// Chain is our access to the current main chain.
	Chain tapgarden.ChainBridge
}

// Name returns the name of the environment. This is used to uniquely identify
// the environment of related state machines. For this state machine, the name
// is based on the channel ID.
func (e *Environment) Name() string {
	return fmt.Sprintf("universe_supply_commit(%v)", e.AssetSpec)
}
