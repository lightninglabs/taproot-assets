package supplyverifier

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightninglabs/taproot-assets/universe/supplycommit"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
)

var (
	// ErrCommitmentNotFound is returned when a supply commitment is not
	// found.
	ErrCommitmentNotFound = fmt.Errorf("commitment not found")

	// ErrPrevCommitmentNotFound is returned when we try to fetch a
	// previous supply commitment, but it is not found in the database.
	ErrPrevCommitmentNotFound = fmt.Errorf("previous supply commitment " +
		"not found")
)

// SupplyCommitView is an interface that is used to look up supply commitments
// and pre-commitments.
type SupplyCommitView interface {
	// UnspentPrecommits returns the set of unspent pre-commitments for a
	// given asset spec.
	UnspentPrecommits(ctx context.Context,
		assetSpec asset.Specifier,
		localIssuerOnly bool) lfn.Result[supplycommit.PreCommits]

	// SupplyCommit returns the latest supply commitment for a given asset
	// spec.
	SupplyCommit(ctx context.Context,
		assetSpec asset.Specifier) supplycommit.RootCommitResp

	// FetchCommitmentByOutpoint fetches a supply commitment by its outpoint
	// and group key. If no commitment is found, it returns
	// ErrCommitmentNotFound.
	FetchCommitmentByOutpoint(ctx context.Context,
		assetSpec asset.Specifier,
		outpoint wire.OutPoint) (*supplycommit.RootCommitment, error)

	// FetchCommitmentBySpentOutpoint fetches a supply commitment by the
	// outpoint it spent and group key. If no commitment is found, it
	// returns ErrCommitmentNotFound.
	FetchCommitmentBySpentOutpoint(ctx context.Context,
		assetSpec asset.Specifier,
		spentOutpoint wire.OutPoint) (*supplycommit.RootCommitment,
		error)

	// FetchStartingCommitment fetches the very first supply commitment of
	// an asset group. If no commitment is found, it returns
	// ErrCommitmentNotFound.
	FetchStartingCommitment(ctx context.Context,
		assetSpec asset.Specifier) (*supplycommit.RootCommitment, error)

	// InsertSupplyCommit inserts a supply commitment into the database.
	InsertSupplyCommit(ctx context.Context,
		assetSpec asset.Specifier, commit supplycommit.RootCommitment,
		leaves supplycommit.SupplyLeaves) error
}

// SupplyTreeView is an interface that is used to look up the root (upper)
// supply tree, subtrees, and leaves.
//
// nolint: lll
type SupplyTreeView interface {
	// FetchSupplyTrees returns a copy of the root supply tree and subtrees
	// for the given asset spec.
	FetchSupplyTrees(ctx context.Context, spec asset.Specifier) (mssmt.Tree,
		*supplycommit.SupplyTrees, error)

	// FetchSubTrees returns all the subtrees for the given asset spec.
	FetchSubTrees(ctx context.Context, assetSpec asset.Specifier,
		blockHeightEnd fn.Option[uint32]) lfn.Result[supplycommit.SupplyTrees]

	// FetchSupplyLeavesByHeight fetches all supply leaves for a given asset
	// specifier within a given block height range.
	FetchSupplyLeavesByHeight(ctx context.Context, spec asset.Specifier,
		startHeight,
		endHeight uint32) lfn.Result[supplycommit.SupplyLeaves]
}

// Environment is a struct that holds all the dependencies that the supply
// verifier needs to carry out its duties.
type Environment struct {
	// AssetSpec is the asset specifier that is used to identify the asset
	// that we're maintaining a supply commit for.
	AssetSpec asset.Specifier

	// Chain is our access to the current main chain.
	Chain tapgarden.ChainBridge

	// SupplyCommitView allows us to look up supply commitments and
	// pre-commitments.
	SupplyCommitView SupplyCommitView

	// ErrChan is the channel that is used to send errors to the caller.
	ErrChan chan<- error

	// QuitChan is the channel that is used to signal that the state
	// machine should quit.
	QuitChan <-chan struct{}
}

// Name returns the name of the environment.
func (e *Environment) Name() string {
	return fmt.Sprintf("supply_verifier(%s)", e.AssetSpec.String())
}
