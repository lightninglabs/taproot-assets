package supplyverifier

import (
	"context"
	"fmt"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightninglabs/taproot-assets/universe/supplycommit"
)

// OnChainLookup is an interface that is used to look up on-chain information
// about supply commitments.
type OnChainLookup interface {
	// UnspentPrecommits returns the set of unspent pre-commitments for a
	// given asset spec.
	UnspentPrecommits(ctx context.Context,
		assetSpec asset.Specifier) (supplycommit.PreCommits, error)

	// SupplyCommit returns the latest supply commitment for a given asset
	// spec.
	SupplyCommit(ctx context.Context,
		assetSpec asset.Specifier) (*supplycommit.RootCommitment, error)

	// LastVerifiedCommitment returns the last verified supply commitment
	// for a given asset spec.
	LastVerifiedCommitment(ctx context.Context,
		assetSpec asset.Specifier) (*supplycommit.RootCommitment, error)
}

// Environment is a struct that holds all the dependencies that the supply
// verifier needs to carry out its duties.
type Environment struct {
	// AssetSpec is the asset specifier that is used to identify the asset
	// that we're maintaining a supply commit for.
	AssetSpec asset.Specifier

	// Chain is our access to the current main chain.
	Chain tapgarden.ChainBridge

	// OnChainLookup is used to look up on-chain information.
	OnChainLookup OnChainLookup

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
