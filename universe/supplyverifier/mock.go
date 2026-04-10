package supplyverifier

import (
	"context"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/universe/supplycommit"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/stretchr/testify/mock"
)

// MockSupplyCommitView is a mock implementation of the SupplyCommitView
// interface.
type MockSupplyCommitView struct {
	mock.Mock
}

func (m *MockSupplyCommitView) UnspentPrecommits(ctx context.Context,
	assetSpec asset.Specifier,
	localIssuerOnly bool) lfn.Result[supplycommit.PreCommits] {

	args := m.Called(ctx, assetSpec, localIssuerOnly)
	return args.Get(0).(lfn.Result[supplycommit.PreCommits])
}

func (m *MockSupplyCommitView) FetchStartingCommitment(ctx context.Context,
	assetSpec asset.Specifier) (*supplycommit.RootCommitment, error) {

	args := m.Called(ctx, assetSpec)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*supplycommit.RootCommitment), args.Error(1)
}

func (m *MockSupplyCommitView) FetchLatestCommitment(ctx context.Context,
	assetSpec asset.Specifier) (*supplycommit.RootCommitment, error) {

	args := m.Called(ctx, assetSpec)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*supplycommit.RootCommitment), args.Error(1)
}

func (m *MockSupplyCommitView) FetchCommitmentByOutpoint(ctx context.Context,
	assetSpec asset.Specifier,
	outpoint wire.OutPoint) (*supplycommit.RootCommitment, error) {

	args := m.Called(ctx, assetSpec, outpoint)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*supplycommit.RootCommitment), args.Error(1)
}

func (m *MockSupplyCommitView) FetchCommitmentBySpentOutpoint(
	ctx context.Context, assetSpec asset.Specifier,
	spentOutpoint wire.OutPoint) (*supplycommit.RootCommitment, error) {

	args := m.Called(ctx, assetSpec, spentOutpoint)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*supplycommit.RootCommitment), args.Error(1)
}

func (m *MockSupplyCommitView) InsertSupplyCommit(ctx context.Context,
	assetSpec asset.Specifier, commit supplycommit.RootCommitment,
	leaves supplycommit.SupplyLeaves,
	unspentPreCommits supplycommit.PreCommits) error {

	args := m.Called(ctx, assetSpec, commit, leaves, unspentPreCommits)
	return args.Error(0)
}

// MockSupplyTreeView is a mock implementation of the SupplyTreeView interface.
type MockSupplyTreeView struct {
	mock.Mock
}

func (m *MockSupplyTreeView) FetchSupplyTrees(ctx context.Context,
	spec asset.Specifier) (mssmt.Tree, *supplycommit.SupplyTrees, error) {

	args := m.Called(ctx, spec)
	if args.Get(0) == nil {
		return nil, nil, args.Error(2)
	}
	return args.Get(0).(mssmt.Tree),
		args.Get(1).(*supplycommit.SupplyTrees),
		args.Error(2)
}

func (m *MockSupplyTreeView) FetchSubTrees(ctx context.Context,
	assetSpec asset.Specifier,
	blockHeightEnd fn.Option[uint32]) lfn.Result[supplycommit.SupplyTrees] {

	args := m.Called(ctx, assetSpec, blockHeightEnd)
	return args.Get(0).(lfn.Result[supplycommit.SupplyTrees])
}

func (m *MockSupplyTreeView) FetchSupplyLeavesByHeight(ctx context.Context,
	spec asset.Specifier,
	startHeight, endHeight uint32) lfn.Result[supplycommit.SupplyLeaves] {

	args := m.Called(ctx, spec, startHeight, endHeight)
	return args.Get(0).(lfn.Result[supplycommit.SupplyLeaves])
}

// MockGroupFetcher is a mock implementation of tapgarden.GroupFetcher.
type MockGroupFetcher struct {
	mock.Mock
}

func (m *MockGroupFetcher) FetchGroupByGroupKey(ctx context.Context,
	groupKey *btcec.PublicKey) (*asset.AssetGroup, error) {

	args := m.Called(ctx, groupKey)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*asset.AssetGroup), args.Error(1)
}
