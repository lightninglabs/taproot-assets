package tapfreighter

import (
	"context"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockBurnSupplyCommitter is a mock implementation of the BurnSupplyCommitter
// interface for testing.
type MockBurnSupplyCommitter struct {
	mock.Mock
}

// MockDelegationKeyChecker is a mock implementation of the DelegationKeyChecker
// interface for testing.
type MockDelegationKeyChecker struct {
	mock.Mock
}

// HasDelegationKey implements the DelegationKeyChecker interface.
func (m *MockDelegationKeyChecker) HasDelegationKey(ctx context.Context,
	assetID asset.ID) (bool, error) {

	args := m.Called(ctx, assetID)
	return args.Bool(0), args.Error(1)
}

// SendEvent implements the BurnSupplyCommitter interface.
func (m *MockBurnSupplyCommitter) SendEvent(ctx context.Context,
	assetSpec asset.Specifier, event interface{}) error {

	args := m.Called(ctx, assetSpec, event)
	return args.Error(0)
}

// SendBurnEvent implements the BurnSupplyCommitter interface.
func (m *MockBurnSupplyCommitter) SendBurnEvent(ctx context.Context,
	assetSpec asset.Specifier, burnLeaf universe.BurnLeaf) error {

	args := m.Called(ctx, assetSpec, burnLeaf)
	return args.Error(0)
}

// delegationKeyResult represents the result of a delegation key check.
type delegationKeyResult struct {
	hasKey bool
	err    error
}

// chainPorterTestSetup holds the configuration for a chain porter test.
type chainPorterTestSetup struct {
	burns                  []*AssetBurn
	delegationKeyResponses map[asset.ID]delegationKeyResult
	expectedBurnCalls      int
	expectError            bool
	expectNoManager        bool
	managerError           error
}

// setupChainPorterTest creates a configured ChainPorter with mocks based on the
// test setup.
func setupChainPorterTest(t *testing.T,
	ctx context.Context, setup chainPorterTestSetup,
) (*ChainPorter, *MockBurnSupplyCommitter, *MockDelegationKeyChecker) {

	mockDelegationChecker := &MockDelegationKeyChecker{}

	// Only set up delegation key expectations if we have a manager.
	if !setup.expectNoManager {
		for assetID, result := range setup.delegationKeyResponses {
			mockDelegationChecker.On(
				"HasDelegationKey", ctx, assetID,
			).Return(
				result.hasKey, result.err,
			)
		}
	}

	var (
		mockManager *MockBurnSupplyCommitter
		manager     BurnSupplyCommitter
	)

	// If we expect a manager, set it up with the expected burn calls.
	if !setup.expectNoManager {
		mockManager = &MockBurnSupplyCommitter{}

		if setup.expectedBurnCalls > 0 {
			call := mockManager.On("SendBurnEvent",
				ctx,
				mock.AnythingOfType("asset.Specifier"),
				mock.AnythingOfType("universe.BurnLeaf"))

			if setup.managerError != nil {
				call.Return(setup.managerError)
			} else {
				call.Return(nil)
			}
			call.Times(setup.expectedBurnCalls)
		}

		manager = mockManager
	}

	porter := &ChainPorter{
		cfg: &ChainPorterConfig{
			BurnCommitter:        manager,
			DelegationKeyChecker: mockDelegationChecker,
		},
	}

	return porter, mockManager, mockDelegationChecker
}

// TestChainPorterSupplyCommitEvents tests the comprehensive functionality of
// supply commit burn event processing including delegation key filtering, error
// handling, and various burn scenarios.
func TestChainPorterSupplyCommitEvents(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// We'll make some test data, including asset IDs, anchor transaction
	// ID, and a series of burns.
	assetID1 := asset.RandID(t)
	assetID2 := asset.RandID(t)
	assetID3 := asset.RandID(t)
	anchorTxid := chainhash.Hash{1, 2, 3, 4}
	groupKey := test.RandPubKey(t)

	// Create various burn scenarios
	burnWithoutGroup := &AssetBurn{
		AssetID:    assetID1[:],
		Amount:     1000,
		AnchorTxid: anchorTxid,
		GroupKey:   nil,
		Note:       "burn without group",
	}

	burnWithGroup := &AssetBurn{
		AssetID:    assetID2[:],
		Amount:     500,
		AnchorTxid: anchorTxid,
		GroupKey:   groupKey.SerializeCompressed(),
		Note:       "burn with group",
	}

	burnForFiltering := &AssetBurn{
		AssetID:    assetID3[:],
		Amount:     250,
		AnchorTxid: anchorTxid,
		GroupKey:   groupKey.SerializeCompressed(),
		Note:       "burn for filtering test",
	}

	burnWithInvalidGroup := &AssetBurn{
		AssetID:    assetID1[:],
		Amount:     100,
		AnchorTxid: anchorTxid,
		GroupKey:   []byte{0xFF, 0xFF},
		Note:       "burn with invalid group",
	}

	//nolint:lll
	tests := []struct {
		name  string
		setup chainPorterTestSetup
	}{
		{
			name: "successful burn events with mixed group keys",
			setup: chainPorterTestSetup{
				burns: []*AssetBurn{
					burnWithoutGroup, burnWithGroup,
				},
				delegationKeyResponses: map[asset.ID]delegationKeyResult{
					assetID1: {hasKey: false, err: nil},
					assetID2: {hasKey: true, err: nil},
				},
				expectedBurnCalls: 1,
				expectError:       false,
			},
		},
		{
			name: "delegation key filtering - only some have " +
				"delegation keys",
			setup: chainPorterTestSetup{
				burns: []*AssetBurn{
					burnWithoutGroup, burnWithGroup, burnForFiltering,
				},
				delegationKeyResponses: map[asset.ID]delegationKeyResult{
					assetID1: {hasKey: false, err: nil},
					assetID2: {hasKey: false, err: nil},
					assetID3: {hasKey: true, err: nil},
				},
				expectedBurnCalls: 1,
				expectError:       false,
			},
		},
		{
			name: "delegation key filtering - no assets have " +
				"delegation keys",
			setup: chainPorterTestSetup{
				burns: []*AssetBurn{
					burnWithoutGroup, burnWithGroup,
				},
				delegationKeyResponses: map[asset.ID]delegationKeyResult{
					assetID1: {hasKey: false, err: nil},
					assetID2: {hasKey: false, err: nil},
				},
				expectedBurnCalls: 0,
				expectError:       false,
			},
		},
		{
			name: "delegation key checker error - filtered out " +
				"gracefully",
			setup: chainPorterTestSetup{
				burns: []*AssetBurn{
					burnWithoutGroup, burnWithGroup,
				},
				delegationKeyResponses: map[asset.ID]delegationKeyResult{
					assetID1: {hasKey: false, err: assert.AnError},
					assetID2: {hasKey: true, err: nil},
				},
				expectedBurnCalls: 1,
				expectError:       false,
			},
		},
		{
			name: "burn committer error",
			setup: chainPorterTestSetup{
				burns: []*AssetBurn{burnWithGroup},
				delegationKeyResponses: map[asset.ID]delegationKeyResult{
					assetID2: {hasKey: true, err: nil},
				},
				expectedBurnCalls: 1,
				managerError:      assert.AnError,
				expectError:       true,
			},
		},
		{
			name: "no burn committer configured",
			setup: chainPorterTestSetup{
				burns: []*AssetBurn{burnWithoutGroup, burnWithGroup},
				delegationKeyResponses: map[asset.ID]delegationKeyResult{
					assetID1: {hasKey: false, err: nil},
					assetID2: {hasKey: true, err: nil},
				},
				expectNoManager: true,
				expectError:     false,
			},
		},
		{
			name: "invalid group key bytes",
			setup: chainPorterTestSetup{
				burns: []*AssetBurn{burnWithInvalidGroup},
				delegationKeyResponses: map[asset.ID]delegationKeyResult{
					assetID1: {hasKey: true, err: nil},
				},
				expectedBurnCalls: 0,
				expectError:       true,
			},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// We'll set up the test, call the method with the
			// specified args, then assert the results.
			//nolint:lll
			porter, mockManager, mockDelegationChecker := setupChainPorterTest(
				t, ctx, tc.setup,
			)

			err := porter.sendBurnSupplyCommitEvents(
				ctx, tc.setup.burns,
			)

			if tc.setup.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			if mockManager != nil {
				mockManager.AssertExpectations(t)
			}
			if !tc.setup.expectNoManager {
				mockDelegationChecker.AssertExpectations(t)
			}
		})
	}
}
