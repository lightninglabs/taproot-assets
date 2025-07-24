package tapgarden

import (
	"context"
	"testing"
	"time"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockSupplyCommitManager is a mock implementation of the SupplyCommitManager
// interface for testing.
type MockSupplyCommitManager struct {
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

// SendEvent implements the SupplyCommitManager interface.
func (m *MockSupplyCommitManager) SendEvent(ctx context.Context,
	assetSpec asset.Specifier, event interface{}) error {

	args := m.Called(ctx, assetSpec, event)
	return args.Error(0)
}

// SendMintEvent implements the SupplyCommitManager interface.
func (m *MockSupplyCommitManager) SendMintEvent(ctx context.Context,
	assetSpec asset.Specifier, leafKey universe.UniqueLeafKey,
	issuanceProof universe.Leaf) error {

	args := m.Called(ctx, assetSpec, leafKey, issuanceProof)
	return args.Error(0)
}

// SendBurnEvent implements the SupplyCommitManager interface.
func (m *MockSupplyCommitManager) SendBurnEvent(ctx context.Context,
	assetSpec asset.Specifier, burnLeaf universe.BurnLeaf) error {

	args := m.Called(ctx, assetSpec, burnLeaf)
	return args.Error(0)
}

// TestSupplyCommitDelegationKeyFiltering tests that supply commit events
// are only sent for assets where we control the delegation key.
func TestSupplyCommitDelegationKeyFiltering(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	asset1 := asset.RandAsset(t, asset.Normal)
	asset2 := asset.RandAsset(t, asset.Normal)
	asset3 := asset.RandAsset(t, asset.Normal)

	tests := []struct {
		name                   string
		assets                 []*asset.Asset
		delegationKeyResponses map[asset.ID]bool
		expectedCallCount      int
	}{
		{
			name:   "all assets have delegation key",
			assets: []*asset.Asset{asset1, asset2},
			delegationKeyResponses: map[asset.ID]bool{
				asset1.ID(): true,
				asset2.ID(): true,
			},
			expectedCallCount: 2,
		},
		{
			name:   "only one asset has delegation key",
			assets: []*asset.Asset{asset1, asset2, asset3},
			delegationKeyResponses: map[asset.ID]bool{
				asset1.ID(): true,
				asset2.ID(): false,
				asset3.ID(): true,
			},
			expectedCallCount: 2,
		},
		{
			name:   "no assets have delegation key",
			assets: []*asset.Asset{asset1, asset2},
			delegationKeyResponses: map[asset.ID]bool{
				asset1.ID(): false,
				asset2.ID(): false,
			},
			expectedCallCount: 0,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// First, we'll set up our series of mocks, and then
			// record the intended responses for each of them.
			mockCommitter := &MockSupplyCommitManager{}
			mockDelegationChecker := &MockDelegationKeyChecker{}

			// Set up delegation key checker responses
			for assetID, hasKey := range tc.delegationKeyResponses {
				mockDelegationChecker.On(
					"HasDelegationKey", ctx, assetID,
				).Return(hasKey, nil)
			}

			// If we're expecting any calls, then we'll make sure to
			// register that here.
			if tc.expectedCallCount > 0 {
				//nolint:lll
				mockCommitter.On("SendMintEvent",
					ctx,
					mock.AnythingOfType("asset.Specifier"),
					mock.AnythingOfType(
						"universe.AssetLeafKey",
					),
					mock.AnythingOfType("universe.Leaf")).
					Return(nil).
					Times(tc.expectedCallCount)
			}

			// With the mocks registered above, we'll create a new
			// care taker instance that uses them.
			//nolint:lll
			caretaker := &BatchCaretaker{
				cfg: &BatchCaretakerConfig{
					GardenKit: GardenKit{
						MintSupplyCommitter:  mockCommitter,
						DelegationKeyChecker: mockDelegationChecker,
					},
				},
			}

			// Next, we'll create a series of proofs for each of the
			// assets.
			proofs := make(proof.AssetProofs)
			dummyTx := &wire.MsgTx{
				Version: 2,
				TxIn: []*wire.TxIn{{
					PreviousOutPoint: wire.OutPoint{},
					SignatureScript:  []byte{},
					Sequence:         0xffffffff,
				}},
			}
			block := wire.MsgBlock{
				Header: wire.BlockHeader{
					Version:   1,
					Timestamp: time.Now(),
					Bits:      0x207fffff,
				},
				Transactions: []*wire.MsgTx{dummyTx},
			}
			for i, a := range tc.assets {
				scriptKey := asset.ToSerialized(
					a.ScriptKey.PubKey,
				)
				testProof := proof.RandProof(
					t, a.Genesis, a.ScriptKey.PubKey, block,
					0, uint32(i),
				)
				proofs[scriptKey] = &testProof
			}

			// Call the internal method, then verify the expected
			// calls were made.
			err := caretaker.sendSupplyCommitEvents(
				ctx, tc.assets, nil, proofs,
			)
			require.NoError(t, err)
			mockCommitter.AssertExpectations(t)
			mockDelegationChecker.AssertExpectations(t)
		})
	}
}
