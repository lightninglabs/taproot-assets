package supplyverifier

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightninglabs/taproot-assets/universe/supplycommit"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// createTestPreCommitment creates a test pre-commitment for testing.
func createTestPreCommitment(t *testing.T, blockHeight uint32, txIndex uint32,
	outIdx uint32) supplycommit.PreCommitment {

	t.Helper()

	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{
				Hash:  chainhash.Hash{},
				Index: 0,
			},
		}},
		TxOut: []*wire.TxOut{{
			Value:    1000,
			PkScript: []byte{0x51},
		}},
	}

	privKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatalf("failed to create private key: %v", err)
	}
	internalKey := keychain.KeyDescriptor{
		PubKey: privKey.PubKey(),
		KeyLocator: keychain.KeyLocator{
			Family: keychain.KeyFamily(1),
			Index:  txIndex,
		},
	}

	groupPrivKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatalf("failed to create group private key: %v", err)
	}

	return supplycommit.PreCommitment{
		BlockHeight: blockHeight,
		MintingTxn:  tx,
		OutIdx:      outIdx,
		InternalKey: internalKey,
		GroupPubKey: *groupPrivKey.PubKey(),
	}
}

// createTestRootCommitment creates a test root commitment for testing.
func createTestRootCommitment(t *testing.T,
	blockHeight uint32) supplycommit.RootCommitment {

	t.Helper()

	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{
				Hash:  chainhash.Hash{},
				Index: 0,
			},
		}},
		TxOut: []*wire.TxOut{{
			Value:    1000,
			PkScript: []byte{0x51},
		}},
	}

	privKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatalf("failed to create private key: %v", err)
	}
	internalKey := keychain.KeyDescriptor{
		PubKey: privKey.PubKey(),
		KeyLocator: keychain.KeyLocator{
			Family: keychain.KeyFamily(1),
			Index:  0,
		},
	}

	commitmentBlock := supplycommit.CommitmentBlock{
		Height:    blockHeight,
		Hash:      chainhash.Hash{},
		TxIndex:   0,
		ChainFees: 1000,
	}

	return supplycommit.RootCommitment{
		Txn:             tx,
		TxOutIdx:        0,
		InternalKey:     internalKey,
		OutputKey:       privKey.PubKey(),
		CommitmentBlock: fn.Some(commitmentBlock),
		SpentCommitment: fn.None[wire.OutPoint](),
	}
}

// createTestAssetSpec creates a test asset specifier for testing.
func createTestAssetSpec(t *testing.T) asset.Specifier {
	t.Helper()

	privKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatalf("failed to create private key: %v", err)
	}

	return asset.NewSpecifierFromGroupKey(*privKey.PubKey())
}

// createTestDelegationKey creates a test delegation key for testing.
func createTestDelegationKey(t *testing.T) btcec.PublicKey {
	t.Helper()

	privKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatalf("failed to create private key: %v", err)
	}
	return *privKey.PubKey()
}

// createTestMetaReveal creates a test meta reveal with delegation key for
// testing.
func createTestMetaReveal(t *testing.T) *proof.MetaReveal {
	t.Helper()

	delegationKey := createTestDelegationKey(t)
	return &proof.MetaReveal{
		Data:          []byte("test-metadata"),
		Type:          proof.MetaOpaque,
		DelegationKey: fn.Some(delegationKey),
	}
}

// createTestMetaRevealWithKey creates a test MetaReveal with a specific
// delegation key.
func createTestMetaRevealWithKey(t *testing.T,
	delegationKey *btcec.PublicKey) *proof.MetaReveal {

	t.Helper()

	return &proof.MetaReveal{
		Data:          []byte("test-metadata"),
		Type:          proof.MetaOpaque,
		DelegationKey: fn.Some(*delegationKey),
	}
}

// createTestMintEvent creates a test mint event for testing.
// Note: This creates a minimal mint event that will fail processing due to
// missing RawProof, which is useful for testing error conditions.
func createTestMintEvent(t *testing.T,
	blockHeight uint32) supplycommit.NewMintEvent {

	t.Helper()

	privKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatalf("failed to create private key: %v", err)
	}
	scriptKey := privKey.PubKey()

	outpoint := wire.OutPoint{
		Hash:  chainhash.Hash{1, 2, 3},
		Index: 0,
	}

	assetGenesis := asset.Genesis{
		FirstPrevOut: wire.OutPoint{
			Hash:  chainhash.Hash{},
			Index: 0,
		},
		Tag:         "test-asset",
		OutputIndex: 0,
		Type:        asset.Normal,
	}

	assetID := assetGenesis.ID()
	testAsset := &asset.Asset{
		Version:   asset.V0,
		Genesis:   assetGenesis,
		Amount:    1000,
		ScriptKey: asset.NewScriptKey(scriptKey),
		GroupKey:  nil,
	}

	// Create the issuance proof (without RawProof, so it will fail
	// processing).
	issuanceProof := universe.Leaf{
		GenesisWithGroup: universe.GenesisWithGroup{
			Genesis: assetGenesis,
		},
		Asset: testAsset,
		Amt:   testAsset.Amount,
		// RawProof is intentionally omitted to test error handling.
	}

	leafKey := universe.AssetLeafKey{
		BaseLeafKey: universe.BaseLeafKey{
			OutPoint:  outpoint,
			ScriptKey: &asset.ScriptKey{PubKey: scriptKey},
		},
		AssetID: assetID,
	}

	return supplycommit.NewMintEvent{
		LeafKey:       leafKey,
		IssuanceProof: issuanceProof,
		MintHeight:    blockHeight,
	}
}

// createTestValidMintEvent creates a valid mint event.
func createTestValidMintEvent(t *testing.T, blockHeight uint32,
	delegationKey *btcec.PublicKey) supplycommit.NewMintEvent {

	t.Helper()

	privKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatalf("failed to create private key: %v", err)
	}
	scriptKey := privKey.PubKey()

	outpoint := wire.OutPoint{
		Hash:  chainhash.Hash{1, 2, 3},
		Index: 0,
	}

	assetGenesis := asset.Genesis{
		FirstPrevOut: wire.OutPoint{
			Hash:  chainhash.Hash{},
			Index: 0,
		},
		Tag:         "test-asset",
		OutputIndex: 0,
		Type:        asset.Normal,
	}

	// Create the pre-commitment output that matches what
	// tapgarden.PreCommitTxOut would create.
	preCommitTxOut, err := tapgarden.PreCommitTxOut(*delegationKey)
	if err != nil {
		t.Fatalf("failed to create pre-commit tx out: %v", err)
	}

	// Create an anchor transaction that includes the pre-commitment output.
	anchorTx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{
				Hash:  chainhash.Hash{},
				Index: 0,
			},
		}},
		TxOut: []*wire.TxOut{
			// First output: the pre-commitment output that matches
			// the delegation key.
			&preCommitTxOut,
			// Second output: a dummy output for the asset.
			{
				Value:    1000,
				PkScript: []byte{0x51},
			},
		},
	}

	block := wire.MsgBlock{
		Header: wire.BlockHeader{
			Version:    1,
			PrevBlock:  chainhash.Hash{},
			MerkleRoot: chainhash.Hash{},
			Timestamp:  time.Unix(1234567890, 0),
			Bits:       0x207fffff,
		},
		Transactions: []*wire.MsgTx{anchorTx},
	}

	// Create a valid proof using proof.RandProof, but we need to modify
	// the anchor transaction to have the correct structure.
	validProof := proof.RandProof(t, assetGenesis, scriptKey, block, 0, 1)

	// Replace the anchor transaction in the proof with our custom one
	// that has the correct pre-commitment output.
	validProof.AnchorTx = *anchorTx

	var proofBuf bytes.Buffer
	err = validProof.Encode(&proofBuf)
	if err != nil {
		t.Fatalf("failed to encode proof: %v", err)
	}

	assetID := assetGenesis.ID()
	testAsset := &asset.Asset{
		Version:   asset.V0,
		Genesis:   assetGenesis,
		Amount:    1000,
		ScriptKey: asset.NewScriptKey(scriptKey),
		GroupKey:  nil,
	}

	issuanceProof := universe.Leaf{
		GenesisWithGroup: universe.GenesisWithGroup{
			Genesis: assetGenesis,
		},
		Asset:    testAsset,
		Amt:      testAsset.Amount,
		RawProof: proofBuf.Bytes(),
	}

	leafKey := universe.AssetLeafKey{
		BaseLeafKey: universe.BaseLeafKey{
			OutPoint:  outpoint,
			ScriptKey: &asset.ScriptKey{PubKey: scriptKey},
		},
		AssetID: assetID,
	}

	return supplycommit.NewMintEvent{
		LeafKey:       leafKey,
		IssuanceProof: issuanceProof,
		MintHeight:    blockHeight,
	}
}

// TestFetchPreCommits tests the FetchPreCommits function with various
// scenarios.
func TestFetchPreCommits(t *testing.T) {
	ctx := context.Background()
	assetSpec := createTestAssetSpec(t)

	// Create a single delegation key to use consistently throughout test
	// cases.
	delegationKey := createTestDelegationKey(t)

	tests := []struct {
		name       string
		setupMocks func(
			*supplycommit.MockAssetLookup,
			*MockSupplyCommitView,
		)
		supplyCommit supplycommit.RootCommitment
		mintEvents   []supplycommit.NewMintEvent
		expectedLen  int
		expectError  bool
	}{
		{
			name: "successful fetch with no mint events",
			setupMocks: func(
				assetLookup *supplycommit.MockAssetLookup,
				commitView *MockSupplyCommitView,
			) {

				// Create test pre-commitments.
				preCommit1 := createTestPreCommitment(
					t, 100, 0, 0,
				)
				preCommit2 := createTestPreCommitment(
					t, 150, 1, 0,
				)
				preCommits := []supplycommit.PreCommitment{
					preCommit1, preCommit2,
				}

				commitView.On(
					"UnspentPrecommits", ctx, assetSpec,
					false,
				).Return(lfn.Ok(preCommits))
			},
			supplyCommit: createTestRootCommitment(t, 200),
			mintEvents:   []supplycommit.NewMintEvent{},
			expectedLen:  2,
			expectError:  false,
		},
		{
			name: "filter pre-commitments above supply commit " +
				"height",
			setupMocks: func(
				assetLookup *supplycommit.MockAssetLookup,
				commitView *MockSupplyCommitView,
			) {

				// Create test pre-commitments with mixed
				// heights.
				//
				// Below height.
				preCommit1 := createTestPreCommitment(
					t, 100, 0, 0,
				)

				// Above height.
				preCommit2 := createTestPreCommitment(
					t, 250, 1, 0,
				)

				// Below height.
				preCommit3 := createTestPreCommitment(
					t, 150, 2, 0,
				)

				preCommits := []supplycommit.PreCommitment{
					preCommit1, preCommit2, preCommit3,
				}

				commitView.On(
					"UnspentPrecommits", ctx, assetSpec,
					false,
				).Return(lfn.Ok(preCommits))
			},
			supplyCommit: createTestRootCommitment(t, 200),
			mintEvents:   []supplycommit.NewMintEvent{},
			// Only preCommit1 and preCommit3 should remain.
			expectedLen: 2,
			expectError: false,
		},
		{
			name: "supply commitment missing commitment block",
			setupMocks: func(
				assetLookup *supplycommit.MockAssetLookup,
				commitView *MockSupplyCommitView) {

				// No mocks needed as this should fail early
			},
			supplyCommit: func() supplycommit.RootCommitment {
				commit := createTestRootCommitment(t, 200)
				commit.CommitmentBlock =
					fn.None[supplycommit.CommitmentBlock]()
				return commit
			}(),
			mintEvents:  []supplycommit.NewMintEvent{},
			expectedLen: 0,
			expectError: true,
		},
		{
			name: "unspent pre-commitments fetch error",
			setupMocks: func(
				assetLookup *supplycommit.MockAssetLookup,
				commitView *MockSupplyCommitView,
			) {

				commitView.On(
					"UnspentPrecommits", ctx, assetSpec,
					false,
				).Return(lfn.Err[supplycommit.PreCommits](
					ErrCommitmentNotFound))
			},
			supplyCommit: createTestRootCommitment(t, 200),
			mintEvents:   []supplycommit.NewMintEvent{},
			expectedLen:  0,
			expectError:  true,
		},
		{
			name: "successful fetch with mint events",
			setupMocks: func(
				assetLookup *supplycommit.MockAssetLookup,
				commitView *MockSupplyCommitView,
			) {

				// Create test pre-commitments.
				preCommit1 := createTestPreCommitment(
					t, 100, 0, 0,
				)
				preCommits := []supplycommit.PreCommitment{
					preCommit1,
				}

				commitView.On(
					"UnspentPrecommits", ctx, assetSpec,
					false,
				).Return(lfn.Ok(preCommits))

				// Mock asset group fetch (needed by
				// FetchLatestAssetMetadata).
				dummyAssetGroup := &asset.AssetGroup{
					Genesis: &asset.Genesis{
						FirstPrevOut: wire.OutPoint{
							Hash:  chainhash.Hash{},
							Index: 0,
						},
						Tag:         "test-asset",
						OutputIndex: 0,
						Type:        asset.Normal,
					},
				}
				assetLookup.On(
					"QueryAssetGroupByGroupKey", ctx,
					mock.Anything,
				).Return(dummyAssetGroup, nil)

				// Mock successful asset metadata fetch for
				// delegation key. Use the same delegation key
				// as in the mint event.
				metaReveal := createTestMetaRevealWithKey(
					t, &delegationKey,
				)
				assetLookup.On(
					"FetchAssetMetaForAsset", ctx,
					mock.AnythingOfType("asset.ID"),
				).Return(metaReveal, nil)
			},
			supplyCommit: createTestRootCommitment(t, 200),
			mintEvents: []supplycommit.NewMintEvent{
				// This mint event has the correct anchor
				// transaction structure with a pre-commitment
				// output that matches the delegation key,
				// allowing successful processing.
				createTestValidMintEvent(
					t, 150, &delegationKey,
				),
			},
			// Original pre-commitment + new pre-commitment from
			// successfully processed mint event.
			expectedLen: 2,
			expectError: false,
		},
		{
			name: "mint event processing error",
			setupMocks: func(
				assetLookup *supplycommit.MockAssetLookup,
				commitView *MockSupplyCommitView) {

				// Create test pre-commitments.
				preCommit1 := createTestPreCommitment(
					t, 100, 0, 0,
				)
				preCommits := []supplycommit.PreCommitment{
					preCommit1,
				}

				commitView.On(
					"UnspentPrecommits", ctx, assetSpec,
					false,
				).Return(lfn.Ok(preCommits))

				// Mock asset group fetch (needed by
				// FetchLatestAssetMetadata).
				dummyAssetGroup := &asset.AssetGroup{
					Genesis: &asset.Genesis{
						FirstPrevOut: wire.OutPoint{
							Hash:  chainhash.Hash{},
							Index: 0,
						},
						Tag:         "test-asset",
						OutputIndex: 0,
						Type:        asset.Normal,
					},
				}
				assetLookup.On(
					"QueryAssetGroupByGroupKey", ctx,
					mock.Anything,
				).Return(dummyAssetGroup, nil)

				// Mock asset metadata fetch for delegation key.
				metaReveal := createTestMetaReveal(t)
				assetLookup.On(
					"FetchAssetMetaForAsset", ctx,
					mock.AnythingOfType("asset.ID"),
				).Return(metaReveal, nil)
			},
			supplyCommit: createTestRootCommitment(t, 200),
			mintEvents: []supplycommit.NewMintEvent{
				// Below supply commit height.
				createTestMintEvent(t, 150),
			},
			// Error in processing mint event.
			expectedLen: 0,
			expectError: true,
		},
		{
			name: "delegation key fetch error with mint events",
			setupMocks: func(
				assetLookup *supplycommit.MockAssetLookup,
				commitView *MockSupplyCommitView) {

				// Create test pre-commitments.
				preCommit1 := createTestPreCommitment(
					t, 100, 0, 0,
				)
				preCommits := []supplycommit.PreCommitment{
					preCommit1,
				}

				commitView.On("UnspentPrecommits", ctx,
					assetSpec, false,
				).Return(lfn.Ok(preCommits))

				// Mock asset group fetch (needed by
				// FetchLatestAssetMetadata).
				assetLookup.On("QueryAssetGroupByGroupKey", ctx,
					mock.Anything,
				).Return(
					(*asset.AssetGroup)(nil),
					ErrCommitmentNotFound,
				)
			},
			supplyCommit: createTestRootCommitment(t, 200),
			mintEvents: []supplycommit.NewMintEvent{
				// Below supply commit height.
				createTestMintEvent(t, 150),
			},
			expectedLen: 0,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mocks.
			mockAssetLookup := &supplycommit.MockAssetLookup{}
			mockCommitView := &MockSupplyCommitView{}

			// Setup mocks.
			tt.setupMocks(mockAssetLookup, mockCommitView)

			// Call the function under test.
			result, err := FetchPreCommits(
				ctx, mockAssetLookup, mockCommitView, assetSpec,
				tt.supplyCommit, tt.mintEvents,
			)

			// Check error expectation.
			if tt.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Len(t, result, tt.expectedLen)

			// Verify all mock expectations were met.
			mockAssetLookup.AssertExpectations(t)
			mockCommitView.AssertExpectations(t)
		})
	}
}

// TestFetchDelegationKey tests the FetchDelegationKey function.
func TestFetchDelegationKey(t *testing.T) {
	ctx := context.Background()
	assetSpec := createTestAssetSpec(t)

	tests := []struct {
		name        string
		setupMocks  func(*supplycommit.MockAssetLookup)
		expectError bool
	}{
		{
			name: "successful delegation key fetch",
			setupMocks: func(
				assetLookup *supplycommit.MockAssetLookup,
			) {

				// Mock asset group fetch (needed by
				// FetchLatestAssetMetadata).
				dummyAssetGroup := &asset.AssetGroup{
					Genesis: &asset.Genesis{
						FirstPrevOut: wire.OutPoint{
							Hash:  chainhash.Hash{},
							Index: 0,
						},
						Tag:         "test-asset",
						OutputIndex: 0,
						Type:        asset.Normal,
					},
				}
				assetLookup.On("QueryAssetGroupByGroupKey", ctx,
					mock.Anything,
				).Return(dummyAssetGroup, nil)

				metaReveal := createTestMetaReveal(t)
				assetLookup.On(
					"FetchAssetMetaForAsset", ctx,
					mock.AnythingOfType("asset.ID"),
				).Return(metaReveal, nil)
			},
			expectError: false,
		},
		{
			name: "asset metadata fetch error",
			setupMocks: func(
				assetLookup *supplycommit.MockAssetLookup,
			) {

				assetLookup.On(
					"QueryAssetGroupByGroupKey", ctx,
					mock.Anything,
				).Return(
					(*asset.AssetGroup)(nil),
					ErrCommitmentNotFound,
				)
			},
			expectError: true,
		},
		{
			name: "missing delegation key",
			setupMocks: func(
				assetLookup *supplycommit.MockAssetLookup,
			) {

				// Mock asset group fetch (needed by
				// FetchLatestAssetMetadata).
				dummyAssetGroup := &asset.AssetGroup{
					Genesis: &asset.Genesis{
						FirstPrevOut: wire.OutPoint{
							Hash:  chainhash.Hash{},
							Index: 0,
						},
						Tag:         "test-asset",
						OutputIndex: 0,
						Type:        asset.Normal,
					},
				}
				assetLookup.On(
					"QueryAssetGroupByGroupKey", ctx,
					mock.Anything,
				).Return(dummyAssetGroup, nil)

				pk := fn.None[btcec.PublicKey]()
				metaReveal := &proof.MetaReveal{
					Data:          []byte("test-metadata"),
					Type:          proof.MetaOpaque,
					DelegationKey: pk,
				}
				assetLookup.On(
					"FetchAssetMetaForAsset", ctx,
					mock.AnythingOfType("asset.ID"),
				).Return(metaReveal, nil)
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock.
			mockAssetLookup := &supplycommit.MockAssetLookup{}

			// Setup mock.
			tt.setupMocks(mockAssetLookup)

			// Call the function under test.
			result, err := FetchDelegationKey(
				ctx, mockAssetLookup, assetSpec,
			)

			// Check error expectation.
			if tt.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, result)

			// Verify all mock expectations were met.
			mockAssetLookup.AssertExpectations(t)
		})
	}
}
