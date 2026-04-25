package supplyverifier

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightninglabs/taproot-assets/tapscript"
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

// randProofWithGroupKey constructs a minimal proof that passes
// proof.Verify with real verifiers. It differs from proof.RandProof
// in two ways: the group private key is caller-supplied so
// MockGroupFetcher can be wired after construction, and GroupKey.RawKey
// is not cleared so IsGroupAnchor can re-derive the group pub key.
//
// The anchor tx output is derived from the tap commitment and internal
// key using the same derivation chain that verifyTaprootProof uses,
// so ExtractTaprootKey returns the same key that DeriveByAssetInclusion
// produces.
func randProofWithGroupKey(t *testing.T,
	groupPrivKey *btcec.PrivateKey,
	delegationKey *btcec.PublicKey) (proof.Proof, *btcec.PrivateKey) {

	t.Helper()

	scriptPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	scriptKey := scriptPrivKey.PubKey()

	assetGenesis := asset.Genesis{
		FirstPrevOut: wire.OutPoint{},
		Tag:          "test-asset",
		OutputIndex:  1,
		Type:         asset.Normal,
	}

	amount := uint64(1000)
	scriptKeyDesc := test.PubToKeyDesc(scriptKey)
	bip86ScriptKey := asset.NewScriptKeyBip86(scriptKeyDesc)
	protoAsset := asset.NewAssetNoErr(
		t, assetGenesis, amount, 0, 0, bip86ScriptKey, nil,
	)

	groupKey, _ := asset.RandGroupKeyWithSigner(
		t, groupPrivKey, assetGenesis, protoAsset,
	)

	groupReveal := asset.NewGroupKeyRevealV0(
		asset.ToSerialized(groupPrivKey.PubKey()),
		groupKey.TapscriptRoot,
	)

	mintCommitment, assets, err := commitment.Mint(
		nil, assetGenesis, groupKey, &commitment.AssetDetails{
			Type:      assetGenesis.Type,
			ScriptKey: test.PubToKeyDesc(scriptKey),
			Amount:    &amount,
		},
	)
	require.NoError(t, err)

	proofAsset := assets[0]

	_, commitmentProof, err := mintCommitment.Proof(
		proofAsset.TapCommitmentKey(),
		proofAsset.AssetCommitmentKey(),
	)
	require.NoError(t, err)

	siblingLeaf := txscript.NewBaseTapLeaf([]byte{1})
	siblingPreimage, err := commitment.NewPreimageFromLeaf(siblingLeaf)
	require.NoError(t, err)

	// Compute sibling hash using same path as
	// deriveTaprootKeysFromTapCommitment takes
	// when TapSiblingPreimage is set.
	siblingHash, err := siblingPreimage.TapHash()
	require.NoError(t, err)

	// internalKey must be the same in both the inclusion proof and
	// the taproot output derivation, so ExtractTaprootKey and
	// DeriveByAssetInclusion produce the same key.
	internalKey := test.RandPubKey(t)

	// Derive the taproot output key the same way verifyTaprootProof
	// does via deriveTaprootKeyFromTapCommitment.
	tapscriptRoot := mintCommitment.TapscriptRoot(siblingHash)
	taprootOutputKey := txscript.ComputeTaprootOutputKey(
		internalKey, tapscriptRoot[:],
	)
	pkScript, err := txscript.PayToTaprootScript(taprootOutputKey)
	require.NoError(t, err)

	preCommitTxOut, err := tapgarden.PreCommitTxOut(*delegationKey)
	require.NoError(t, err)

	// Anchor tx: pre-commit output at index 0,
	// asset-bearing P2TR at index 1.
	anchorTx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{},
		}},
		TxOut: []*wire.TxOut{
			&preCommitTxOut,
			{
				Value:    1000,
				PkScript: pkScript,
			},
		},
	}

	txHash := anchorTx.TxHash()
	merkleProof, err := proof.NewTxMerkleProof(
		[]*wire.MsgTx{anchorTx}, 0,
	)
	require.NoError(t, err)

	blockHeader := wire.BlockHeader{
		Version:    1,
		MerkleRoot: txHash,
		Bits:       0x207fffff,
	}

	return proof.Proof{
		PrevOut:       assetGenesis.FirstPrevOut,
		BlockHeader:   blockHeader,
		BlockHeight:   42,
		AnchorTx:      *anchorTx,
		TxMerkleProof: *merkleProof,
		Asset:         *proofAsset,
		InclusionProof: proof.TaprootProof{
			OutputIndex: 1,
			InternalKey: internalKey,
			CommitmentProof: &proof.CommitmentProof{
				Proof:              *commitmentProof,
				TapSiblingPreimage: siblingPreimage,
			},
		},
		ExclusionProofs: []proof.TaprootProof{
			{
				OutputIndex:     0,
				InternalKey:     delegationKey,
				CommitmentProof: nil,
				TapscriptProof: &proof.TapscriptProof{
					Bip86: true,
				},
			},
		},
		MetaReveal:     nil,
		GenesisReveal:  &assetGenesis,
		GroupKeyReveal: groupReveal,
	}, scriptPrivKey
}

// taprootKeySpendWitness signs a virtual transaction input with a key spend
// and returns the witness. Replicates the logic from proof.genTaprootKeySpend
// which is unexported and lives in proof/append_test.go.
func taprootKeySpendWitness(t *testing.T, privKey btcec.PrivateKey,
	virtualTx *wire.MsgTx, input, newAsset *asset.Asset,
	idx uint32) wire.TxWitness {

	t.Helper()

	virtualTxCopy := asset.VirtualTxWithInput(
		virtualTx, newAsset.LockTime, newAsset.RelativeLockTime,
		idx, nil,
	)
	sigHash, err := tapscript.InputKeySpendSigHash(
		virtualTxCopy, input, newAsset, idx, txscript.SigHashDefault,
	)
	require.NoError(t, err)

	taprootPrivKey := txscript.TweakTaprootPrivKey(privKey, nil)
	sig, err := schnorr.Sign(taprootPrivKey, sigHash)
	require.NoError(t, err)

	return wire.TxWitness{sig.Serialize()}
}

// randBurnProofWithGroupKey constructs a valid burn proof that passes
// burnProof.Verify with real verifiers. It builds on randProofWithGroupKey
// for the genesis proof, then constructs a transfer to a burn key with a
// valid Schnorr witness. The genesis proof is embedded as AdditionalInputs
// so proof.Verify can resolve the previous asset state.
func randBurnProofWithGroupKey(t *testing.T,
	groupPrivKey *btcec.PrivateKey,
	delegationKey *btcec.PublicKey) proof.Proof {

	t.Helper()

	// Build a valid genesis proof. The script key private key
	// is needed to sign the transfer witness.
	genesisProof, scriptPrivKey := randProofWithGroupKey(
		t, groupPrivKey, delegationKey,
	)

	prevOutpoint := wire.OutPoint{
		Hash:  genesisProof.AnchorTx.TxHash(),
		Index: genesisProof.InclusionProof.OutputIndex,
	}
	prevID := asset.PrevID{
		OutPoint: prevOutpoint,
		ID:       genesisProof.Asset.Genesis.ID(),
		ScriptKey: asset.ToSerialized(
			genesisProof.Asset.ScriptKey.PubKey,
		),
	}

	// Construct the burn asset. Script key is the burn key
	// derived from the prevID so IsBurn() returns true.
	burnScriptKey := asset.NewScriptKey(asset.DeriveBurnKey(prevID))
	burnGenesis := genesisProof.Asset.Genesis
	burnAmount := genesisProof.Asset.Amount

	burnAsset, err := asset.New(
		burnGenesis, burnAmount, 0, 0,
		burnScriptKey,
		genesisProof.Asset.GroupKey,
	)
	require.NoError(t, err)

	burnAsset.PrevWitnesses = []asset.Witness{{
		PrevID: &prevID,
	}}
	inputs := commitment.InputSet{
		prevID: &genesisProof.Asset,
	}
	virtualTx, _, err := tapscript.VirtualTx(burnAsset, inputs)
	require.NoError(t, err)

	witness := taprootKeySpendWitness(
		t, *scriptPrivKey, virtualTx,
		&genesisProof.Asset, burnAsset, 0,
	)
	burnAsset.PrevWitnesses[0].TxWitness = witness

	burnAssetCommitment, err := commitment.NewAssetCommitment(burnAsset)
	require.NoError(t, err)

	burnCommitment, err := commitment.NewTapCommitment(
		nil, burnAssetCommitment,
	)
	require.NoError(t, err)

	internalKey := test.RandPubKey(t)
	siblingLeaf := txscript.NewBaseTapLeaf([]byte{1})
	siblingPreimage, err := commitment.NewPreimageFromLeaf(siblingLeaf)
	require.NoError(t, err)

	siblingHash, err := siblingPreimage.TapHash()
	require.NoError(t, err)

	tapscriptRoot := burnCommitment.TapscriptRoot(siblingHash)
	taprootOutputKey := txscript.ComputeTaprootOutputKey(
		internalKey, tapscriptRoot[:],
	)
	pkScript, err := txscript.PayToTaprootScript(taprootOutputKey)
	require.NoError(t, err)

	burnAnchorTx := &wire.MsgTx{
		Version: 2,
		// No witness: proof.Verify only checks taproot derivation
		// and asset state transition.
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: prevOutpoint,
		}},
		TxOut: []*wire.TxOut{{
			Value:    1000,
			PkScript: pkScript,
		}},
	}

	burnTxHash := burnAnchorTx.TxHash()
	burnMerkleProof, err := proof.NewTxMerkleProof(
		[]*wire.MsgTx{burnAnchorTx}, 0,
	)
	require.NoError(t, err)

	burnBlockHeader := wire.BlockHeader{
		Version:    1,
		MerkleRoot: burnTxHash,
		Bits:       0x207fffff,
	}

	_, burnCommitmentProof, err := burnCommitment.Proof(
		burnAsset.TapCommitmentKey(),
		burnAsset.AssetCommitmentKey(),
	)
	require.NoError(t, err)

	genesisFile, err := proof.NewFile(proof.V0, genesisProof)
	require.NoError(t, err)

	return proof.Proof{
		PrevOut:       prevOutpoint,
		BlockHeader:   burnBlockHeader,
		BlockHeight:   genesisProof.BlockHeight + 1,
		AnchorTx:      *burnAnchorTx,
		TxMerkleProof: *burnMerkleProof,
		Asset:         *burnAsset,
		InclusionProof: proof.TaprootProof{
			OutputIndex: 0,
			InternalKey: internalKey,
			CommitmentProof: &proof.CommitmentProof{
				Proof:              *burnCommitmentProof,
				TapSiblingPreimage: siblingPreimage,
			},
		},
		AdditionalInputs: []proof.File{*genesisFile},
	}
}

// createVerifiableCommitment builds a RootCommitment whose chain anchor
// passes VerifyChainAnchor without a live chain. It uses a single-tx block
// so the merkle proof is empty (merkle root == tx hash), and MockChainBridge
// returns nil from VerifyBlock unconditionally. The TxOut is derived from
// RootCommitTxOut using an empty supply tree root, so the output script
// check passes. If txIns is nil, a single default input with a zero outpoint
// is used.
func createVerifiableCommitment(t *testing.T, blockHeight uint32,
	spentCommitment fn.Option[wire.OutPoint],
	txIns []*wire.TxIn) supplycommit.RootCommitment {

	t.Helper()

	if txIns == nil {
		txIns = []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{
				Hash:  chainhash.Hash{},
				Index: 0,
			},
		}}
	}

	emptyTree := mssmt.NewCompactedTree(mssmt.NewDefaultStore())
	supplyRoot, err := emptyTree.Root(context.Background())
	require.NoError(t, err)

	base := createTestRootCommitment(t, blockHeight)
	txOut, outputKey, err := supplycommit.RootCommitTxOut(
		base.InternalKey.PubKey, nil, supplyRoot.NodeHash(),
	)
	require.NoError(t, err)

	tx := &wire.MsgTx{
		Version: 2,
		TxIn:    txIns,
		TxOut:   []*wire.TxOut{txOut},
	}
	txHash := tx.TxHash()

	merkleProof, err := proof.NewTxMerkleProof(
		[]*wire.MsgTx{tx}, 0,
	)
	require.NoError(t, err)

	blockHeader := &wire.BlockHeader{
		Version:    1,
		MerkleRoot: txHash,
		Bits:       0x207fffff,
	}
	commitBlock := supplycommit.CommitmentBlock{
		Height:      blockHeight,
		Hash:        blockHeader.BlockHash(),
		TxIndex:     0,
		BlockHeader: blockHeader,
		MerkleProof: merkleProof,
	}

	base.Txn = tx
	base.TxOutIdx = 0
	base.OutputKey = outputKey
	base.SupplyRoot = supplyRoot
	base.CommitmentBlock = fn.Some(commitBlock)
	base.SpentCommitment = spentCommitment

	return base
}

// setupDelegationKeyMocks wires MockAssetLookup to return the given
// delegation key via the group-key path that FetchLatestAssetMetadata
// takes when the asset specifier carries a group key.
func setupDelegationKeyMocks(t *testing.T,
	mockLookup *supplycommit.MockAssetLookup,
	groupPubKey *btcec.PublicKey,
	delegKey *btcec.PublicKey) {

	t.Helper()

	metaReveal := createTestMetaRevealWithKey(t, delegKey)
	assetGenesis := asset.Genesis{
		Tag:  "test",
		Type: asset.Normal,
	}

	mockLookup.On(
		"QueryAssetGroupByGroupKey",
		mock.Anything,
		mock.Anything,
	).Return(&asset.AssetGroup{
		Genesis: &assetGenesis,
		GroupKey: &asset.GroupKey{
			GroupPubKey: *groupPubKey,
		},
	}, nil).Once()

	mockLookup.On(
		"FetchAssetMetaForAsset",
		mock.Anything,
		mock.Anything,
	).Return(metaReveal, nil).Once()
}

// buildValidIssuanceEntry constructs a NewMintEvent and decoded proof
// that pass verifyIssuanceLeaf when used with the returned assetSpec
// and delegationKey.
func buildValidIssuanceEntry(t *testing.T) (
	supplycommit.NewMintEvent,
	asset.Specifier,
	btcec.PublicKey,
) {

	t.Helper()

	groupPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	delegPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	delegationKey := delegPrivKey.PubKey()

	validProof, _ := randProofWithGroupKey(
		t, groupPrivKey, delegationKey,
	)

	var proofBuf bytes.Buffer
	err = validProof.Encode(&proofBuf)
	require.NoError(t, err)

	var decodedProof proof.Proof
	err = decodedProof.Decode(bytes.NewReader(proofBuf.Bytes()))
	require.NoError(t, err)

	extractedGenesis := decodedProof.Asset.Genesis
	extractedGroupKey := decodedProof.Asset.GroupKey

	assetSpec := asset.NewSpecifierFromGroupKey(
		extractedGroupKey.GroupPubKey,
	)

	decodedAsset := decodedProof.Asset
	outpoint := wire.OutPoint{
		Hash:  chainhash.Hash{1, 2, 3},
		Index: 0,
	}
	leafKey := universe.AssetLeafKey{
		BaseLeafKey: universe.BaseLeafKey{
			OutPoint: outpoint,
			ScriptKey: &asset.ScriptKey{
				PubKey: decodedProof.Asset.ScriptKey.PubKey,
			},
		},
		AssetID: extractedGenesis.ID(),
	}

	issuanceLeaf := universe.Leaf{
		GenesisWithGroup: universe.GenesisWithGroup{
			Genesis:  extractedGenesis,
			GroupKey: extractedGroupKey,
		},
		Asset:    &decodedAsset,
		Amt:      decodedProof.Asset.Amount,
		RawProof: proofBuf.Bytes(),
	}

	entry := supplycommit.NewMintEvent{
		LeafKey:       leafKey,
		IssuanceProof: issuanceLeaf,
		MintHeight:    decodedProof.BlockHeight,
	}

	return entry, assetSpec, *delegationKey
}
