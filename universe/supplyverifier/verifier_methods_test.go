package supplyverifier

import (
	"context"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	internaltest "github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightninglabs/taproot-assets/universe/supplycommit"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestVerifyIgnoreLeaf tests verifyIgnoreLeaf.
func TestVerifyIgnoreLeaf(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	groupPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	assetSpec := asset.NewSpecifierFromGroupKey(
		*groupPrivKey.PubKey(),
	)

	delegPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	ignTuple := universe.IgnoreTuple{
		PrevID: asset.PrevID{
			OutPoint: wire.OutPoint{
				Hash:  chainhash.Hash{1, 2, 3},
				Index: 0,
			},
		},
		Amount:      100,
		BlockHeight: 50,
	}

	digest, err := ignTuple.Digest()
	require.NoError(t, err)

	sig, err := schnorr.Sign(delegPrivKey, digest[:])
	require.NoError(t, err)

	signedIgnore := universe.NewSignedIgnoreTuple(
		ignTuple,
		universe.IgnoreSig{Signature: *sig},
	)
	validEntry := supplycommit.NewIgnoreEvent{
		SignedIgnoreTuple: signedIgnore,
	}

	sigBytes := sig.Serialize()
	assetID := ignTuple.ID

	matchingGroup := &asset.AssetGroup{
		GroupKey: &asset.GroupKey{
			GroupPubKey: *groupPrivKey.PubKey(),
		},
	}

	tests := []struct {
		name       string
		setupMocks func(
			*internaltest.MockSigner,
			*supplycommit.MockAssetLookup,
		)
		expectError bool
		errContains string
	}{
		{
			name: "signer returns wrong bytes",
			setupMocks: func(
				_ *internaltest.MockSigner,
				_ *supplycommit.MockAssetLookup,
			) {
			},
			expectError: true,
			errContains: "failed to verify signed ignore",
		},
		{
			name: "asset lookup error",
			setupMocks: func(
				ms *internaltest.MockSigner,
				ml *supplycommit.MockAssetLookup,
			) {

				ms.Signature = sigBytes
				ml.On(
					"QueryAssetGroupByID",
					mock.Anything, assetID,
				).Return(
					nil,
					fmt.Errorf("db error"),
				).Once()
			},
			expectError: true,
			errContains: "failed to query asset group",
		},
		{
			name: "group key mismatch",
			setupMocks: func(
				ms *internaltest.MockSigner,
				ml *supplycommit.MockAssetLookup,
			) {

				ms.Signature = sigBytes

				wrongKey, err :=
					btcec.NewPrivateKey()
				require.NoError(t, err)

				wrongGroup := &asset.AssetGroup{
					GroupKey: &asset.GroupKey{
						GroupPubKey: *wrongKey.
							PubKey(),
					},
				}
				ml.On(
					"QueryAssetGroupByID",
					mock.Anything, assetID,
				).Return(
					wrongGroup, nil,
				).Once()
			},
			expectError: true,
			errContains: "asset group key for ignore leaf",
		},
		{
			name: "valid ignore entry",
			setupMocks: func(
				ms *internaltest.MockSigner,
				ml *supplycommit.MockAssetLookup,
			) {

				ms.Signature = sigBytes
				ml.On(
					"QueryAssetGroupByID",
					mock.Anything, assetID,
				).Return(
					matchingGroup, nil,
				).Once()
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSigner := internaltest.NewMockSigner()
			mockLookup := &supplycommit.MockAssetLookup{}

			tt.setupMocks(mockSigner, mockLookup)

			v := Verifier{
				assetLog: log,
				cfg: VerifierCfg{
					Lnd: &lndclient.LndServices{
						Signer: mockSigner,
					},
					AssetLookup: mockLookup,
				},
			}

			err := v.verifyIgnoreLeaf(
				ctx, assetSpec,
				*delegPrivKey.PubKey(),
				validEntry,
			)

			if tt.expectError {
				require.Error(t, err)
				require.ErrorContains(
					t, err, tt.errContains,
				)
				return
			}

			require.NoError(t, err)
			mockLookup.AssertExpectations(t)
		})
	}
}

// TestVerifyIssuanceLeaf tests verifyIssuanceLeaf.
func TestVerifyIssuanceLeaf(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	t.Run("missing raw proof", func(t *testing.T) {
		assetSpec := createTestAssetSpec(t)
		delegPrivKey, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		v := Verifier{assetLog: log}
		err = v.verifyIssuanceLeaf(
			ctx, assetSpec,
			*delegPrivKey.PubKey(),
			createTestMintEvent(t, 100),
		)

		require.Error(t, err)
		require.ErrorContains(
			t, err, "unable to decode issuance proof",
		)
	})

	fieldTests := []struct {
		name        string
		mutate      func(*supplycommit.NewMintEvent)
		mutateSpec  func(*asset.Specifier)
		expectError bool
		errContains string
	}{
		{
			name: "mint height mismatch",
			mutate: func(e *supplycommit.NewMintEvent) {
				e.MintHeight = 999
			},
			expectError: true,
			errContains: "mint height in issuance leaf does " +
				"not match",
		},
		{
			name: "amount mismatch",
			mutate: func(e *supplycommit.NewMintEvent) {
				e.IssuanceProof.Amt = 999
			},
			expectError: true,
			errContains: "amount in issuance leaf does not " +
				"match",
		},
		{
			name: "is burn true",
			mutate: func(e *supplycommit.NewMintEvent) {
				e.IssuanceProof.IsBurn = true
			},
			expectError: true,
			errContains: "IsBurn is unexpectedly true",
		},
		{
			name: "asset deep equal mismatch",
			mutate: func(e *supplycommit.NewMintEvent) {
				assetCopy := *e.IssuanceProof.Asset
				assetCopy.Amount = 999
				e.IssuanceProof.Asset = &assetCopy
			},
			expectError: true,
			errContains: "asset in issuance leaf does not " +
				"match",
		},
		{
			name: "genesis mismatch",
			mutate: func(e *supplycommit.NewMintEvent) {
				gen := e.IssuanceProof.Genesis
				gen.Tag = "wrong-tag"
				e.IssuanceProof.GenesisWithGroup =
					universe.GenesisWithGroup{
						Genesis: gen,
						GroupKey: e.IssuanceProof.
							GroupKey,
					}
			},
			expectError: true,
			errContains: "genesis in issuance leaf does not " +
				"match",
		},
		{
			name: "group key mismatch in leaf",
			mutate: func(e *supplycommit.NewMintEvent) {
				wrongKey, err := btcec.NewPrivateKey()
				require.NoError(t, err)

				wrongGroupKey := &asset.GroupKey{
					GroupPubKey: *wrongKey.PubKey(),
				}
				e.IssuanceProof.GenesisWithGroup =
					universe.GenesisWithGroup{
						Genesis: e.IssuanceProof.
							Genesis,
						GroupKey: wrongGroupKey,
					}
			},
			expectError: true,
			errContains: "group key in issuance leaf does " +
				"not match",
		},
		{
			name: "leaf key asset ID mismatch",
			mutate: func(e *supplycommit.NewMintEvent) {
				origKey := e.LeafKey.(universe.AssetLeafKey)
				e.LeafKey = universe.AssetLeafKey{
					BaseLeafKey: universe.BaseLeafKey{
						OutPoint: origKey.OutPoint,
						ScriptKey: origKey.
							ScriptKey,
					},
					AssetID: asset.ID{0xff, 0xff, 0xff},
				}
			},
			expectError: true,
			errContains: "issuance leaf key asset id does " +
				"not match",
		},
		{
			name: "asset spec group key mismatch",
			mutateSpec: func(spec *asset.Specifier) {
				wrongKey, err := btcec.NewPrivateKey()
				require.NoError(t, err)
				*spec = asset.NewSpecifierFromGroupKey(
					*wrongKey.PubKey(),
				)
			},
			expectError: true,
			errContains: "asset group key in issuance proof " +
				"does not match",
		},
		{
			name:        "valid entry/happy path",
			expectError: false,
		},
	}

	entry, assetSpec, delegKey := buildValidIssuanceEntry(t)

	for _, tt := range fieldTests {
		t.Run(tt.name, func(t *testing.T) {
			entryCopy := entry
			specCopy := assetSpec

			if tt.mutate != nil {
				tt.mutate(&entryCopy)
			}

			if tt.mutateSpec != nil {
				tt.mutateSpec(&specCopy)
			}

			cfg := VerifierCfg{
				ChainBridge:  tapgarden.NewMockChainBridge(),
				GroupFetcher: &MockGroupFetcher{},
			}
			v := Verifier{assetLog: log, cfg: cfg}

			err := v.verifyIssuanceLeaf(
				ctx, specCopy, delegKey, entryCopy,
			)

			if tt.expectError {
				require.Error(t, err)
				require.ErrorContains(
					t, err, tt.errContains,
				)
				return
			}

			require.NoError(t, err)
		})
	}
}

// TestVerifySupplyLeaves tests verifySupplyLeaves.
func TestVerifySupplyLeaves(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	assetSpec := createTestAssetSpec(t)

	delegPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	v := Verifier{assetLog: log}

	t.Run("empty leaves", func(t *testing.T) {
		err := v.verifySupplyLeaves(
			ctx, assetSpec,
			*delegPrivKey.PubKey(),
			supplycommit.SupplyLeaves{},
		)
		require.NoError(t, err)
	})

	t.Run("issuance leaf decode error", func(t *testing.T) {
		leaves := supplycommit.SupplyLeaves{
			IssuanceLeafEntries: []supplycommit.NewMintEvent{
				createTestMintEvent(t, 100),
			},
		}

		err := v.verifySupplyLeaves(
			ctx, assetSpec,
			*delegPrivKey.PubKey(),
			leaves,
		)

		require.Error(t, err)
		require.ErrorContains(
			t, err, "issuance leaf failed verification",
		)
	})
}

// TestVerifyInitialCommit covers error paths for
// verifyInitialCommit. The happy path (tree reconstruction + root check)
// is tested in TestVerifyCommit.
func TestVerifyInitialCommit(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	assetSpec := createTestAssetSpec(t)
	commitment := createTestRootCommitment(t, 200)

	tests := []struct {
		name          string
		commitment    supplycommit.RootCommitment
		setupMockView func(*MockSupplyCommitView)
		preCommits    supplycommit.PreCommits
		expectError   bool
		errContains   string
	}{
		{
			name: "spent commitment set on initial commit",
			commitment: func() supplycommit.RootCommitment {
				c := commitment
				c.SpentCommitment = fn.Some(
					wire.OutPoint{
						Hash:  chainhash.Hash{9},
						Index: 0,
					},
				)
				return c
			}(),
			setupMockView: func(_ *MockSupplyCommitView) {},
			expectError:   true,
			errContains:   "initial supply commitment must not",
		},
		{
			name:       "already verified same commit point",
			commitment: commitment,
			setupMockView: func(mv *MockSupplyCommitView) {
				mv.On(
					"FetchStartingCommitment",
					mock.Anything,
					mock.Anything,
				).Return(
					&commitment, nil,
				).Once()
			},
			expectError: false,
		},
		{
			name:       "alternative initial commitment found",
			commitment: commitment,
			setupMockView: func(mv *MockSupplyCommitView) {
				alt := createTestRootCommitment(t, 100)
				alt.Txn.LockTime = 99
				mv.On(
					"FetchStartingCommitment",
					mock.Anything,
					mock.Anything,
				).Return(&alt, nil).Once()
			},
			expectError: true,
			errContains: "found alternative initial commitment",
		},
		{
			name:       "fetch starting commitment error",
			commitment: commitment,
			setupMockView: func(mv *MockSupplyCommitView) {
				mv.On(
					"FetchStartingCommitment",
					mock.Anything,
					mock.Anything,
				).Return(
					nil,
					fmt.Errorf("db error"),
				).Once()
			},
			expectError: true,
			errContains: "failed to check for starting",
		},
		{
			name:       "no pre-commits provided",
			commitment: commitment,
			setupMockView: func(mv *MockSupplyCommitView) {
				mv.On(
					"FetchStartingCommitment",
					mock.Anything,
					mock.Anything,
				).Return(
					nil, ErrCommitmentNotFound,
				).Once()
			},
			preCommits:  supplycommit.PreCommits{},
			expectError: true,
			errContains: "no unspent supply pre-commitment",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockView := &MockSupplyCommitView{}
			tt.setupMockView(mockView)

			v := Verifier{
				assetLog: log,
				cfg: VerifierCfg{
					SupplyCommitView: mockView,
				},
			}

			err := v.verifyInitialCommit(
				ctx, assetSpec,
				tt.commitment,
				supplycommit.SupplyLeaves{},
				tt.preCommits,
			)

			if tt.expectError {
				require.Error(t, err)
				require.ErrorContains(
					t, err, tt.errContains,
				)
				return
			}

			require.NoError(t, err)
			mockView.AssertExpectations(t)
		})
	}
}

// TestVerifyIncrementalCommit covers error paths for verifyIncrementalCommit.
// The happy path is covered by TestVerifyCommit.
func TestVerifyIncrementalCommit(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	assetSpec := createTestAssetSpec(t)

	spentOutPoint := wire.OutPoint{
		Hash:  chainhash.Hash{5, 6, 7},
		Index: 1,
	}

	tests := []struct {
		name          string
		commitment    func(t *testing.T) supplycommit.RootCommitment
		setupMockView func(*MockSupplyCommitView)
		setupTreeView func(*MockSupplyTreeView)
		preCommits    supplycommit.PreCommits
		expectError   bool
		errContains   string
		errorIs       error
	}{
		{
			name: "missing spent commitment outpoint",
			commitment: func(
				t *testing.T,
			) supplycommit.RootCommitment {

				c := createTestRootCommitment(t, 200)
				c.SpentCommitment =
					fn.None[wire.OutPoint]()
				return c
			},
			setupMockView: func(
				_ *MockSupplyCommitView,
			) {
			},
			setupTreeView: func(
				_ *MockSupplyTreeView,
			) {
			},
			expectError: true,
			errContains: "missing spent supply commitment",
		},
		{
			name: "previous commitment not found",
			commitment: func(
				t *testing.T,
			) supplycommit.RootCommitment {

				c := createTestRootCommitment(t, 200)
				c.SpentCommitment =
					fn.Some(spentOutPoint)
				return c
			},
			setupMockView: func(
				mv *MockSupplyCommitView,
			) {

				mv.On(
					"FetchCommitmentByOutpoint",
					mock.Anything,
					mock.Anything,
					spentOutPoint,
				).Return(
					nil, ErrCommitmentNotFound,
				).Once()
			},
			setupTreeView: func(
				_ *MockSupplyTreeView,
			) {
			},
			expectError: true,
			errorIs:     ErrPrevCommitmentNotFound,
		},
		{
			name: "commitment does not spend previous outpoint",
			commitment: func(
				t *testing.T,
			) supplycommit.RootCommitment {

				c := createTestRootCommitment(t, 200)
				c.SpentCommitment =
					fn.Some(spentOutPoint)
				return c
			},
			setupMockView: func(
				mv *MockSupplyCommitView,
			) {

				prev := createTestRootCommitment(t, 100)
				mv.On(
					"FetchCommitmentByOutpoint",
					mock.Anything,
					mock.Anything,
					spentOutPoint,
				).Return(&prev, nil).Once()
			},
			setupTreeView: func(
				_ *MockSupplyTreeView,
			) {
			},
			expectError: true,
			errContains: "does not spend",
		},
		{
			name: "fetch supply trees fails",
			commitment: func(
				t *testing.T,
			) supplycommit.RootCommitment {

				c := createTestRootCommitment(t, 200)
				c.SpentCommitment =
					fn.Some(spentOutPoint)
				c.Txn = &wire.MsgTx{
					Version: 2,
					TxIn: []*wire.TxIn{{
						PreviousOutPoint: spentOutPoint,
					}},
					TxOut: []*wire.TxOut{{
						Value:    1000,
						PkScript: []byte{0x51},
					}},
				}
				return c
			},
			setupMockView: func(
				mv *MockSupplyCommitView,
			) {

				prev := createTestRootCommitment(t, 100)
				mv.On(
					"FetchCommitmentByOutpoint",
					mock.Anything,
					mock.Anything,
					spentOutPoint,
				).Return(&prev, nil).Once()
			},
			setupTreeView: func(
				mtv *MockSupplyTreeView,
			) {

				mtv.On(
					"FetchSupplyTrees",
					mock.Anything,
					mock.Anything,
				).Return(
					nil,
					nil,
					fmt.Errorf("db error"),
				).Once()
			},
			preCommits:  supplycommit.PreCommits{},
			expectError: true,
			errContains: "unable to fetch spent root supply tree",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockView := &MockSupplyCommitView{}
			tt.setupMockView(mockView)

			mockTreeView := &MockSupplyTreeView{}
			tt.setupTreeView(mockTreeView)

			v := Verifier{
				assetLog: log,
				cfg: VerifierCfg{
					SupplyCommitView: mockView,
					SupplyTreeView:   mockTreeView,
				},
			}

			commit := tt.commitment(t)
			err := v.verifyIncrementalCommit(
				ctx, assetSpec, commit,
				supplycommit.SupplyLeaves{},
				tt.preCommits,
			)

			if tt.expectError {
				require.Error(t, err)

				if tt.errorIs != nil {
					require.ErrorIs(t, err, tt.errorIs)
				} else if tt.errContains != "" {
					require.ErrorContains(
						t, err, tt.errContains,
					)
				}

				return
			}

			require.NoError(t, err)
			mockView.AssertExpectations(t)
			mockTreeView.AssertExpectations(t)
		})
	}
}

// TestVerifyCommit exercises VerifyCommit e2e.
func TestVerifyCommit(t *testing.T) {
	t.Parallel()

	t.Run("chain anchor gate", func(t *testing.T) {
		ctx := context.Background()
		assetSpec := createTestAssetSpec(t)
		commitment := createTestRootCommitment(t, 200)

		cfg := VerifierCfg{
			ChainBridge:      tapgarden.NewMockChainBridge(),
			SupplyCommitView: &MockSupplyCommitView{},
		}
		v := Verifier{assetLog: log, cfg: cfg}

		err := v.VerifyCommit(
			ctx, assetSpec, commitment,
			supplycommit.SupplyLeaves{},
			supplycommit.PreCommits{},
		)

		require.Error(t, err)
		require.ErrorContains(
			t, err, "unable to verify supply commitment",
		)
	})

	t.Run("already stored", func(t *testing.T) {
		ctx := context.Background()
		assetSpec := createTestAssetSpec(t)
		commitment := createVerifiableCommitment(
			t, 200, fn.None[wire.OutPoint](), nil,
		)

		mockView := &MockSupplyCommitView{}
		mockView.On(
			"FetchCommitmentByOutpoint",
			mock.Anything,
			mock.Anything,
			mock.Anything,
		).Return(&commitment, nil).Once()

		cfg := VerifierCfg{
			ChainBridge:      tapgarden.NewMockChainBridge(),
			SupplyCommitView: mockView,
		}
		v := Verifier{assetLog: log, cfg: cfg}

		err := v.VerifyCommit(
			ctx, assetSpec, commitment,
			supplycommit.SupplyLeaves{},
			supplycommit.PreCommits{},
		)

		require.NoError(t, err)
		mockView.AssertExpectations(t)
	})

	t.Run("not enough pre-commits", func(t *testing.T) {
		ctx := context.Background()

		groupPrivKey, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		delegKey := createTestDelegationKey(t)
		assetSpec := asset.NewSpecifierFromGroupKey(
			*groupPrivKey.PubKey(),
		)

		commitment := createVerifiableCommitment(
			t, 200, fn.None[wire.OutPoint](), nil,
		)

		mockView := &MockSupplyCommitView{}
		mockLookup := &supplycommit.MockAssetLookup{}

		mockView.On(
			"FetchCommitmentByOutpoint",
			mock.Anything,
			mock.Anything,
			mock.Anything,
		).Return(nil, ErrCommitmentNotFound).Once()

		setupDelegationKeyMocks(
			t, mockLookup, groupPrivKey.PubKey(), &delegKey,
		)
		cfg := VerifierCfg{
			ChainBridge:      tapgarden.NewMockChainBridge(),
			SupplyCommitView: mockView,
			AssetLookup:      mockLookup,
		}
		v := Verifier{
			assetLog: log,
			cfg:      cfg,
		}

		leaves := supplycommit.SupplyLeaves{
			IssuanceLeafEntries: []supplycommit.NewMintEvent{
				createTestMintEvent(t, 100),
			},
		}

		err = v.VerifyCommit(
			ctx, assetSpec, commitment,
			leaves, supplycommit.PreCommits{},
		)

		require.Error(t, err)
		require.ErrorContains(
			t, err, "not enough unspent supply pre-commitment",
		)
		mockView.AssertExpectations(t)
		mockLookup.AssertExpectations(t)
	})

	t.Run("initial commit happypath with empty leaves", func(t *testing.T) {
		ctx := context.Background()

		groupPrivKey, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		assetSpec := asset.NewSpecifierFromGroupKey(
			*groupPrivKey.PubKey(),
		)
		delegKey := createTestDelegationKey(t)

		pc := createTestPreCommitment(t, 100, 0, 0)
		pcOutPoint := pc.OutPoint()

		commitment := createVerifiableCommitment(
			t, 200,
			fn.None[wire.OutPoint](),
			[]*wire.TxIn{{PreviousOutPoint: pcOutPoint}},
		)

		mockView := &MockSupplyCommitView{}
		mockLookup := &supplycommit.MockAssetLookup{}

		mockView.On(
			"FetchCommitmentByOutpoint",
			mock.Anything,
			mock.Anything,
			commitment.CommitPoint(),
		).Return(nil, ErrCommitmentNotFound).Once()

		setupDelegationKeyMocks(
			t, mockLookup, groupPrivKey.PubKey(), &delegKey,
		)

		mockView.On(
			"FetchStartingCommitment",
			mock.Anything,
			mock.Anything,
		).Return(nil, ErrCommitmentNotFound).Once()

		cfg := VerifierCfg{
			ChainBridge:      tapgarden.NewMockChainBridge(),
			SupplyCommitView: mockView,
			AssetLookup:      mockLookup,
			GroupFetcher:     &MockGroupFetcher{},
		}
		v := Verifier{
			assetLog: log,
			cfg:      cfg,
		}

		err = v.VerifyCommit(
			ctx, assetSpec, commitment,
			supplycommit.SupplyLeaves{},
			supplycommit.PreCommits{pc},
		)

		require.NoError(t, err)
		mockView.AssertExpectations(t)
		mockLookup.AssertExpectations(t)
	})

	t.Run("incremental commit happy path", func(t *testing.T) {
		ctx := context.Background()

		groupPrivKey, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		assetSpec := asset.NewSpecifierFromGroupKey(
			*groupPrivKey.PubKey(),
		)
		delegKey := createTestDelegationKey(t)

		prevCommit := createVerifiableCommitment(
			t, 100, fn.None[wire.OutPoint](), nil,
		)
		spentOutPoint := prevCommit.CommitPoint()

		currCommit := createVerifiableCommitment(
			t, 200,
			fn.Some(spentOutPoint),
			[]*wire.TxIn{{PreviousOutPoint: spentOutPoint}},
		)

		mockView := &MockSupplyCommitView{}
		mockLookup := &supplycommit.MockAssetLookup{}
		mockTreeView := &MockSupplyTreeView{}

		mockView.On(
			"FetchCommitmentByOutpoint",
			mock.Anything,
			mock.Anything,
			currCommit.CommitPoint(),
		).Return(nil, ErrCommitmentNotFound).Once()

		setupDelegationKeyMocks(
			t, mockLookup, groupPrivKey.PubKey(), &delegKey,
		)

		mockView.On(
			"FetchCommitmentByOutpoint",
			mock.Anything,
			mock.Anything,
			spentOutPoint,
		).Return(&prevCommit, nil).Once()

		emptyTree := mssmt.NewCompactedTree(mssmt.NewDefaultStore())
		emptySupplyTrees := &supplycommit.SupplyTrees{}
		mockTreeView.On(
			"FetchSupplyTrees",
			mock.Anything,
			mock.Anything,
		).Return(emptyTree, emptySupplyTrees, nil).Once()

		cfg := VerifierCfg{
			ChainBridge:      tapgarden.NewMockChainBridge(),
			SupplyCommitView: mockView,
			AssetLookup:      mockLookup,
			GroupFetcher:     &MockGroupFetcher{},
			SupplyTreeView:   mockTreeView,
		}
		v := Verifier{
			assetLog: log,
			cfg:      cfg,
		}

		err = v.VerifyCommit(
			ctx, assetSpec, currCommit,
			supplycommit.SupplyLeaves{},
			supplycommit.PreCommits{},
		)

		require.NoError(t, err)
		mockView.AssertExpectations(t)
		mockLookup.AssertExpectations(t)
		mockTreeView.AssertExpectations(t)
	})
}

// TestVerifyBurnLeaf tests verifyBurnLeaf.
func TestVerifyBurnLeaf(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	t.Run("nil burn proof", func(t *testing.T) {
		assetSpec := createTestAssetSpec(t)
		v := Verifier{assetLog: log}

		err := v.verifyBurnLeaf(
			ctx, assetSpec,
			supplycommit.NewBurnEvent{
				BurnLeaf: universe.BurnLeaf{
					BurnProof: nil,
				},
			},
		)

		require.Error(t, err)
		require.ErrorContains(t, err, "missing burn proof")
	})

	t.Run("valid burn proof", func(t *testing.T) {
		groupPrivKey, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		delegPrivKey, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		burnProof := randBurnProofWithGroupKey(
			t, groupPrivKey, delegPrivKey.PubKey(),
		)

		extractedGroupKey := burnProof.Asset.GroupKey
		assetSpec := asset.NewSpecifierFromGroupKey(
			extractedGroupKey.GroupPubKey,
		)

		burnGenesis := burnProof.Asset.Genesis
		mockGroupFetcher := &MockGroupFetcher{}
		mockGroupFetcher.On(
			"FetchGroupByGroupKey",
			mock.Anything,
			mock.Anything,
		).Return(&asset.AssetGroup{
			Genesis:  &burnGenesis,
			GroupKey: extractedGroupKey,
		}, nil)

		scriptKey := asset.RandScriptKey(t)
		burnEntry := supplycommit.NewBurnEvent{
			BurnLeaf: universe.BurnLeaf{
				UniverseKey: universe.AssetLeafKey{
					BaseLeafKey: universe.BaseLeafKey{
						OutPoint:  burnProof.OutPoint(),
						ScriptKey: &scriptKey,
					},
					AssetID: burnProof.Asset.Genesis.ID(),
				},
				BurnProof: &burnProof,
			},
		}

		v := Verifier{
			assetLog: log,
			cfg: VerifierCfg{
				ChainBridge:  tapgarden.NewMockChainBridge(),
				GroupFetcher: mockGroupFetcher,
			},
		}

		err = v.verifyBurnLeaf(ctx, assetSpec, burnEntry)
		require.NoError(t, err)
	})
}
