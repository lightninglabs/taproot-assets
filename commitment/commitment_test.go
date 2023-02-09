package commitment

import (
	"math/rand"
	"testing"
	"testing/quick"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/internal/test"
	"github.com/lightninglabs/taro/mssmt"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

func randAssetDetails(t *testing.T, assetType asset.Type) *AssetDetails {
	t.Helper()
	var amount *uint64
	if assetType != asset.Collectible {
		amount = new(uint64)
		*amount = rand.Uint64()
	}
	return &AssetDetails{
		Type: assetType,
		ScriptKey: keychain.KeyDescriptor{
			PubKey: test.RandPrivKey(t).PubKey(),
		},
		Amount:           amount,
		LockTime:         rand.Uint64(),
		RelativeLockTime: rand.Uint64(),
	}
}

func randAsset(t *testing.T, genesis asset.Genesis,
	groupKey *asset.GroupKey) *asset.Asset {

	t.Helper()

	scriptKey := asset.RandScriptKey(t)
	return asset.RandAssetWithValues(t, genesis, groupKey, scriptKey)
}

// TestNewAssetCommitment tests edge cases around NewAssetCommitment.
func TestNewAssetCommitment(t *testing.T) {
	t.Parallel()

	genesis1 := asset.RandGenesis(t, asset.Normal)
	genesis1Collectible := asset.RandGenesis(t, asset.Collectible)
	genesis2 := asset.RandGenesis(t, asset.Normal)
	groupKey1 := asset.RandGroupKey(t, genesis1)
	groupKey1Collectible := asset.RandGroupKey(t, genesis1Collectible)
	groupKey2 := asset.RandGroupKey(t, genesis2)
	copyOfGroupKey1Collectible := &asset.GroupKey{
		RawKey:      groupKey1Collectible.RawKey,
		GroupPubKey: groupKey1Collectible.GroupPubKey,
		Sig:         groupKey1Collectible.Sig,
	}

	testCases := []struct {
		name string
		f    func() []*asset.Asset
		err  error
	}{
		{
			name: "group key mismatch",
			f: func() []*asset.Asset {
				return []*asset.Asset{
					randAsset(t, genesis1, groupKey1),
					randAsset(t, genesis1, groupKey2),
				}
			},
			err: ErrAssetGroupKeyMismatch,
		},
		{
			name: "no group key asset id mismatch",
			f: func() []*asset.Asset {
				return []*asset.Asset{
					randAsset(t, genesis1, nil),
					randAsset(t, genesis2, nil),
				}
			},
			err: ErrAssetGenesisMismatch,
		},
		{
			name: "same group key asset id mismatch",
			f: func() []*asset.Asset {
				return []*asset.Asset{
					randAsset(t, genesis1, groupKey1),
					randAsset(t, genesis2, groupKey1),
				}
			},
			err: ErrAssetGenesisInvalidSig,
		},
		{
			name: "duplicate script key",
			f: func() []*asset.Asset {
				asset1 := randAsset(t, genesis1, groupKey1)
				asset2 := randAsset(t, genesis1, groupKey1)
				asset1.ScriptKey = asset2.ScriptKey
				return []*asset.Asset{asset1, asset2}
			},
			err: ErrAssetDuplicateScriptKey,
		},
		{
			name: "valid normal asset commitment with group key",
			f: func() []*asset.Asset {
				return []*asset.Asset{
					randAsset(t, genesis1, groupKey1),
					randAsset(t, genesis1, groupKey1),
				}
			},
			err: nil,
		},
		{
			name: "valid collectible asset commitment with " +
				"group key",
			f: func() []*asset.Asset {
				return []*asset.Asset{
					randAsset(
						t, genesis1Collectible,
						groupKey1Collectible,
					),
					randAsset(
						t, genesis1Collectible,
						copyOfGroupKey1Collectible,
					),
				}
			},
			err: nil,
		},
		{
			name: "valid normal asset commitment without group " +
				"key",
			f: func() []*asset.Asset {
				return []*asset.Asset{
					randAsset(t, genesis1, nil),
					randAsset(t, genesis1, nil),
				}
			},
			err: nil,
		},
		{
			name: "valid collectible asset commitment without " +
				"group key",
			f: func() []*asset.Asset {
				return []*asset.Asset{
					randAsset(t, genesis1Collectible, nil),
					randAsset(t, genesis1Collectible, nil),
				}
			},
			err: nil,
		},
	}

	for _, testCase := range testCases {
		success := t.Run(testCase.name, func(t *testing.T) {
			assets := testCase.f()
			commitment, err := NewAssetCommitment(assets...)
			require.ErrorIs(t, err, testCase.err)
			if testCase.err == nil {
				// Ensure that the Taro commitment was properly set.
				require.NotZero(t, commitment.TaroCommitmentKey())

				for _, asset := range assets {
					asset, _, err = commitment.AssetProof(
						asset.AssetCommitmentKey(),
					)
					require.NoError(t, err)
					require.NotNil(t, asset)
				}
			}
		})
		if !success {
			return
		}
	}
}

// TestMintTaroCommitment tests edge cases around minting new commitments.
func TestMintTaroCommitment(t *testing.T) {
	t.Parallel()

	genesisNormal := asset.RandGenesis(t, asset.Normal)
	genesisCollectible := asset.RandGenesis(t, asset.Collectible)
	pubKey := keychain.KeyDescriptor{
		PubKey: test.RandPrivKey(t).PubKey(),
	}

	testCases := []struct {
		name  string
		g     asset.Genesis
		f     func() *AssetDetails
		valid bool
	}{
		{
			name: "normal with nil amount",
			g:    genesisNormal,
			f: func() *AssetDetails {
				return &AssetDetails{
					Type:             asset.Normal,
					ScriptKey:        pubKey,
					Amount:           nil,
					LockTime:         1337,
					RelativeLockTime: 6,
				}
			},
			valid: false,
		},
		{
			name: "normal with zero amount",
			g:    genesisNormal,
			f: func() *AssetDetails {
				zero := uint64(0)
				return &AssetDetails{
					Type:             asset.Normal,
					ScriptKey:        pubKey,
					Amount:           &zero,
					LockTime:         1337,
					RelativeLockTime: 6,
				}
			},
			valid: false,
		},
		{
			name: "normal with amount",
			g:    genesisNormal,
			f: func() *AssetDetails {
				amount := uint64(10)
				return &AssetDetails{
					Type:             asset.Normal,
					ScriptKey:        pubKey,
					Amount:           &amount,
					LockTime:         1337,
					RelativeLockTime: 6,
				}
			},
			valid: true,
		},
		{
			name: "collectible with invalid amount",
			g:    genesisCollectible,
			f: func() *AssetDetails {
				two := uint64(2)
				return &AssetDetails{
					Type:             asset.Collectible,
					ScriptKey:        pubKey,
					Amount:           &two,
					LockTime:         1337,
					RelativeLockTime: 6,
				}
			},
			valid: false,
		},
		{
			name: "collectible with nil amount",
			g:    genesisCollectible,
			f: func() *AssetDetails {
				return &AssetDetails{
					Type:             asset.Collectible,
					ScriptKey:        pubKey,
					Amount:           nil,
					LockTime:         1337,
					RelativeLockTime: 6,
				}
			},
			valid: true,
		},
		{
			name: "collectible with one amount",
			g:    genesisCollectible,
			f: func() *AssetDetails {
				one := uint64(1)
				return &AssetDetails{
					Type:             asset.Collectible,
					ScriptKey:        pubKey,
					Amount:           &one,
					LockTime:         1337,
					RelativeLockTime: 6,
				}
			},
			valid: true,
		},
		{
			name: "invalid asset type",
			g:    asset.RandGenesis(t, asset.Type(255)),
			f: func() *AssetDetails {
				return &AssetDetails{
					Type:             asset.Type(255),
					ScriptKey:        pubKey,
					Amount:           nil,
					LockTime:         1337,
					RelativeLockTime: 6,
				}
			},
			valid: false,
		},
	}

	for _, testCase := range testCases {
		success := t.Run(testCase.name, func(t *testing.T) {
			details := testCase.f()
			groupKey := asset.RandGroupKey(t, testCase.g)
			_, _, err := Mint(testCase.g, groupKey, details)
			if testCase.valid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
		if !success {
			return
		}
	}
}

// TestMintAndDeriveTaroCommitment tests that we can mint a new Taro commitment,
// compute a proof for each asset minted, and use that proof to derive the same
// Taro commitment. It also tests that assets existing outside of that
// commitment have a proper non-inclusion proof.
func TestMintAndDeriveTaroCommitment(t *testing.T) {
	t.Parallel()

	const assetType = asset.Normal
	const numAssets = 5

	genesis1 := asset.RandGenesis(t, assetType)
	groupKey1 := asset.RandGroupKey(t, genesis1)
	assetDetails := make([]*AssetDetails, 0, numAssets)
	for i := 0; i < numAssets; i++ {
		details := randAssetDetails(t, assetType)
		assetDetails = append(assetDetails, details)
	}

	// Mint a new Taro commitment with the included assets.
	commitment, assets, err := Mint(genesis1, groupKey1, assetDetails...)
	require.NoError(t, err)

	proveAssets := func(assets []*asset.Asset, includesAsset,
		includesAssetGroup bool) {

		t.Helper()
		for _, asset := range assets {
			proofAsset, proof, err := commitment.Proof(
				asset.TaroCommitmentKey(),
				asset.AssetCommitmentKey(),
			)
			require.NoError(t, err)
			require.Equal(t, includesAsset, proofAsset != nil)

			if includesAssetGroup {
				require.NotNil(t, proof.AssetProof)
			} else {
				require.Nil(t, proof.AssetProof)
			}

			var taroCommitment *TaroCommitment

			if includesAsset && includesAssetGroup {
				taroCommitment, err = proof.DeriveByAssetInclusion(
					asset,
				)
			} else if includesAssetGroup {
				taroCommitment, err = proof.DeriveByAssetExclusion(
					asset.AssetCommitmentKey(),
				)
			} else {
				taroCommitment, err = proof.DeriveByAssetCommitmentExclusion(
					asset.TaroCommitmentKey(),
				)
			}
			require.NoError(t, err)
			require.Equal(
				t, commitment.TapLeaf(), taroCommitment.TapLeaf(),
			)
		}
	}

	// Prove that all assets minted are properly committed to.
	proveAssets(assets, true, true)

	// Now, we'll compute proofs for assets of the same group but not
	// included in the above Taro commitment (non-inclusion proofs).
	_, nonExistentAssets, err := Mint(
		genesis1, groupKey1, randAssetDetails(t, assetType),
	)
	require.NoError(t, err)
	proveAssets(nonExistentAssets, false, true)

	// Finally, we'll compute proofs for assets with a different group and
	// not included in the above Taro commitment (non-inclusion proofs).
	// We'll reuse the same asset details, except we'll mint them with a
	// distinct genesis and group key.
	genesis2 := asset.RandGenesis(t, assetType)
	groupKey2 := asset.RandGroupKey(t, genesis2)
	_, nonExistentAssetGroup, err := Mint(
		genesis2, groupKey2, assetDetails...,
	)
	require.NoError(t, err)
	proveAssets(nonExistentAssetGroup, false, false)
}

// TestSplitCommitment assets that we can properly create and prove split
// commitments, testing negative cases along the way.
func TestSplitCommitment(t *testing.T) {
	t.Parallel()

	outPoint := wire.OutPoint{}
	genesisNormal := asset.RandGenesis(t, asset.Normal)
	genesisCollectible := asset.RandGenesis(t, asset.Collectible)
	groupKeyNormal := asset.RandGroupKey(t, genesisNormal)
	groupKeyCollectible := asset.RandGroupKey(t, genesisCollectible)

	testCases := []struct {
		name string
		f    func() (*asset.Asset, *SplitLocator, []*SplitLocator)
		err  error
	}{
		{
			name: "collectible split with excess external locators",
			f: func() (*asset.Asset, *SplitLocator, []*SplitLocator) {
				input := randAsset(
					t, genesisCollectible,
					groupKeyCollectible,
				)
				root := &SplitLocator{
					OutputIndex: 0,
					AssetID:     genesisCollectible.ID(),
					ScriptKey:   asset.NUMSCompressedKey,
					Amount:      0,
				}
				external := []*SplitLocator{{
					OutputIndex: 1,
					AssetID:     genesisCollectible.ID(),
					ScriptKey:   asset.RandSerializedKey(t),
					Amount:      input.Amount,
				}, {
					OutputIndex: 1,
					AssetID:     genesisCollectible.ID(),
					ScriptKey:   asset.RandSerializedKey(t),
					Amount:      input.Amount,
				}}
				return input, root, external
			},
			err: ErrInvalidSplitLocatorCount,
		},
		{
			name: "collectible split commitment",
			f: func() (*asset.Asset, *SplitLocator, []*SplitLocator) {
				input := randAsset(
					t, genesisCollectible,
					groupKeyCollectible,
				)
				root := &SplitLocator{
					OutputIndex: 0,
					AssetID:     genesisCollectible.ID(),
					ScriptKey:   asset.NUMSCompressedKey,
					Amount:      0,
				}
				external := []*SplitLocator{{
					OutputIndex: 1,
					AssetID:     genesisCollectible.ID(),
					ScriptKey:   asset.RandSerializedKey(t),
					Amount:      input.Amount,
				}}
				return input, root, external
			},
			err: nil,
		},
		{
			name: "locator duplicate output index",
			f: func() (*asset.Asset, *SplitLocator, []*SplitLocator) {
				input := randAsset(
					t, genesisNormal, groupKeyNormal,
				)
				root := &SplitLocator{
					OutputIndex: 0,
					AssetID:     genesisNormal.ID(),
					ScriptKey: asset.ToSerialized(
						input.ScriptKey.PubKey,
					),
					Amount: input.Amount,
				}
				external := []*SplitLocator{root}
				return input, root, external
			},
			err: ErrDuplicateSplitOutputIndex,
		},
		{
			name: "invalid split amount",
			f: func() (*asset.Asset, *SplitLocator, []*SplitLocator) {
				input := randAsset(
					t, genesisNormal, groupKeyNormal,
				)
				splitAmount := input.Amount / 4
				root := &SplitLocator{
					OutputIndex: 0,
					AssetID:     genesisNormal.ID(),
					ScriptKey: asset.ToSerialized(
						input.ScriptKey.PubKey,
					),
					Amount: splitAmount,
				}
				external := []*SplitLocator{{
					OutputIndex: 1,
					AssetID:     genesisNormal.ID(),
					ScriptKey: asset.ToSerialized(
						input.ScriptKey.PubKey,
					),
					Amount: splitAmount,
				}}
				return input, root, external
			},
			err: ErrInvalidSplitAmount,
		},
		{
			name: "single input split commitment",
			f: func() (*asset.Asset, *SplitLocator, []*SplitLocator) {
				input := randAsset(
					t, genesisNormal, groupKeyNormal,
				)
				input.Amount = 3

				root := &SplitLocator{
					OutputIndex: 0,
					AssetID:     genesisNormal.ID(),
					ScriptKey: asset.ToSerialized(
						input.ScriptKey.PubKey,
					),
					Amount: 1,
				}
				external := []*SplitLocator{{
					OutputIndex: 1,
					AssetID:     genesisNormal.ID(),
					ScriptKey:   asset.RandSerializedKey(t),
					Amount:      1,
				}, {

					OutputIndex: 2,
					AssetID:     genesisNormal.ID(),
					ScriptKey:   asset.RandSerializedKey(t),
					Amount:      1,
				}}

				return input, root, external
			},
			err: nil,
		},
		{
			name: "no external splits",
			f: func() (*asset.Asset, *SplitLocator, []*SplitLocator) {
				input := randAsset(
					t, genesisNormal, groupKeyNormal,
				)
				input.Amount = 3

				root := &SplitLocator{
					OutputIndex: 0,
					AssetID:     genesisNormal.ID(),
					ScriptKey: asset.ToSerialized(
						input.ScriptKey.PubKey,
					),
					Amount: 1,
				}

				return input, root, nil
			},
			err: ErrInvalidSplitLocator,
		},
		{
			name: "unspendable root locator with non-zero amount",
			f: func() (*asset.Asset, *SplitLocator, []*SplitLocator) {
				input := randAsset(
					t, genesisNormal, groupKeyNormal,
				)
				input.Amount = 3

				root := &SplitLocator{
					OutputIndex: 0,
					AssetID:     genesisNormal.ID(),
					ScriptKey:   asset.NUMSCompressedKey,
					Amount:      1,
				}
				external := []*SplitLocator{{
					OutputIndex: 1,
					AssetID:     genesisNormal.ID(),
					ScriptKey:   asset.RandSerializedKey(t),
					Amount:      2,
				}}

				return input, root, external
			},
			err: ErrNonZeroSplitAmount,
		},
		{
			name: "invalid zero-value root locator",
			f: func() (*asset.Asset, *SplitLocator, []*SplitLocator) {
				input := randAsset(
					t, genesisNormal, groupKeyNormal,
				)
				input.Amount = 3

				root := &SplitLocator{
					OutputIndex: 0,
					AssetID:     genesisNormal.ID(),
					ScriptKey: asset.ToSerialized(
						input.ScriptKey.PubKey,
					),
					Amount: 0,
				}
				external := []*SplitLocator{{
					OutputIndex: 1,
					AssetID:     genesisNormal.ID(),
					ScriptKey:   asset.RandSerializedKey(t),
					Amount:      3,
				}}

				return input, root, external
			},
			err: ErrInvalidScriptKey,
		},
		{
			name: "zero-value external locator",
			f: func() (*asset.Asset, *SplitLocator, []*SplitLocator) {
				input := randAsset(
					t, genesisNormal, groupKeyNormal,
				)
				input.Amount = 3

				root := &SplitLocator{
					OutputIndex: 0,
					AssetID:     genesisNormal.ID(),
					ScriptKey: asset.ToSerialized(
						input.ScriptKey.PubKey,
					),
					Amount: 3,
				}
				external := []*SplitLocator{{
					OutputIndex: 1,
					AssetID:     genesisNormal.ID(),
					ScriptKey:   asset.RandSerializedKey(t),
					Amount:      0,
				}}

				return input, root, external
			},
			err: ErrZeroSplitAmount,
		},
		{
			name: "full value split commitment",
			f: func() (*asset.Asset, *SplitLocator, []*SplitLocator) {
				input := randAsset(
					t, genesisNormal, groupKeyNormal,
				)
				input.Amount = 3

				root := &SplitLocator{
					OutputIndex: 0,
					AssetID:     genesisNormal.ID(),
					ScriptKey:   asset.NUMSCompressedKey,
					Amount:      0,
				}
				external := []*SplitLocator{{
					OutputIndex: 1,
					AssetID:     genesisNormal.ID(),
					ScriptKey:   asset.RandSerializedKey(t),
					Amount:      3,
				}}

				return input, root, external
			},
			err: nil,
		},
	}

	for _, testCase := range testCases {
		success := t.Run(testCase.name, func(t *testing.T) {
			input, root, external := testCase.f()
			split, err := NewSplitCommitment(
				input, outPoint, root, external...,
			)
			require.Equal(t, testCase.err, err)

			if testCase.err != nil {
				return
			}

			// Verify that the asset input is well formed within the
			// InputSet.
			prevID := asset.PrevID{
				OutPoint: outPoint,
				ID:       input.Genesis.ID(),
				ScriptKey: asset.ToSerialized(
					input.ScriptKey.PubKey,
				),
			}
			require.Contains(t, split.PrevAssets, prevID)
			prevAsset := split.PrevAssets[prevID]
			require.Equal(t, *input, *prevAsset)

			// Verify that the root asset was constructed properly.
			require.Equal(t, root.AssetID, split.RootAsset.Genesis.ID())
			require.Equal(
				t, root.ScriptKey[:],
				split.RootAsset.ScriptKey.PubKey.SerializeCompressed(),
			)
			require.Equal(t, root.Amount, split.RootAsset.Amount)
			require.Len(t, split.RootAsset.PrevWitnesses, 1)
			require.NotNil(t, split.RootAsset.PrevWitnesses[0].PrevID)
			require.Nil(t, split.RootAsset.PrevWitnesses[0].TxWitness)
			require.Nil(t, split.RootAsset.PrevWitnesses[0].SplitCommitment)
			require.NotNil(t, split.RootAsset.SplitCommitmentRoot)

			// Verify that each asset split was constructed properly
			// and has a valid split commitment proof.
			for _, l := range append(external, root) {
				require.Contains(t, split.SplitAssets, *l)
				splitAsset := split.SplitAssets[*l]

				// If this is a leaf split, then we need to
				// ensure that the prev ID is zero.
				if splitAsset.SplitCommitmentRoot == nil {
					require.Equal(
						t, asset.ZeroPrevID,
						*splitAsset.PrevWitnesses[0].PrevID,
					)
				}

				require.Equal(t, l.AssetID, splitAsset.Genesis.ID())
				require.Equal(
					t, l.ScriptKey[:],
					splitAsset.ScriptKey.PubKey.SerializeCompressed(),
				)
				require.Equal(t, l.Amount, splitAsset.Amount)
				require.Len(t, splitAsset.PrevWitnesses, 1)
				require.NotNil(t, splitAsset.PrevWitnesses[0].PrevID)
				require.Nil(t, splitAsset.PrevWitnesses[0].TxWitness)
				require.NotNil(t, splitAsset.PrevWitnesses[0].SplitCommitment)
				require.Nil(t, splitAsset.SplitCommitmentRoot)

				splitAssetNoProof := splitAsset.Copy()
				splitAssetNoProof.PrevWitnesses[0].SplitCommitment = nil
				splitLeaf, err := splitAssetNoProof.Leaf()
				require.NoError(t, err)
				require.True(t, mssmt.VerifyMerkleProof(
					l.Hash(), splitLeaf,
					&splitAsset.PrevWitnesses[0].SplitCommitment.Proof,
					split.RootAsset.SplitCommitmentRoot,
				))
			}
		})
		if !success {
			return
		}
	}
}

// TestTaroCommitmentPopulation tests a series of invariants related to the
// Taro commitment key.
func TestTaroCommitmentKeyPopulation(t *testing.T) {
	type assetDescription struct {
		HasGroupKey   bool
		IsCollectible bool
	}
	mainScenario := func(assetDesc assetDescription) bool {
		var assetType asset.Type
		if assetDesc.IsCollectible {
			assetType = asset.Collectible
		}

		genesis := asset.RandGenesis(t, assetType)

		var groupKey *asset.GroupKey
		if assetDesc.HasGroupKey {
			groupKey = asset.RandGroupKey(t, genesis)
		}

		a := randAsset(t, genesis, groupKey)
		commitment, err := NewAssetCommitment(a)
		require.NoError(t, err)

		// The Taro commitment key value MUST always be set for the
		// commitment to be well-formed.
		var zero [32]byte
		if commitment.TaroCommitmentKey() == zero {
			t.Log("commitment has blank taro commitment key!")
			return false
		}

		return true
	}
	require.NoError(t, quick.Check(mainScenario, nil))
}

// TestUpdateAssetCommitment asserts that we can properly insert and remove
// assets from an AssetCommitment. It also tests that we reject assets that
// could not be included in the AssetCommitment.
func TestUpdateAssetCommitment(t *testing.T) {
	t.Parallel()

	genesis1 := asset.RandGenesis(t, asset.Normal)
	genesis2 := asset.RandGenesis(t, asset.Normal)
	genesis1collect := genesis1
	genesis1collect.Type = asset.Collectible
	groupKey1 := asset.RandGroupKey(t, genesis1)
	groupKey2 := asset.RandGroupKey(t, genesis2)
	copyOfGroupKey1 := &asset.GroupKey{
		RawKey:      groupKey1.RawKey,
		GroupPubKey: groupKey1.GroupPubKey,
		Sig:         groupKey1.Sig,
	}

	assetWithGroup := randAsset(t, genesis1, groupKey1)
	assetNoGroup := randAsset(t, genesis2, nil)
	copyOfAssetNoGroup := assetNoGroup.Copy()

	// Create two AssetCommitments, both including one asset.
	// One AssetCommitment includes an asset with a group key.
	groupAssetCommitment, err := NewAssetCommitment(assetWithGroup)
	require.NoError(t, err)
	soloAssetCommitment, err := NewAssetCommitment(assetNoGroup)
	require.NoError(t, err)

	testCases := []struct {
		name      string
		f         func() (*asset.Asset, error)
		numAssets int
		err       error
	}{
		{
			name: "group key mismatch",
			f: func() (*asset.Asset, error) {
				mismatchedAsset := randAsset(t, genesis1, groupKey2)
				return nil, groupAssetCommitment.Upsert(mismatchedAsset)
			},
			numAssets: 0,
			err:       ErrAssetGroupKeyMismatch,
		},
		{
			name: "genesis mismatch",
			f: func() (*asset.Asset, error) {
				mismatchedAsset := randAsset(t, genesis2, nil)
				return nil, groupAssetCommitment.Upsert(mismatchedAsset)
			},
			numAssets: 0,
			err:       ErrAssetGenesisMismatch,
		},
		{
			name: "fresh asset commitment",
			f: func() (*asset.Asset, error) {
				return assetWithGroup, nil
			},
			numAssets: 1,
			err:       nil,
		},
		{
			name: "insertion of collectible with group key",
			f: func() (*asset.Asset, error) {
				newAsset := randAsset(t, genesis1collect, copyOfGroupKey1)
				return newAsset, groupAssetCommitment.Upsert(newAsset)
			},
			numAssets: 2,
			err:       nil,
		},
		{
			name: "deletion with no group key",
			f: func() (*asset.Asset, error) {
				return copyOfAssetNoGroup, soloAssetCommitment.Delete(
					copyOfAssetNoGroup,
				)
			},
			numAssets: 0,
			err:       nil,
		},
	}

	for _, testCase := range testCases {
		success := t.Run(testCase.name, func(t *testing.T) {
			asset, err := testCase.f()
			require.Equal(t, testCase.err, err)

			// Verify the number of assets in the updated AssetCommitment,
			// as well as the inlcusion of an inserted asset or non-inclusion
			// of a deleted asset.
			if testCase.err == nil {
				switch testCase.numAssets {
				// Deletion with no group key.
				case 0:
					assets := soloAssetCommitment.Assets()
					require.Equal(t, len(assets), testCase.numAssets)
					proofAsset, _, err := groupAssetCommitment.AssetProof(
						asset.AssetCommitmentKey(),
					)
					require.NoError(t, err)
					require.Nil(t, proofAsset)

				// Fresh asset commitment.
				case 1:
					assets := groupAssetCommitment.Assets()
					require.Equal(t, len(assets), testCase.numAssets)
					require.True(t, asset.DeepEqual(
						assets[asset.AssetCommitmentKey()],
					))

				// insertion of collectible with group key.
				case 2:
					assets := groupAssetCommitment.Assets()
					require.Equal(t, len(assets), testCase.numAssets)
					proofAsset, _, err := groupAssetCommitment.AssetProof(
						asset.AssetCommitmentKey(),
					)
					require.NoError(t, err)
					require.True(t, asset.DeepEqual(
						proofAsset,
					))
				}
			}
		})
		if !success {
			return
		}
	}
}

// TestUpdateTaroCommitment asserts that we can properly insert and remove
// assetCommitments from a TaroCommitment.
func TestUpdateTaroCommitment(t *testing.T) {
	t.Parallel()

	// Create two assets with different geneses and groupKeys, to ensure
	// they are not in the same AssetCommitment.
	genesis1 := asset.RandGenesis(t, asset.Normal)
	genesis2 := asset.RandGenesis(t, asset.Normal)
	groupKey1 := asset.RandGroupKey(t, genesis1)
	groupKey2 := asset.RandGroupKey(t, genesis2)

	asset1 := randAsset(t, genesis1, groupKey1)
	asset2 := randAsset(t, genesis2, groupKey2)
	assetCommitment1, err := NewAssetCommitment(asset1)
	require.NoError(t, err)
	commitmentKey1 := assetCommitment1.TaroCommitmentKey()
	assetCommitment2, err := NewAssetCommitment(asset2)
	require.NoError(t, err)
	commitmentKey2 := assetCommitment2.TaroCommitmentKey()

	// Mint a new Taro commitment with only the first assetCommitment.
	commitment, err := NewTaroCommitment(assetCommitment1)
	require.NoError(t, err)
	copyOfCommitment, err := NewTaroCommitment(assetCommitment1)
	require.NoError(t, err)

	// Check that the assetCommitment map has only the first assetCommitment.
	assetCommitments := commitment.Commitments()
	require.Equal(t, len(assetCommitments), 1)
	require.Equal(t, assetCommitments[commitmentKey1], assetCommitment1)

	// Verify commitment deletion with an empty assetCommitment map
	// and a proof of non inclusion.
	require.NoError(t, commitment.Delete(assetCommitment1))
	proofAsset1, _, err := commitment.Proof(
		commitmentKey1, asset1.AssetCommitmentKey(),
	)
	require.NoError(t, err)
	require.Nil(t, proofAsset1)

	assetCommitments = commitment.Commitments()
	require.Equal(t, len(assetCommitments), 0)

	// Verify commitment insertion with a proof of inclusion and checking the
	// assetCommitment map for the inserted assetCommitment.
	require.NoError(t, copyOfCommitment.Upsert(assetCommitment2))
	proofAsset2, _, err := copyOfCommitment.Proof(
		commitmentKey2, asset2.AssetCommitmentKey(),
	)
	require.NoError(t, err)
	require.True(t, proofAsset2.DeepEqual(asset2))

	assetCommitments = copyOfCommitment.Commitments()
	require.Equal(t, len(assetCommitments), 2)
	require.Equal(t, assetCommitments[commitmentKey2], assetCommitment2)
}

// TestAssetCommitmentDeepCopy tests that we're able to properly perform a deep
// copy of a given asset commitment.
func TestAssetCommitmentDeepCopy(t *testing.T) {
	t.Parallel()

	// First, we'll make a commitment with two random assets.
	genesis := asset.RandGenesis(t, asset.Normal)
	asset1 := randAsset(t, genesis, nil)
	asset2 := randAsset(t, genesis, nil)

	assetCommitment, err := NewAssetCommitment(asset1, asset2)
	require.NoError(t, err)

	// Next, we'll copy the commitment and ensure that we get the exact
	// same commitment out the other side.
	assetCommitmentCopy, err := assetCommitment.Copy()
	require.NoError(t, err)

	require.Equal(t, assetCommitment.Version, assetCommitmentCopy.Version)
	require.Equal(t, assetCommitment.AssetID, assetCommitmentCopy.AssetID)
	require.True(
		t, mssmt.IsEqualNode(
			assetCommitment.TreeRoot, assetCommitmentCopy.TreeRoot,
		),
	)
}

// TestTaroCommitmentDeepCopy tests that we're able to properly perform a deep
// copy of a given taro commitment.
func TestTaroCommitmentDeepCopy(t *testing.T) {
	t.Parallel()

	// Fist, we'll make two asset commitments with a random asset, then
	// make a taro commitment out of that.
	genesis1 := asset.RandGenesis(t, asset.Normal)
	groupKey1 := asset.RandGroupKey(t, genesis1)
	asset1 := randAsset(t, genesis1, groupKey1)

	genesis2 := asset.RandGenesis(t, asset.Normal)
	groupKey2 := asset.RandGroupKey(t, genesis2)
	asset2 := randAsset(t, genesis2, groupKey2)

	assetCommitment1, err := NewAssetCommitment(asset1)
	require.NoError(t, err)

	assetCommitment2, err := NewAssetCommitment(asset2)
	require.NoError(t, err)

	// With both commitments created, we'll now make a new taro commitment
	// then copy it.
	taroCommitment, err := NewTaroCommitment(
		assetCommitment1, assetCommitment2,
	)
	require.NoError(t, err)

	newCommitment, err := taroCommitment.Copy()
	require.NoError(t, err)

	// The new taro commitment should match the existing one exactly.
	require.Equal(t, taroCommitment.Version, newCommitment.Version)
	require.True(t, mssmt.IsEqualNode(
		taroCommitment.TreeRoot, newCommitment.TreeRoot),
	)
}
