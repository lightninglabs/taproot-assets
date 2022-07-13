package commitment

import (
	"math/rand"
	"testing"
	"testing/quick"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/mssmt"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

func randKey(t *testing.T) *btcec.PrivateKey {
	t.Helper()
	key, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	return key
}

func randGenesis(t *testing.T) asset.Genesis {
	t.Helper()
	return asset.Genesis{
		FirstPrevOut: wire.OutPoint{},
		Tag:          "",
		Metadata:     nil,
		OutputIndex:  rand.Uint32(),
	}
}

func randFamilyKey(t *testing.T, genesis asset.Genesis) *asset.FamilyKey {
	t.Helper()
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	genSigner := asset.NewRawKeyGenesisSigner(privKey)
	fakeKeyDesc := keychain.KeyDescriptor{
		PubKey: privKey.PubKey(),
	}
	familyKey, err := asset.DeriveFamilyKey(genSigner, fakeKeyDesc, genesis)
	require.NoError(t, err)
	return familyKey
}

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
			PubKey: randKey(t).PubKey(),
		},
		Amount:           amount,
		LockTime:         rand.Uint64(),
		RelativeLockTime: rand.Uint64(),
	}
}

func randAsset(t *testing.T, genesis asset.Genesis, familyKey *asset.FamilyKey,
	assetType asset.Type) *asset.Asset {

	t.Helper()

	pubKey := randKey(t).PubKey()

	switch assetType {
	case asset.Normal:
		units := rand.Uint64() + 1
		return asset.New(
			genesis, units, 0, 0,
			keychain.KeyDescriptor{
				PubKey: pubKey,
			},
			familyKey,
		)
	case asset.Collectible:
		return asset.NewCollectible(
			genesis, 0, 0,
			keychain.KeyDescriptor{
				PubKey: pubKey,
			},
			familyKey,
		)
	default:
		t.Fatal("unhandled asset type", assetType)
		return nil // unreachable
	}
}

// TestNewAssetCommitment tests edge cases around NewAssetCommitment.
func TestNewAssetCommitment(t *testing.T) {
	t.Parallel()

	genesis1 := randGenesis(t)
	genesis2 := randGenesis(t)
	familyKey1 := randFamilyKey(t, genesis1)
	familyKey2 := randFamilyKey(t, genesis2)
	copyOfFamilyKey1 := &asset.FamilyKey{
		RawKey: familyKey1.RawKey,
		FamKey: familyKey1.FamKey,
		Sig:    familyKey1.Sig,
	}

	testCases := []struct {
		name string
		f    func() []*asset.Asset
		err  error
	}{
		{
			name: "family key mismatch",
			f: func() []*asset.Asset {
				return []*asset.Asset{
					randAsset(t, genesis1, familyKey1, asset.Normal),
					randAsset(t, genesis1, familyKey2, asset.Normal),
				}
			},
			err: ErrAssetFamilyKeyMismatch,
		},
		{
			name: "no family key asset id mismatch",
			f: func() []*asset.Asset {
				return []*asset.Asset{
					randAsset(t, genesis1, nil, asset.Normal),
					randAsset(t, genesis2, nil, asset.Normal),
				}
			},
			err: ErrAssetGenesisMismatch,
		},
		{
			name: "same family key asset id mismatch",
			f: func() []*asset.Asset {
				return []*asset.Asset{
					randAsset(t, genesis1, familyKey1, asset.Normal),
					randAsset(t, genesis2, familyKey1, asset.Normal),
				}
			},
			err: nil,
		},
		{
			name: "duplicate script key",
			f: func() []*asset.Asset {
				asset1 := randAsset(t, genesis1, familyKey1, asset.Normal)
				asset2 := randAsset(t, genesis1, familyKey1, asset.Normal)
				asset1.ScriptKey = asset2.ScriptKey
				return []*asset.Asset{asset1, asset2}
			},
			err: ErrAssetDuplicateScriptKey,
		},
		{
			name: "valid asset commitment with family key",
			f: func() []*asset.Asset {
				return []*asset.Asset{
					randAsset(t, genesis1, familyKey1, asset.Normal),
					randAsset(t, genesis1, copyOfFamilyKey1, asset.Collectible),
				}
			},
			err: nil,
		},
		{
			name: "valid asset commitment without family key",
			f: func() []*asset.Asset {
				return []*asset.Asset{
					randAsset(t, genesis1, nil, asset.Normal),
					randAsset(t, genesis1, nil, asset.Collectible),
				}
			},
			err: nil,
		},
	}

	for _, testCase := range testCases {
		success := t.Run(testCase.name, func(t *testing.T) {
			assets := testCase.f()
			commitment, err := NewAssetCommitment(assets...)
			require.Equal(t, testCase.err, err)
			if testCase.err == nil {
				// Ensure that the Taro commitment was properly set.
				require.NotZero(t, commitment.TaroCommitmentKey())

				for _, asset := range assets {
					asset, _ = commitment.AssetProof(
						asset.AssetCommitmentKey(),
					)
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

	genesis := randGenesis(t)
	familyKey := randFamilyKey(t, genesis)
	pubKey := keychain.KeyDescriptor{
		PubKey: randKey(t).PubKey(),
	}

	testCases := []struct {
		name  string
		f     func() *AssetDetails
		valid bool
	}{
		{
			name: "normal with nil amount",
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
			_, _, err := Mint(genesis, familyKey, details)
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

	genesis1 := randGenesis(t)
	familyKey1 := randFamilyKey(t, genesis1)
	assetDetails := make([]*AssetDetails, 0, numAssets)
	for i := 0; i < numAssets; i++ {
		details := randAssetDetails(t, assetType)
		assetDetails = append(assetDetails, details)
	}

	// Mint a new Taro commitment with the included assets.
	commitment, assets, err := Mint(genesis1, familyKey1, assetDetails...)
	require.NoError(t, err)

	proveAssets := func(assets []*asset.Asset, includesAsset,
		includesAssetFamily bool) {

		t.Helper()
		for _, asset := range assets {
			proofAsset, proof := commitment.Proof(
				asset.TaroCommitmentKey(),
				asset.AssetCommitmentKey(),
			)
			require.Equal(t, includesAsset, proofAsset != nil)
			if includesAssetFamily {
				require.NotNil(t, proof.AssetProof)
			} else {
				require.Nil(t, proof.AssetProof)
			}

			var (
				taroCommitment *TaroCommitment
				err            error
			)
			if includesAsset && includesAssetFamily {
				taroCommitment, err = proof.DeriveByAssetInclusion(
					asset,
				)
			} else if includesAssetFamily {
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

	// Now, we'll compute proofs for assets of the same family but not
	// included in the above Taro commitment (non-inclusion proofs).
	_, nonExistentAssets, err := Mint(
		genesis1, familyKey1, randAssetDetails(t, assetType),
	)
	require.NoError(t, err)
	proveAssets(nonExistentAssets, false, true)

	// Finally, we'll compute proofs for assets with a different family and
	// not included in the above Taro commitment (non-inclusion proofs).
	// We'll reuse the same asset details, except we'll mint them with a
	// distinct genesis and family key.
	genesis2 := randGenesis(t)
	familyKey2 := randFamilyKey(t, genesis2)
	_, nonExistentAssetFamily, err := Mint(
		genesis2, familyKey2, assetDetails...,
	)
	require.NoError(t, err)
	proveAssets(nonExistentAssetFamily, false, false)
}

// TestSplitCommitment assets that we can properly create and prove split
// commitments, testing negative cases along the way.
func TestSplitCommitment(t *testing.T) {
	t.Parallel()

	outPoint := wire.OutPoint{}
	genesis := randGenesis(t)
	familyKey := randFamilyKey(t, genesis)

	testCases := []struct {
		name string
		f    func() (*asset.Asset, *SplitLocator, []*SplitLocator)
		err  error
	}{
		{
			name: "invalid asset input type",
			f: func() (*asset.Asset, *SplitLocator, []*SplitLocator) {
				input := randAsset(
					t, genesis, familyKey, asset.Collectible,
				)
				root := &SplitLocator{
					OutputIndex: 0,
					AssetID:     genesis.ID(),
					ScriptKey:   *input.ScriptKey.PubKey,
					Amount:      input.Amount,
				}
				return input, root, nil
			},
			err: ErrInvalidInputType,
		},
		{
			name: "locator duplicate output index",
			f: func() (*asset.Asset, *SplitLocator, []*SplitLocator) {
				input := randAsset(
					t, genesis, familyKey, asset.Normal,
				)
				root := &SplitLocator{
					OutputIndex: 0,
					AssetID:     genesis.ID(),
					ScriptKey:   *input.ScriptKey.PubKey,
					Amount:      input.Amount,
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
					t, genesis, familyKey, asset.Normal,
				)
				splitAmount := input.Amount / 4
				root := &SplitLocator{
					OutputIndex: 0,
					AssetID:     genesis.ID(),
					ScriptKey:   *input.ScriptKey.PubKey,
					Amount:      splitAmount,
				}
				external := []*SplitLocator{{
					OutputIndex: 1,
					AssetID:     genesis.ID(),
					ScriptKey:   *input.ScriptKey.PubKey,
					Amount:      splitAmount,
				}}
				return input, root, external
			},
			err: ErrInvalidSplitAmount,
		},
		{
			name: "single input split commitment",
			f: func() (*asset.Asset, *SplitLocator, []*SplitLocator) {
				input := randAsset(
					t, genesis, familyKey, asset.Normal,
				)
				input.Amount = 3

				root := &SplitLocator{
					OutputIndex: 0,
					AssetID:     genesis.ID(),
					ScriptKey:   *input.ScriptKey.PubKey,
					Amount:      1,
				}
				external := []*SplitLocator{{
					OutputIndex: 1,
					AssetID:     genesis.ID(),
					ScriptKey:   *randKey(t).PubKey(),
					Amount:      1,
				}, {

					OutputIndex: 2,
					AssetID:     genesis.ID(),
					ScriptKey:   *randKey(t).PubKey(),
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
					t, genesis, familyKey, asset.Normal,
				)
				input.Amount = 3

				root := &SplitLocator{
					OutputIndex: 0,
					AssetID:     genesis.ID(),
					ScriptKey:   *input.ScriptKey.PubKey,
					Amount:      1,
				}

				return input, root, nil
			},
			err: ErrInvalidSplitLocator,
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
				OutPoint:  outPoint,
				ID:        genesis.ID(),
				ScriptKey: *input.ScriptKey.PubKey,
			}
			require.Contains(t, split.PrevAssets, prevID)
			prevAsset := split.PrevAssets[prevID]
			require.Equal(t, *input, *prevAsset)

			// Verify that the root asset was constructed properly.
			require.Equal(t, root.AssetID, split.RootAsset.Genesis.ID())
			require.Equal(t, root.ScriptKey, *split.RootAsset.ScriptKey.PubKey)
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

				require.Equal(t, l.AssetID, splitAsset.Genesis.ID())
				require.Equal(t, l.ScriptKey, *splitAsset.ScriptKey.PubKey)
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
	// TODO(roasbeef): update after issue #42 is fixed, should also make
	// many assets w/ same name but diff type
	type assetDescription struct {
		HasFamilyKey  bool
		IsCollectible bool
	}
	mainScenario := func(assetDesc assetDescription) bool {
		genesis := randGenesis(t)

		var familyKey *asset.FamilyKey
		if assetDesc.HasFamilyKey {
			familyKey = randFamilyKey(t, genesis)
		}

		var assetType asset.Type
		if assetDesc.IsCollectible {
			assetType = asset.Collectible
		}

		asset := randAsset(t, genesis, familyKey, assetType)
		commitment, err := NewAssetCommitment(asset)
		require.NoError(t, err)

		// The Taro commitment key value MUST always be set for the
		// commitment to be well formed.
		var zero [32]byte
		if commitment.TaroCommitmentKey() == zero {
			t.Log("commitment has blank taro commitment key!")
			return false
		}

		return true
	}
	require.NoError(t, quick.Check(mainScenario, nil))
}
