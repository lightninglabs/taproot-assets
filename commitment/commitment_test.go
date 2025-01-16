package commitment

import (
	"bytes"
	"context"
	"encoding/hex"
	"math/rand"
	"testing"
	"testing/quick"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/tlv"
	"github.com/stretchr/testify/require"
)

var (
	testTapCommitmentScript, _ = hex.DecodeString(
		"002dc2975396094e0c17f70abd43715ade3c9660f6fe22056e4f706941b8" +
			"511c4c1cfee543eac337024a6f13bb5f496e99209207a3792a74" +
			"89ccc21d4dbbe5ed180000000000001389",
	)

	zeroAmt = uint64(0)
	oneAmt  = uint64(1)
)

func randAssetDetails(t *testing.T, assetType asset.Type) *AssetDetails {
	t.Helper()

	// Generate asset amount.
	var amount uint64
	switch assetType {
	case asset.Normal:
		amount = mssmt.RandLeafAmount()
	case asset.Collectible:
		amount = 1
	}

	var assetVersion asset.Version
	if rand.Int()%2 == 0 {
		assetVersion = asset.V1
	}

	return &AssetDetails{
		Version: assetVersion,
		Type:    assetType,
		ScriptKey: keychain.KeyDescriptor{
			PubKey: test.RandPrivKey().PubKey(),
		},
		Amount:           &amount,
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

func proveAssets(t *testing.T, commit *TapCommitment, assets []*asset.Asset,
	includesAsset, includesAssetGroup bool) {

	t.Helper()
	for _, asset := range assets {
		proofAsset, proof, err := commit.Proof(
			asset.TapCommitmentKey(),
			asset.AssetCommitmentKey(),
		)
		require.NoError(t, err)
		require.Equal(t, includesAsset, proofAsset != nil)
		require.Equal(
			t, commit.Version, proof.TaprootAssetProof.Version,
		)

		if includesAssetGroup {
			require.NotNil(t, proof.AssetProof)
		} else {
			require.Nil(t, proof.AssetProof)
		}

		var tapCommitment *TapCommitment

		switch {
		case includesAsset && includesAssetGroup:
			tapCommitment, err = proof.DeriveByAssetInclusion(
				asset,
			)
		case !includesAsset && includesAssetGroup:
			tapCommitment, err = proof.DeriveByAssetExclusion(
				asset.AssetCommitmentKey(),
			)
		case !includesAsset && !includesAssetGroup:
			tapCommitment, err = proof.
				DeriveByAssetCommitmentExclusion(
					asset.TapCommitmentKey(),
				)
		}
		require.NoError(t, err)
		require.Equal(
			t, commit.TapLeaf(), tapCommitment.TapLeaf(),
		)
	}
}

// TestNewAssetCommitment tests edge cases around NewAssetCommitment.
func TestNewAssetCommitment(t *testing.T) {
	t.Parallel()

	genesis1 := asset.RandGenesis(t, asset.Normal)
	genesis2 := asset.RandGenesis(t, asset.Normal)
	genesis1Collectible := asset.RandGenesis(t, asset.Collectible)
	genesis1CollectibleProtoAsset := asset.NewAssetNoErr(
		t, genesis1Collectible, 1, 0, 0, asset.RandScriptKey(t), nil,
	)
	group1Anchor := randAsset(t, genesis1, nil)
	groupKey1, group1PrivBytes := asset.RandGroupKeyWithSigner(
		t, nil, genesis1, group1Anchor,
	)
	group1Anchor = asset.NewAssetNoErr(
		t, genesis1, group1Anchor.Amount, group1Anchor.LockTime,
		group1Anchor.RelativeLockTime, group1Anchor.ScriptKey,
		groupKey1, asset.WithAssetVersion(group1Anchor.Version),
	)
	groupKey1Collectible := asset.RandGroupKey(
		t, genesis1Collectible, genesis1CollectibleProtoAsset,
	)
	genesis2ProtoAsset := randAsset(t, genesis2, nil)
	groupKey2 := asset.RandGroupKey(t, genesis2, genesis2ProtoAsset)
	copyOfGroupKey1Collectible := &asset.GroupKey{
		RawKey:        groupKey1Collectible.RawKey,
		GroupPubKey:   groupKey1Collectible.GroupPubKey,
		TapscriptRoot: groupKey1Collectible.TapscriptRoot,
		Witness:       groupKey1Collectible.Witness,
	}
	group1Reissued := randAsset(t, genesis2, nil)
	genTxBuilder := asset.MockGroupTxBuilder{}
	group1Priv, group1Pub := btcec.PrivKeyFromBytes(group1PrivBytes)
	group1ReissuedGroupReq := asset.NewGroupKeyRequestNoErr(
		t, test.PubToKeyDesc(group1Pub), fn.None[asset.ExternalKey](),
		genesis1, genesis2ProtoAsset, nil, fn.None[chainhash.Hash](),
	)
	group1ReissuedGenTx, err := group1ReissuedGroupReq.BuildGroupVirtualTx(
		&genTxBuilder,
	)
	require.NoError(t, err)

	group1ReissuedGroupKey, err := asset.DeriveGroupKey(
		asset.NewMockGenesisSigner(group1Priv), *group1ReissuedGenTx,
		*group1ReissuedGroupReq, nil,
	)
	require.NoError(t, err)
	group1Reissued = asset.NewAssetNoErr(
		t, genesis2, group1Reissued.Amount, group1Reissued.LockTime,
		group1Reissued.RelativeLockTime, group1Reissued.ScriptKey,
		group1ReissuedGroupKey,
		asset.WithAssetVersion(group1Reissued.Version),
	)

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
			name: "valid normal asset commitment with group reissue",
			f: func() []*asset.Asset {
				return []*asset.Asset{
					group1Anchor,
					group1Reissued,
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
				// Ensure that the Taproot Asset commitment was
				// properly set: each asset is present and a
				// proof can be generated for each asset.
				require.NotZero(t, commitment.TapCommitmentKey())

				for _, a := range assets {
					committedAsset, proof, err := commitment.AssetProof(
						a.AssetCommitmentKey(),
					)
					require.NoError(t, err)
					require.NotNil(t, committedAsset)
					require.NotNil(t, proof)
				}
			}
		})
		if !success {
			return
		}
	}
}

// TestMintTapCommitment tests edge cases around minting new commitments.
func TestMintTapCommitment(t *testing.T) {
	t.Parallel()

	genesisNormal := asset.RandGenesis(t, asset.Normal)
	genesisCollectible := asset.RandGenesis(t, asset.Collectible)
	pubKey := keychain.KeyDescriptor{
		PubKey: test.RandPrivKey().PubKey(),
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
				return &AssetDetails{
					Type:             asset.Normal,
					ScriptKey:        pubKey,
					Amount:           &zeroAmt,
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
				return &AssetDetails{
					Type:             asset.Collectible,
					ScriptKey:        pubKey,
					Amount:           &oneAmt,
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

			// Test case concerns amount sanity checking, skip
			// group key creation.
			var err error
			amt := details.Amount
			invalidNormalAmt := details.Type != asset.Collectible &&
				((amt != nil && *amt == zeroAmt) || amt == nil)
			invalidCollctibleAmt := amt != nil && *amt != oneAmt &&
				details.Type == asset.Collectible

			tapCommitVersion := RandTapCommitVersion()
			switch {
			case invalidNormalAmt || invalidCollctibleAmt:
				_, _, err = Mint(
					tapCommitVersion, testCase.g, nil,
					details,
				)

			default:
				trueAmt := amt
				if amt == nil {
					trueAmt = &oneAmt
				}

				protoAsset := asset.NewAssetNoErr(
					t, testCase.g, *trueAmt,
					details.LockTime,
					details.RelativeLockTime,
					asset.NewScriptKeyBip86(details.ScriptKey),
					nil,
				)

				groupKey := asset.RandGroupKey(
					t, testCase.g, protoAsset,
				)

				_, _, err = Mint(
					RandTapCommitVersion(),
					testCase.g, groupKey, details,
				)
			}

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

// TestMintAndDeriveTapCommitment tests that we can mint a new Taproot Asset
// commitment, compute a proof for each asset minted, and use that proof to
// derive the same Taproot Asset commitment. It also tests that assets existing
// outside of that commitment have a proper non-inclusion proof.
func TestMintAndDeriveTapCommitment(t *testing.T) {
	t.Parallel()

	const assetType = asset.Normal
	const numAssets = 5
	var anchorDetails *AssetDetails

	tapCommitVersion := RandTapCommitVersion()
	genesis1 := asset.RandGenesis(t, assetType)
	assetDetails := make([]*AssetDetails, 0, numAssets)
	for i := 0; i < numAssets; i++ {
		details := randAssetDetails(t, assetType)
		assetDetails = append(assetDetails, details)
		if i == 0 {
			anchorDetails = details
		}
	}

	genesis1ProtoAsset := asset.NewAssetNoErr(
		t, genesis1, *anchorDetails.Amount, anchorDetails.LockTime,
		anchorDetails.RelativeLockTime,
		asset.NewScriptKeyBip86(anchorDetails.ScriptKey), nil,
		asset.WithAssetVersion(anchorDetails.Version),
	)
	groupKey1 := asset.RandGroupKey(t, genesis1, genesis1ProtoAsset)

	// Mint a new Taproot Asset commitment with the included assets.
	commitment, assets, err := Mint(
		tapCommitVersion, genesis1, groupKey1, assetDetails...,
	)
	require.NoError(t, err)

	// Prove that all assets minted are properly committed to.
	proveAssets(t, commitment, assets, true, true)

	// Now, we'll compute proofs for assets of the same group but not
	// included in the above Taproot Asset commitment (non-inclusion
	// proofs).
	_, nonExistentAssets, err := Mint(
		tapCommitVersion, genesis1, groupKey1,
		randAssetDetails(t, assetType),
	)
	require.NoError(t, err)
	proveAssets(t, commitment, nonExistentAssets, false, true)

	// Finally, we'll compute proofs for assets with a different group and
	// not included in the above Taproot Asset commitment (non-inclusion
	// proofs). We'll reuse the same asset details, except we'll mint them
	// with a distinct genesis and group key.
	genesis2 := asset.RandGenesis(t, assetType)
	genesis2ProtoAsset := asset.NewAssetNoErr(
		t, genesis2, *anchorDetails.Amount, anchorDetails.LockTime,
		anchorDetails.RelativeLockTime,
		asset.NewScriptKeyBip86(anchorDetails.ScriptKey), nil,
		asset.WithAssetVersion(anchorDetails.Version),
	)
	groupKey2 := asset.RandGroupKey(t, genesis2, genesis2ProtoAsset)
	_, nonExistentAssetGroup, err := Mint(
		tapCommitVersion, genesis2, groupKey2, assetDetails...,
	)
	require.NoError(t, err)
	proveAssets(t, commitment, nonExistentAssetGroup, false, false)
}

// TestSplitCommitment assets that we can properly create and prove split
// commitments, testing negative cases along the way.
func TestSplitCommitment(t *testing.T) {
	t.Parallel()

	outPoint := wire.OutPoint{}
	genesisNormal := asset.RandGenesis(t, asset.Normal)
	genesisCollectible := asset.RandGenesis(t, asset.Collectible)
	normalProtoAsset := randAsset(t, genesisNormal, nil)
	collectibleProtoAsset := randAsset(t, genesisCollectible, nil)
	groupKeyNormal := asset.RandGroupKey(t, genesisNormal, normalProtoAsset)
	groupKeyCollectible := asset.RandGroupKey(
		t, genesisCollectible, collectibleProtoAsset,
	)

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
			name: "single input split commitment lock time input",
			f: func() (*asset.Asset, *SplitLocator,
				[]*SplitLocator) {

				input := randAsset(
					t, genesisNormal, groupKeyNormal,
				)
				input.Amount = 3
				input.RelativeLockTime = 1
				input.LockTime = 1

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
			name: "un-spendable root locator with non-zero amount",
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
		{
			name: "split commitment remainder underflow",
			// This test case attempts to underflow the remainder
			// which is calculated to ensure that the sum of the
			// external split amounts is equal to the input amount.
			// The underflow attempt should fail and an error
			// should be returned.
			f: func() (*asset.Asset, *SplitLocator, []*SplitLocator) {
				input := randAsset(
					t, genesisNormal, groupKeyNormal,
				)
				input.Amount = 3

				rootScriptKey := asset.ToSerialized(
					input.ScriptKey.PubKey,
				)
				root := &SplitLocator{
					OutputIndex: 0,
					AssetID:     genesisNormal.ID(),
					ScriptKey:   rootScriptKey,
					Amount:      1,
				}
				external := []*SplitLocator{{
					OutputIndex: 1,
					AssetID:     genesisNormal.ID(),
					ScriptKey:   asset.RandSerializedKey(t),
					Amount:      uint64(18446744073709551515),
				}, {
					OutputIndex: 2,
					AssetID:     genesisNormal.ID(),
					ScriptKey:   asset.RandSerializedKey(t),
					Amount:      uint64(103),
				}}

				return input, root, external
			},
			err: ErrInvalidSplitAmount,
		},
	}

	for _, testCase := range testCases {
		success := t.Run(testCase.name, func(t *testing.T) {
			input, root, external := testCase.f()
			inputs := []SplitCommitmentInput{{
				Asset:    input,
				OutPoint: outPoint,
			}}
			split, err := NewSplitCommitment(
				context.Background(), inputs, root, external...,
			)
			require.Equal(t, testCase.err, err)

			if testCase.err != nil {
				return
			}

			// Verify that the asset input is well-formed within the
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
				t, root.ScriptKey.SchnorrSerialized(),
				schnorr.SerializePubKey(
					split.RootAsset.ScriptKey.PubKey,
				),
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

				// Make sure that the splits don't inherit lock
				// time information from the root asset.
				require.Zero(t, splitAsset.LockTime)
				require.Zero(t, splitAsset.RelativeLockTime)

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
					t, l.ScriptKey.SchnorrSerialized(),
					schnorr.SerializePubKey(
						splitAsset.ScriptKey.PubKey,
					),
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

// TestTapCommitmentKeyPopulation tests a series of invariants related to the
// Taproot Asset commitment key.
func TestTapCommitmentKeyPopulation(t *testing.T) {
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
		a := randAsset(t, genesis, nil)

		var groupKey *asset.GroupKey
		if assetDesc.HasGroupKey {
			groupKey = asset.RandGroupKey(t, genesis, a)
			a = asset.NewAssetNoErr(
				t, genesis, a.Amount, a.LockTime,
				a.RelativeLockTime, a.ScriptKey, groupKey,
				asset.WithAssetVersion(a.Version),
			)
		}

		commitment, err := NewAssetCommitment(a)
		require.NoError(t, err)

		// The Taproot Asset commitment key value MUST always be set for
		// the commitment to be well-formed.
		var zero [32]byte
		if commitment.TapCommitmentKey() == zero {
			t.Log("commitment has blank Taproot Asset commitment " +
				"key!")
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
	group1Anchor := randAsset(t, genesis1, nil)
	groupKey1, group1PrivBytes := asset.RandGroupKeyWithSigner(
		t, nil, genesis1, group1Anchor,
	)
	group1Anchor = asset.NewAssetNoErr(
		t, genesis1, group1Anchor.Amount, group1Anchor.LockTime,
		group1Anchor.RelativeLockTime, group1Anchor.ScriptKey,
		groupKey1, asset.WithAssetVersion(group1Anchor.Version),
	)
	group2Anchor := randAsset(t, genesis2, nil)
	groupKey2 := asset.RandGroupKey(t, genesis2, group2Anchor)
	group1Reissued := randAsset(t, genesis2, nil)
	genTxBuilder := asset.MockGroupTxBuilder{}
	group1Priv, group1Pub := btcec.PrivKeyFromBytes(group1PrivBytes)
	group1ReissuedGroupReq := asset.NewGroupKeyRequestNoErr(
		t, test.PubToKeyDesc(group1Pub), fn.None[asset.ExternalKey](),
		genesis1, group1Reissued, nil, fn.None[chainhash.Hash](),
	)
	group1ReissuedGenTx, err := group1ReissuedGroupReq.BuildGroupVirtualTx(
		&genTxBuilder,
	)
	require.NoError(t, err)

	group1ReissuedGroupKey, err := asset.DeriveGroupKey(
		asset.NewMockGenesisSigner(group1Priv), *group1ReissuedGenTx,
		*group1ReissuedGroupReq, nil,
	)
	require.NoError(t, err)
	group1Reissued = asset.NewAssetNoErr(
		t, genesis2, group1Reissued.Amount, group1Reissued.LockTime,
		group1Reissued.RelativeLockTime, group1Reissued.ScriptKey,
		group1ReissuedGroupKey,
		asset.WithAssetVersion(group1Reissued.Version),
	)

	assetNoGroup := randAsset(t, genesis2, nil)
	copyOfAssetNoGroup := assetNoGroup.Copy()

	// Create two AssetCommitments, both including one asset.
	// One AssetCommitment includes an asset with a group key.
	groupAssetCommitment, err := NewAssetCommitment(group1Anchor)
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
			name: "asset type mismatch",
			f: func() (*asset.Asset, error) {
				mismatchedAsset := randAsset(t, genesis1collect, nil)
				return nil, groupAssetCommitment.Upsert(mismatchedAsset)
			},
			numAssets: 0,
			err:       ErrAssetTypeMismatch,
		},
		{
			name: "fresh asset commitment",
			f: func() (*asset.Asset, error) {
				return group1Anchor, nil
			},
			numAssets: 1,
			err:       nil,
		},
		{
			name: "insertion of asset with group key",
			f: func() (*asset.Asset, error) {
				return group1Reissued,
					groupAssetCommitment.Upsert(group1Reissued)
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
			// as well as the inclusion of an inserted asset or non-inclusion
			// of a deleted asset.
			if testCase.err == nil {
				switch testCase.numAssets {
				// Deletion with no group key.
				case 0:
					assets := soloAssetCommitment.Assets()
					require.Equal(t, len(assets), testCase.numAssets)
					_, ok := groupAssetCommitment.Asset(
						asset.AssetCommitmentKey(),
					)
					require.False(t, ok)

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
					committedAsset, ok := groupAssetCommitment.Asset(
						asset.AssetCommitmentKey(),
					)
					require.True(t, ok)
					require.True(t, asset.DeepEqual(
						committedAsset,
					))
				}
			}
		})
		if !success {
			return
		}
	}
}

// TestUpdateTapCommitment asserts that we can properly insert and remove
// assetCommitments from a TapCommitment.
func TestUpdateTapCommitment(t *testing.T) {
	t.Parallel()

	// Create two assets with different geneses and groupKeys, to ensure
	// they are not in the same AssetCommitment.
	genesis1 := asset.RandGenesis(t, asset.Normal)
	genesis2 := asset.RandGenesis(t, asset.Normal)
	protoAsset1 := randAsset(t, genesis1, nil)
	protoAsset2 := randAsset(t, genesis2, nil)
	groupKey1 := asset.RandGroupKey(t, genesis1, protoAsset1)
	groupKey2 := asset.RandGroupKey(t, genesis2, protoAsset2)

	// We also create a third asset which is in the same group as the first
	// one, to ensure that we can properly create Taproot Asset commitments
	// from asset commitments of the same group.
	genesis3 := asset.RandGenesis(t, asset.Normal)
	asset3 := randAsset(t, genesis3, groupKey1)

	asset1 := asset.NewAssetNoErr(
		t, genesis1, protoAsset1.Amount, protoAsset1.LockTime,
		protoAsset1.RelativeLockTime, protoAsset1.ScriptKey, groupKey1,
		asset.WithAssetVersion(protoAsset1.Version),
	)

	asset2 := asset.NewAssetNoErr(
		t, genesis2, protoAsset2.Amount, protoAsset2.LockTime,
		protoAsset2.RelativeLockTime, protoAsset2.ScriptKey, groupKey2,
		asset.WithAssetVersion(protoAsset2.Version),
	)

	assetCommitment1, err := NewAssetCommitment(asset1)
	require.NoError(t, err)

	commitmentKey1 := assetCommitment1.TapCommitmentKey()

	assetCommitment2, err := NewAssetCommitment(asset2)
	require.NoError(t, err)

	commitmentKey2 := assetCommitment2.TapCommitmentKey()
	assetCommitment3, err := NewAssetCommitment(asset3)
	require.NoError(t, err)
	commitmentKey3 := assetCommitment3.TapCommitmentKey()

	// When creating a Taproot Asset commitment from all three assets, we
	// expect two commitments to be created, one for each group.
	tapCommitVersion := RandTapCommitVersion()
	cp1, err := assetCommitment1.Copy()
	require.NoError(t, err)
	cp2, err := assetCommitment2.Copy()
	require.NoError(t, err)
	cp3, err := assetCommitment3.Copy()
	require.NoError(t, err)
	commitment, err := NewTapCommitment(tapCommitVersion, cp1, cp2, cp3)
	require.NoError(t, err)
	require.Len(t, commitment.Commitments(), 2)
	require.Len(t, commitment.CommittedAssets(), 3)

	require.Equal(t, commitmentKey1, commitmentKey3)

	// Make sure we can still generate proper proofs for all assets.
	p1, _, err := commitment.Proof(
		commitmentKey1, asset1.AssetCommitmentKey(),
	)
	require.NoError(t, err)
	require.True(t, p1.DeepEqual(asset1))
	p2, _, err := commitment.Proof(
		commitmentKey2, asset2.AssetCommitmentKey(),
	)
	require.NoError(t, err)
	require.True(t, p2.DeepEqual(asset2))
	p3, _, err := commitment.Proof(
		commitmentKey3, asset3.AssetCommitmentKey(),
	)
	require.NoError(t, err)
	require.True(t, p3.DeepEqual(asset3))

	// Mint a new Taproot Asset commitment with only the first
	// assetCommitment.
	commitment, err = NewTapCommitment(tapCommitVersion, assetCommitment1)
	require.NoError(t, err)

	copyOfCommitment, err := NewTapCommitment(
		tapCommitVersion, assetCommitment1,
	)
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

	// Make a new Taproot Asset commitment directly from the same assets,
	// and check equality with the version made via upserts.
	commitmentFromAssets, err := FromAssets(
		tapCommitVersion, asset1, asset2,
	)
	require.NoError(t, err)

	require.Equal(
		t, copyOfCommitment.TapscriptRoot(nil),
		commitmentFromAssets.TapscriptRoot(nil),
	)

	// Make sure that when we upsert an empty asset commitment, the whole
	// asset tree is pruned from the Taproot Asset tree.
	err = assetCommitment2.Delete(asset2)
	require.NoError(t, err)
	require.Equal(
		t, mssmt.EmptyTreeRootHash,
		assetCommitment2.TreeRoot.NodeHash(),
	)

	err = copyOfCommitment.Upsert(assetCommitment2)
	require.NoError(t, err)

	_, ok := copyOfCommitment.Commitment(asset2)
	require.False(t, ok)

	// And if we remove the second asset commitment, we arrive at an empty
	// Taproot Asset tree.
	err = assetCommitment1.Delete(asset1)
	require.NoError(t, err)
	require.Equal(
		t, mssmt.EmptyTreeRootHash,
		assetCommitment1.TreeRoot.NodeHash(),
	)

	err = copyOfCommitment.Upsert(assetCommitment1)
	require.NoError(t, err)

	_, ok = copyOfCommitment.Commitment(asset1)
	require.False(t, ok)
	require.Equal(
		t, mssmt.EmptyTreeRootHash,
		copyOfCommitment.TreeRoot.NodeHash(),
	)
}

// TestTapCommitmentAltLeaves asserts that we can properly fetch, trim, and
// merge alt leaves to and from a TapCommitment.
func TestTapCommitmentAltLeaves(t *testing.T) {
	t.Parallel()

	// Create two random assets, to populate our Tap commitment.
	asset1 := asset.RandAsset(t, asset.Normal)
	asset2 := asset.RandAsset(t, asset.Collectible)

	// We'll create three AltLeaves. Leaves 1 and 2 are valid, and leaf 3
	// will collide with leaf 1.
	leaf1 := asset.RandAltLeaf(t)
	leaf2 := asset.RandAltLeaf(t)
	leaf3 := asset.RandAltLeaf(t)
	leaf3.ScriptKey.PubKey = leaf1.ScriptKey.PubKey
	leaf4 := asset.RandAltLeaf(t)

	// Create our initial, asset-only, Tap commitment.
	commitment, err := FromAssets(nil, asset1, asset2)
	require.NoError(t, err)
	assetOnlyTapLeaf := commitment.TapLeaf()

	// If we try to trim any alt leaves, we should get none back.
	_, altLeaves, err := TrimAltLeaves(commitment)
	require.NoError(t, err)
	require.Empty(t, altLeaves)

	// Trying to merge colliding alt leaves should fail.
	err = commitment.MergeAltLeaves([]asset.AltLeaf[asset.Asset]{
		leaf1, leaf3,
	})
	require.ErrorIs(t, err, asset.ErrDuplicateAltLeafKey)

	// Merging non-colliding, valid alt leaves should succeed. The new
	// commitment should contain three AssetCommitments, since we've created
	// an AltCommitment.
	err = commitment.MergeAltLeaves([]asset.AltLeaf[asset.Asset]{
		leaf1, leaf2,
	})
	require.NoError(t, err)
	require.Len(t, commitment.assetCommitments, 3)

	// Trying to merge an alt leaf that will collide with an existing leaf
	// should also fail.
	err = commitment.MergeAltLeaves([]asset.AltLeaf[asset.Asset]{leaf3})
	require.ErrorIs(t, err, asset.ErrDuplicateAltLeafKey)

	// Merging a valid, non-colliding, new alt leaf into an existing
	// AltCommitment should succeed.
	err = commitment.MergeAltLeaves([]asset.AltLeaf[asset.Asset]{leaf4})
	require.NoError(t, err)

	// If we fetch the alt leaves, they should not be removed from the
	// commitment.
	finalTapLeaf := commitment.TapLeaf()
	fetchedAltLeaves, err := commitment.FetchAltLeaves()
	require.NoError(t, err)
	require.Equal(t, finalTapLeaf, commitment.TapLeaf())
	insertedAltLeaves := []*asset.Asset{leaf1, leaf2, leaf4}

	// The fetched leaves must be equal to the three leaves we successfully
	// inserted.
	asset.CompareAltLeaves(
		t, asset.ToAltLeaves(insertedAltLeaves),
		asset.ToAltLeaves(fetchedAltLeaves),
	)

	// Now, if we trim out the alt leaves, the AltCommitment should be fully
	// removed.
	originalCommitment, _, err := TrimAltLeaves(commitment)
	require.NoError(t, err)

	trimmedTapLeaf := originalCommitment.TapLeaf()
	require.NotEqual(t, finalTapLeaf, trimmedTapLeaf)
	require.Equal(t, assetOnlyTapLeaf, trimmedTapLeaf)

	// The trimmed leaves should match the leaves we successfully merged
	// into the commitment.
	asset.CompareAltLeaves(
		t, asset.ToAltLeaves(fetchedAltLeaves),
		asset.ToAltLeaves(insertedAltLeaves),
	)
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
	require.Equal(t, assetCommitment.TapKey, assetCommitmentCopy.TapKey)
	require.True(
		t, mssmt.IsEqualNode(
			assetCommitment.TreeRoot, assetCommitmentCopy.TreeRoot,
		),
	)
}

// TestTapCommitmentDeepCopy tests that we're able to properly perform a deep
// copy of a given Taproot Asset commitment.
func TestTapCommitmentDeepCopy(t *testing.T) {
	t.Parallel()

	// Fist, we'll make two asset commitments with a random asset, then
	// make a Taproot Asset commitment out of that.
	genesis1 := asset.RandGenesis(t, asset.Normal)
	protoAsset1 := randAsset(t, genesis1, nil)
	groupKey1 := asset.RandGroupKey(t, genesis1, protoAsset1)
	asset1 := asset.NewAssetNoErr(
		t, genesis1, protoAsset1.Amount, protoAsset1.LockTime,
		protoAsset1.RelativeLockTime, protoAsset1.ScriptKey, groupKey1,
		asset.WithAssetVersion(protoAsset1.Version),
	)

	genesis2 := asset.RandGenesis(t, asset.Normal)
	protoAsset2 := randAsset(t, genesis2, nil)
	groupKey2 := asset.RandGroupKey(t, genesis2, protoAsset2)
	asset2 := asset.NewAssetNoErr(
		t, genesis2, protoAsset2.Amount, protoAsset2.LockTime,
		protoAsset2.RelativeLockTime, protoAsset2.ScriptKey, groupKey2,
		asset.WithAssetVersion(protoAsset2.Version),
	)

	assetCommitment1, err := NewAssetCommitment(asset1)
	require.NoError(t, err)

	assetCommitment2, err := NewAssetCommitment(asset2)
	require.NoError(t, err)

	// With both commitments created, we'll now make a new Taproot Asset
	// commitment then copy it.
	tapCommitment, err := NewTapCommitment(
		RandTapCommitVersion(), assetCommitment1, assetCommitment2,
	)
	require.NoError(t, err)

	newCommitment, err := tapCommitment.Copy()
	require.NoError(t, err)

	// The new Taproot Asset commitment should match the existing one
	// exactly.
	require.Equal(t, tapCommitment.Version, newCommitment.Version)
	require.True(t, mssmt.IsEqualNode(
		tapCommitment.TreeRoot, newCommitment.TreeRoot),
	)
}

// TestIsTaprootAssetCommitmentScript tests that we're able to properly
// verify if a given script is a valid Taproot Asset commitment script or not.
func TestIsTaprootAssetCommitmentScript(t *testing.T) {
	t.Parallel()

	require.True(t, IsTaprootAssetCommitmentScript(testTapCommitmentScript))
	require.False(t, IsTaprootAssetCommitmentScript(TaprootAssetsMarker[:]))
}

// TestAssetCommitmentNoWitness tests that an asset commitment of a v1 asset is
// the same with and without the witness field of the asset set.
func TestAssetCommitmentNoWitness(t *testing.T) {
	t.Parallel()

	// We'll start by generating a random asset.
	genesis1 := asset.RandGenesis(t, asset.Normal)
	asset1 := randAsset(t, genesis1, nil)

	// We'll modify the asset version so it uses the segwit encoding for
	// the leaf commitment.
	asset1.Version = asset.V1

	// We'll modify the asset witness to obtain a valid prev ID, along with
	// some random data.
	var randTxid chainhash.Hash
	_, err := rand.Read(randTxid[:])
	require.NoError(t, err)

	asset1.PrevWitnesses[0].PrevID.OutPoint = wire.OutPoint{
		Index: uint32(rand.Int()),
		Hash:  randTxid,
	}
	asset1.PrevWitnesses[0].PrevID.ID = asset.ID(randTxid)
	copy(asset1.PrevWitnesses[0].PrevID.ScriptKey[:], randTxid[:])

	// Now that we have all our initial information set, we'll make a copy
	// of the above asset. One of them will have a witness vector field,
	// the other won't.
	assetNoWitness := asset1.Copy()

	asset1.PrevWitnesses[0].TxWitness = [][]byte{randTxid[:]}

	// Next, we'll use the assets to create two root tap commitments.
	tapCommitVersion := RandTapCommitVersion()
	commitmentWitness, err := FromAssets(tapCommitVersion, asset1)
	require.NoError(t, err)

	commitmentNoWitness, err := FromAssets(tapCommitVersion, assetNoWitness)
	require.NoError(t, err)

	// The two commitment should be identical as this asset version leaves
	// out the tx witness field in the leaf encoding.
	require.Equal(
		t, commitmentWitness.TapscriptRoot(nil),
		commitmentNoWitness.TapscriptRoot(nil),
	)

	// If we make the asset into a V0 asset, then recompute the commitment,
	// we should get a distinct root.
	asset1.Version = asset.V0
	commitmentV0, err := FromAssets(tapCommitVersion, asset1)
	require.NoError(t, err)

	require.NotEqual(
		t, commitmentWitness.TapscriptRoot(nil),
		commitmentV0.TapscriptRoot(nil),
	)
}

// TestTapCommitmentUpsertMaxVersion tests that when we upsert with different
// commitments, that the max version is properly updated.
func TestTapCommitmentUpsertMaxVersion(t *testing.T) {
	t.Parallel()

	// We'll start with a random asset. We'll make sure this asset is
	// version 0.
	genesis1 := asset.RandGenesis(t, asset.Normal)
	asset1 := randAsset(t, genesis1, nil)
	asset1.Version = asset.V0

	// Next, we'll make another asset, this time with version 1.
	genesis2 := asset.RandGenesis(t, asset.Normal)
	asset2 := randAsset(t, genesis2, nil)
	asset2.Version = asset.V1

	// Next, we'll create a new commitment with just the first asset.
	tapCommitment, err := FromAssets(nil, asset1)
	require.NoError(t, err)

	// The version should be zero, as the asset version is 0.
	require.Equal(t, TapCommitmentV0, tapCommitment.Version)

	// Next, we'll upsert the second asset, which should bump the version
	// to v1.
	assetCommitment, err := NewAssetCommitment(asset2)
	require.NoError(t, err)

	require.NoError(t, tapCommitment.Upsert(assetCommitment))

	require.Equal(t, TapCommitmentV1, tapCommitment.Version)

	// Finally, we'll test the delete behavior of Upsert. We'll remove all
	// the commitments in the assetCommitment above, then Upsert. We should
	// find that the version is now zero, since Upsert with an empty tree
	// is actually a delete.
	require.NoError(t, assetCommitment.Delete(asset2))
	require.NoError(t, tapCommitment.Upsert(assetCommitment))

	// Only a V0 asset remains now after the upsert, so the version should
	// have reverted.
	require.Equal(t, TapCommitmentV0, tapCommitment.Version)
}

// TestTapCommitmentDeleteMaxVersion tests that when we delete commitments, the
// max version is also updated.
func TestTapCommitmentDeleteMaxVersion(t *testing.T) {
	t.Parallel()

	// We'll start with a random asset. We'll make sure this asset is
	// version 0.
	genesis1 := asset.RandGenesis(t, asset.Normal)
	asset1 := randAsset(t, genesis1, nil)
	asset1.Version = asset.V0

	// Next, we'll make another asset, this time with version 1.
	genesis2 := asset.RandGenesis(t, asset.Normal)
	asset2 := randAsset(t, genesis2, nil)
	asset2.Version = asset.V1

	// Next, we'll create a new commitment with both assets.
	tapCommitment, err := FromAssets(nil, asset1, asset2)
	require.NoError(t, err)

	// The version should be 1 as that's the max version of the assets.
	require.Equal(t, TapCommitmentV1, tapCommitment.Version)

	// Now we'll delete the asset with a version of 1. This should caause
	// the version to go back down to v0.
	v1Commitment, ok := tapCommitment.Commitment(asset2)
	require.True(t, ok)
	require.NoError(t, tapCommitment.Delete(v1Commitment))

	require.Equal(t, TapCommitmentV0, tapCommitment.Version)
}

// TestTapCommitmentVersionCompatibility tests that we can properly create and
// merge commitments of different versions.
func TestTapCommitmentVersionCompatibility(t *testing.T) {
	t.Parallel()

	// We'll start with two assets; a V0 and a V1 asset.
	genesis1 := asset.RandGenesis(t, asset.Normal)
	asset1 := randAsset(t, genesis1, nil)
	asset1.Version = asset.V0

	genesis2 := asset.RandGenesis(t, asset.Collectible)
	asset2 := randAsset(t, genesis2, nil)
	asset2.Version = asset.V1

	// If the commitment is V2, the version of the input assets should not
	// affect the final version of the commitment.
	asset1TapCommitment, err := FromAssets(fn.Ptr(TapCommitmentV2), asset1)
	require.NoError(t, err)
	require.Equal(t, TapCommitmentV2, asset1TapCommitment.Version)

	asset2TapCommitment, err := FromAssets(fn.Ptr(TapCommitmentV2), asset2)
	require.NoError(t, err)
	require.Equal(t, TapCommitmentV2, asset2TapCommitment.Version)

	// Asset deletion should not affect the tap commitment version.
	tapCommitment, err := FromAssets(
		fn.Ptr(TapCommitmentV2), asset1, asset2,
	)
	require.NoError(t, err)
	require.Equal(t, TapCommitmentV2, tapCommitment.Version)

	assetCommitment, err := NewAssetCommitment(asset1)
	require.NoError(t, err)

	require.NoError(t, assetCommitment.Delete(asset1))
	require.NoError(t, tapCommitment.Upsert(assetCommitment))
	require.Equal(t, TapCommitmentV2, tapCommitment.Version)

	// Unknown commitment versions should be rejected.
	invalidCommitment, err := FromAssets(
		fn.Ptr(TapCommitmentVersion(22)), asset1, asset2,
	)
	require.Nil(t, invalidCommitment)
	require.ErrorIs(t, err, ErrInvalidTapCommitmentVersion)

	// Tap commitment merging should fail if only one commitment is V2.
	notV2Commitment, err := FromAssets(nil, asset1, asset2)
	require.NoError(t, err)

	err = tapCommitment.Merge(notV2Commitment)
	require.ErrorContains(t, err, "commitment version mismatch: 2, 1")

	err = notV2Commitment.Merge(tapCommitment)
	require.ErrorContains(t, err, "commitment version mismatch: 1, 2")

	// Merging two V2 commitments should succeed.
	genesis3 := asset.RandGenesis(t, asset.Collectible)
	asset3 := randAsset(t, genesis3, nil)

	newCommitment, err := FromAssets(fn.Ptr(TapCommitmentV2), asset3)
	require.NoError(t, err)

	err = newCommitment.Merge(tapCommitment)
	require.NoError(t, err)

	// If we make a proof from a V2 commitment, and then mutate the tap
	// commitment version in the proof, the computed tap leaves should not
	// match.
	_, proof, err := newCommitment.Proof(
		asset2.TapCommitmentKey(), asset2.AssetCommitmentKey(),
	)
	require.NoError(t, err)
	require.NotNil(t, proof)

	proof.TaprootAssetProof.Version = test.RandFlip(
		TapCommitmentV0, TapCommitmentV1,
	)
	derivedCommitment, err := proof.DeriveByAssetInclusion(asset2)
	require.NoError(t, err)
	require.NotEqual(
		t, newCommitment.TapLeaf(), derivedCommitment.TapLeaf(),
	)
}

// TestAssetCommitmentUpsertMaxVersion tests that when we upsert with different
// commitments, that the max version is properly updated.
func TestAssetCommitmentUpsertMaxVersion(t *testing.T) {
	t.Parallel()

	// We'll start with a random asset. We'll make sure this asset is
	// version 0.
	genesis := asset.RandGenesis(t, asset.Normal)
	asset1 := randAsset(t, genesis, nil)
	asset1.Version = asset.V0

	// Next, we'll make another asset, this time with version 1.
	asset2 := randAsset(t, genesis, nil)
	asset2.Version = asset.V1

	// Next, we'll create a new commitment with just the first asset.
	assetCommitment, err := NewAssetCommitment(asset1)
	require.NoError(t, err)

	// The version should be zero, as the asset version is 0.
	require.Equal(t, asset.V0, assetCommitment.Version)

	// Next, we'll upsert the second asset, which should bump the version
	// to v1.
	require.NoError(t, assetCommitment.Upsert(asset2))

	require.Equal(t, asset.V1, assetCommitment.Version)
}

// TestAssetCommitmentDeleteMaxVersion tests that when we delete commitments,
// the max version is also updated.
func TestAssetCommitmentDeleteMaxVersion(t *testing.T) {
	t.Parallel()

	// We'll start with a random asset. We'll make sure this asset is
	// version 0.
	genesis := asset.RandGenesis(t, asset.Normal)
	asset1 := randAsset(t, genesis, nil)
	asset1.Version = asset.V0

	// Next, we'll make another asset, this time with version 1.
	asset2 := randAsset(t, genesis, nil)
	asset2.Version = asset.V1

	// Next, we'll create a new commitment with both assets.
	assetCommitment, err := NewAssetCommitment(asset1, asset2)
	require.NoError(t, err)

	// The version should be 1 as that's the max version of the assets.
	require.Equal(t, asset.V1, assetCommitment.Version)

	// Now we'll delete the asset with a version of 1. This should caause
	// the version to go back down to v0.
	require.NoError(t, assetCommitment.Delete(asset2))

	require.Equal(t, asset.V0, assetCommitment.Version)
}

// TestProofUnknownOddType tests that an unknown odd type is allowed in a
// commitment proof and that we can still arrive at the correct root hash with
// it.
func TestProofUnknownOddType(t *testing.T) {
	genesis := asset.RandGenesis(t, asset.Normal)
	asset1 := randAsset(t, genesis, nil)

	singleCommitment, err := FromAssets(nil, asset1)
	require.NoError(t, err)

	_, knownProof, err := singleCommitment.Proof(
		asset1.TapCommitmentKey(), asset1.AssetCommitmentKey(),
	)
	require.NoError(t, err)

	var knownProofBytes []byte
	test.RunUnknownOddTypeTest(
		t, knownProof, &asset.ErrUnknownType{},
		func(buf *bytes.Buffer, proof *Proof) error {
			err := proof.Encode(buf)

			knownProofBytes = fn.CopySlice(buf.Bytes())

			return err
		},
		func(buf *bytes.Buffer) (*Proof, error) {
			var parsedProof Proof
			return &parsedProof, parsedProof.Decode(buf)
		},
		func(parsedProof *Proof, unknownTypes tlv.TypeMap) {
			require.Equal(
				t, unknownTypes, parsedProof.UnknownOddTypes,
			)

			// The proof should've changed, to make sure the
			// unknown value was taken into account when creating
			// the serialized proof.
			var newBuf bytes.Buffer
			err = parsedProof.Encode(&newBuf)
			require.NoError(t, err)

			require.NotEqual(t, knownProofBytes, newBuf.Bytes())

			parsedProof.UnknownOddTypes = nil
			require.Equal(t, knownProof, parsedProof)
		},
	)
}

// TestAssetProofUnknownOddType tests that an unknown odd type is allowed in an
// asset proof and that we can still arrive at the correct root hash with it.
func TestAssetProofUnknownOddType(t *testing.T) {
	genesis := asset.RandGenesis(t, asset.Normal)
	asset1 := randAsset(t, genesis, nil)

	singleCommitment, err := FromAssets(nil, asset1)
	require.NoError(t, err)

	_, commitmentProof, err := singleCommitment.Proof(
		asset1.TapCommitmentKey(), asset1.AssetCommitmentKey(),
	)
	require.NoError(t, err)

	require.NotNil(t, commitmentProof.AssetProof)
	knownAssetProof := commitmentProof.AssetProof

	var knownProofBytes []byte
	test.RunUnknownOddTypeTest(
		t, knownAssetProof, &asset.ErrUnknownType{},
		func(buf *bytes.Buffer, proof *AssetProof) error {
			err := AssetProofEncoder(buf, &proof, nil)

			knownProofBytes = fn.CopySlice(buf.Bytes())

			return err
		},
		func(buf *bytes.Buffer) (*AssetProof, error) {
			parsedProof := &AssetProof{}
			return parsedProof, AssetProofDecoder(
				buf, &parsedProof, nil, uint64(buf.Len()),
			)
		},
		func(parsedProof *AssetProof, unknownTypes tlv.TypeMap) {
			require.Equal(
				t, unknownTypes, parsedProof.UnknownOddTypes,
			)

			// The proof should've changed, to make sure the unknown
			// value was taken into account when creating the
			// serialized proof.
			var newBuf bytes.Buffer
			err = AssetProofEncoder(&newBuf, &parsedProof, nil)
			require.NoError(t, err)

			require.NotEqual(t, knownProofBytes, newBuf.Bytes())

			parsedProof.UnknownOddTypes = nil
			require.Equal(t, knownAssetProof, parsedProof)
		},
	)
}

// TestTaprootAssetProofUnknownOddType tests that an unknown odd type is allowed
// in a Taproot asset proof and that we can still arrive at the correct root
// hash with it.
func TestTaprootAssetProofUnknownOddType(t *testing.T) {
	genesis := asset.RandGenesis(t, asset.Normal)
	asset1 := randAsset(t, genesis, nil)

	singleCommitment, err := FromAssets(nil, asset1)
	require.NoError(t, err)

	_, commitmentProof, err := singleCommitment.Proof(
		asset1.TapCommitmentKey(), asset1.AssetCommitmentKey(),
	)
	require.NoError(t, err)

	knownTaprootAssetProof := commitmentProof.TaprootAssetProof

	var knownProofBytes []byte
	test.RunUnknownOddTypeTest(
		t, knownTaprootAssetProof, &asset.ErrUnknownType{},
		func(buf *bytes.Buffer, proof TaprootAssetProof) error {
			err := TaprootAssetProofEncoder(buf, &proof, nil)

			knownProofBytes = fn.CopySlice(buf.Bytes())

			return err
		},
		func(buf *bytes.Buffer) (TaprootAssetProof, error) {
			var parsedProof TaprootAssetProof
			return parsedProof, TaprootAssetProofDecoder(
				buf, &parsedProof, nil, uint64(buf.Len()),
			)
		},
		func(parsedProof TaprootAssetProof, unknownTypes tlv.TypeMap) {
			require.Equal(
				t, unknownTypes, parsedProof.UnknownOddTypes,
			)

			// The proof should've changed, to make sure the unknown
			// value was taken into account when creating the
			// serialized proof.
			var newBuf bytes.Buffer
			err = TaprootAssetProofEncoder(
				&newBuf, &parsedProof, nil,
			)
			require.NoError(t, err)

			require.NotEqual(t, knownProofBytes, newBuf.Bytes())

			parsedProof.UnknownOddTypes = nil
			require.Equal(t, knownTaprootAssetProof, parsedProof)
		},
	)
}
