package asset

import (
	"bytes"
	"math/rand"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// testCaseGkrEncodeDecode defines a unit test case for encoding
// and decoding a group key reveal.
type testCaseGkrEncodeDecode struct {
	testName string

	version NonSpendLeafVersion

	internalKey       btcec.PublicKey
	genesisAssetID    ID
	customSubtreeRoot fn.Option[chainhash.Hash]
}

// GroupKeyReveal generates a GroupKeyReveal instance from the test case.
func (tc testCaseGkrEncodeDecode) GroupKeyReveal() (GroupKeyReveal, error) {
	gkr, err := NewGroupKeyRevealV1(
		tc.version, tc.internalKey, tc.genesisAssetID,
		tc.customSubtreeRoot,
	)

	return &gkr, err
}

// TestGroupKeyRevealEncodeDecode tests encoding and decoding of GroupKeyReveal.
func TestGroupKeyRevealEncodeDecode(t *testing.T) {
	t.Parallel()

	// Create a random internal public key.
	internalKey := *(test.RandPubKey(t))

	// Create a random genesis asset ID.
	randomAssetIdBytes := test.RandBytes(32)
	genesisAssetID := ID(randomAssetIdBytes)

	// Construct a custom user script leaf. This is used to validate any
	// control block.
	customScriptLeaf := txscript.NewBaseTapLeaf(
		[]byte("I'm a custom user script"),
	)
	customSubtreeRoot := fn.Some(customScriptLeaf.TapHash())

	testCases := []testCaseGkrEncodeDecode{
		{
			testName: "no custom root",

			version:           OpReturnVersion,
			internalKey:       internalKey,
			genesisAssetID:    genesisAssetID,
			customSubtreeRoot: fn.None[chainhash.Hash](),
		},
		{
			testName: "with custom root",

			version:           PedersenVersion,
			internalKey:       internalKey,
			genesisAssetID:    genesisAssetID,
			customSubtreeRoot: customSubtreeRoot,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.testName, func(tt *testing.T) {
			gkr, err := tc.GroupKeyReveal()
			require.NoError(tt, err)

			groupPubKey, err := gkr.GroupPubKey(tc.genesisAssetID)
			require.NoError(tt, err)

			// Encode the GroupKeyReveal into buffer.
			var buffer bytes.Buffer
			var scratchBuffEncode [8]byte
			err = GroupKeyRevealEncoder(
				&buffer, &gkr, &scratchBuffEncode,
			)
			require.NoError(tt, err)

			// Decode the GroupKeyReveal from buffer.
			var gkrDecoded GroupKeyReveal
			var scratchBuffDecode [8]byte
			err = GroupKeyRevealDecoder(
				&buffer, &gkrDecoded, &scratchBuffDecode,
				uint64(buffer.Len()),
			)
			require.NoError(tt, err)

			// Prepare the original GroupKeyReveal for comparison.
			// Remove fields which are not included in
			// encoding/decoding.
			gkrV1, ok := gkr.(*GroupKeyRevealV1)
			require.True(tt, ok)

			// Compare decoded group key reveal with the original.
			require.Equal(tt, gkrV1, gkrDecoded)

			// Ensure the decoded group public key matches the
			// original.
			groupPubKeyDecoded, err := gkrDecoded.GroupPubKey(
				tc.genesisAssetID,
			)
			require.NoError(tt, err)

			require.Equal(
				tt, groupPubKey, groupPubKeyDecoded,
				"decoded GroupKeyReveal group pub key does "+
					"not match original",
			)

			// If a custom subtree root is set, ensure the control
			// block is correct.
			if tc.customSubtreeRoot.IsSome() {
				gkrDecodedV1, ok :=
					gkrDecoded.(*GroupKeyRevealV1)
				require.True(tt, ok)

				ctrlBlock, err :=
					gkrDecodedV1.ScriptSpendControlBlock(
						tc.genesisAssetID,
					)
				require.NoError(tt, err)

				// Use the control block and the custom spend
				// script to compute the root hash.
				computedRoot := chainhash.Hash(
					ctrlBlock.RootHash(
						customScriptLeaf.Script,
					),
				)

				// Ensure the computed root matches the custom
				// subtree root.
				require.Equal(
					tt, gkrDecodedV1.tapscript.root,
					computedRoot,
				)
			}
		})
	}
}

// TestGroupKeyRevealEncodeDecodeRapid tests encoding and decoding of
// GroupKeyReveal using rapid testing. The Rapid framework is used to generate
// random test inputs.
func TestGroupKeyRevealEncodeDecodeRapid(tt *testing.T) {
	tt.Parallel()

	rapid.Check(tt, func(t *rapid.T) {
		// Generate random test inputs using rapid generators.
		//
		// Generate a random internal key.
		internalKeyBytes := rapid.SliceOfN(rapid.Byte(), 32, 32).
			Draw(t, "internal_key_bytes")

		// The internal key bytes shouldn't be all zero.
		if bytes.Equal(internalKeyBytes, make([]byte, 32)) {
			return
		}

		_, publicKey := btcec.PrivKeyFromBytes(internalKeyBytes)
		internalKey := *publicKey

		// Generate a random genesis asset ID.
		genesisAssetID := ID(rapid.SliceOfN(rapid.Byte(), 32, 32).
			Draw(t, "genesis_id"))

		// Randomly decide whether to include a custom script.
		hasCustomScript := rapid.Bool().Draw(t, "has_custom_script")

		// Version should be either 1 or 2.
		var version NonSpendLeafVersion
		if rapid.Bool().Draw(t, "version") {
			version = OpReturnVersion
		} else {
			version = PedersenVersion
		}

		// If a custom script is included, generate a random script leaf
		// and subtree root.
		var customSubtreeRoot fn.Option[chainhash.Hash]
		var customScriptLeaf *txscript.TapLeaf

		if hasCustomScript {
			// Generate random script between 1-100 bytes.
			scriptSize := rapid.IntRange(1, 100).
				Draw(t, "script_size")
			customScript := rapid.SliceOfN(
				rapid.Byte(), scriptSize, scriptSize,
			).Draw(t, "custom_script")

			leaf := txscript.NewBaseTapLeaf(customScript)
			customScriptLeaf = &leaf
			customSubtreeRoot = fn.Some(customScriptLeaf.TapHash())
		} else {
			customSubtreeRoot = fn.None[chainhash.Hash]()
		}

		// Create a new GroupKeyReveal instance from the random test
		// inputs.
		gkrV1, err := NewGroupKeyRevealV1(
			version,
			internalKey,
			genesisAssetID,
			customSubtreeRoot,
		)
		require.NoError(t, err)

		// Encode the GroupKeyReveal instance into a buffer.
		var buffer bytes.Buffer
		var scratchBuffEncode [8]byte
		gkr := GroupKeyReveal(&gkrV1)
		err = GroupKeyRevealEncoder(&buffer, &gkr, &scratchBuffEncode)
		require.NoError(t, err)

		// Decode the GroupKeyReveal instance from the buffer.
		var gkrDecoded GroupKeyReveal
		var scratchBuffDecode [8]byte
		err = GroupKeyRevealDecoder(
			&buffer, &gkrDecoded, &scratchBuffDecode,
			uint64(buffer.Len()),
		)
		require.NoError(t, err)

		// Compare decoded with original.
		require.Equal(t, &gkrV1, gkrDecoded)

		// Verify decoded group public key.
		//
		// First derive a group public key from the original.
		groupPubKey, err := gkrV1.GroupPubKey(genesisAssetID)
		require.NoError(t, err)

		// Then derive a group public key from the decoded.
		groupPubKeyDecoded, err := gkrDecoded.GroupPubKey(
			genesisAssetID,
		)
		require.NoError(t, err)

		require.Equal(t, groupPubKey, groupPubKeyDecoded)

		// If a custom subtree root is set on the decoded
		// GroupKeyReveal, ensure the derived control block is correct.
		if customSubtreeRoot.IsSome() && customScriptLeaf != nil {
			gkrDecodedV1, ok := gkrDecoded.(*GroupKeyRevealV1)
			require.True(t, ok)

			ctrlBlock, err := gkrDecodedV1.ScriptSpendControlBlock(
				genesisAssetID,
			)
			require.NoError(t, err)

			computedRoot := chainhash.Hash(
				ctrlBlock.RootHash(customScriptLeaf.Script),
			)

			// Ensure the computed root matches the tapscript root
			// for both the original and decoded GroupKeyReveal.
			require.Equal(
				t, gkrV1.tapscript.root, computedRoot,
			)
			require.Equal(
				t, gkrDecodedV1.tapscript.root, computedRoot,
			)
		}
	})
}

// TestNonSpendableLeafScript tests that the non-spendable leaf script is
// actually non-spendable.
func TestNonSpendableLeafScript(t *testing.T) {
	var assetID ID
	_, err := rand.Read(assetID[:])
	require.NoError(t, err)

	internalKey := test.RandPubKey(t)

	const amt = 1000

	testCases := []struct {
		name string

		version   NonSpendLeafVersion
		errString string
	}{

		{
			name:      "op_return",
			version:   OpReturnVersion,
			errString: "script returned early",
		},
		{
			name:      "pedersen",
			version:   PedersenVersion,
			errString: "signature not empty on failed checksig",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			// For this test, we'll just have the test leaf be the
			// only element in the script tree.
			testLeaf, err := NewNonSpendableScriptLeaf(
				testCase.version, assetID[:],
			)
			require.NoError(t, err)

			// From the script tree, we'll then create the taproot
			// output public key.
			scriptTree := txscript.AssembleTaprootScriptTree(
				testLeaf,
			)
			rootHash := scriptTree.RootNode.TapHash()
			outputKey := txscript.ComputeTaprootOutputKey(
				internalKey, rootHash[:],
			)

			// Finally, we'll make the dummy spend transaction, and
			// the output script that we'll attempt to spend.
			spendTx := wire.NewMsgTx(1)
			spendTx.AddTxIn(&wire.TxIn{})

			leafScript, err := txscript.PayToTaprootScript(
				outputKey,
			)
			require.NoError(t, err)

			prevOuts := txscript.NewCannedPrevOutputFetcher(
				leafScript, amt,
			)
			sigHash := txscript.NewTxSigHashes(spendTx, prevOuts)

			// If this is the Pedersen variant, then we'll actually
			// need to generate a signature.
			var sig []byte
			if testCase.version == PedersenVersion {
				privKey, _ := btcec.PrivKeyFromBytes(assetID[:])

				sig, err = txscript.RawTxInTapscriptSignature(
					spendTx, sigHash, 0, amt, leafScript,
					testLeaf, txscript.SigHashAll, privKey,
				)
				require.NoError(t, err)
			}

			proofs := scriptTree.LeafMerkleProofs[0]
			ctrlBlock := proofs.ToControlBlock(internalKey)
			ctrlBockBytes, err := ctrlBlock.ToBytes()
			require.NoError(t, err)

			// The final witness template is just the script, then
			// the control block.
			finalWitness := wire.TxWitness{
				testLeaf.Script, ctrlBockBytes,
			}

			// If we have a sig, then we'll add this on as well to
			// ensure that even a well crafted signature is
			// rejected.
			if sig != nil {
				finalWitness = append(
					[][]byte{sig}, finalWitness...,
				)
			}

			spendTx.TxIn[0].Witness = finalWitness

			// Finally, we'll execute the spend. This should fail if
			// the leaf is actually non-spendable.
			vm, err := txscript.NewEngine(
				leafScript, spendTx, 0,
				txscript.StandardVerifyFlags, nil, sigHash,
				amt, prevOuts,
			)
			require.NoError(t, err)

			err = vm.Execute()
			require.Error(t, err)
			require.ErrorContains(t, err, testCase.errString)
		})
	}
}

// TestGroupKeyIsEqual tests that GroupKey.IsEqual is correct.
func TestGroupKeyIsEqual(t *testing.T) {
	t.Parallel()

	testKey := &GroupKey{
		RawKey: keychain.KeyDescriptor{
			// Fill in some non-defaults.
			KeyLocator: keychain.KeyLocator{
				Family: keychain.KeyFamilyMultiSig,
				Index:  1,
			},
			PubKey: pubKey,
		},
		GroupPubKey: *pubKey,
		Witness:     sigWitness,
	}

	pubKeyCopy := *pubKey

	tests := []struct {
		a, b  *GroupKey
		equal bool
	}{
		{
			a:     nil,
			b:     nil,
			equal: true,
		},
		{
			a:     &GroupKey{},
			b:     &GroupKey{},
			equal: true,
		},
		{
			a:     nil,
			b:     &GroupKey{},
			equal: false,
		},
		{
			a: testKey,
			b: &GroupKey{
				GroupPubKey: *pubKey,
			},
			equal: false,
		},
		{
			a: testKey,
			b: &GroupKey{
				GroupPubKey: testKey.GroupPubKey,
				Witness:     testKey.Witness,
			},
			equal: false,
		},
		{
			a: testKey,
			b: &GroupKey{
				RawKey: keychain.KeyDescriptor{
					KeyLocator: testKey.RawKey.KeyLocator,
					PubKey:     nil,
				},

				GroupPubKey: testKey.GroupPubKey,
				Witness:     testKey.Witness,
			},
			equal: false,
		},
		{
			a: testKey,
			b: &GroupKey{
				RawKey: keychain.KeyDescriptor{
					PubKey: &pubKeyCopy,
				},

				GroupPubKey: testKey.GroupPubKey,
				Witness:     testKey.Witness,
			},
			equal: false,
		},
		{
			a: testKey,
			b: &GroupKey{
				RawKey: keychain.KeyDescriptor{
					KeyLocator: testKey.RawKey.KeyLocator,
					PubKey:     &pubKeyCopy,
				},

				GroupPubKey: testKey.GroupPubKey,
				Witness:     testKey.Witness,
			},
			equal: true,
		},
		{
			a: &GroupKey{
				GroupPubKey: testKey.GroupPubKey,
				Witness:     testKey.Witness,
			},
			b: &GroupKey{
				GroupPubKey: testKey.GroupPubKey,
				Witness:     testKey.Witness,
			},
			equal: true,
		},
		{
			a: &GroupKey{
				RawKey: keychain.KeyDescriptor{
					KeyLocator: testKey.RawKey.KeyLocator,
				},
				GroupPubKey: testKey.GroupPubKey,
				Witness:     testKey.Witness,
			},
			b: &GroupKey{
				RawKey: keychain.KeyDescriptor{
					KeyLocator: testKey.RawKey.KeyLocator,
				},
				GroupPubKey: testKey.GroupPubKey,
				Witness:     testKey.Witness,
			},
			equal: true,
		},
	}

	for _, testCase := range tests {
		testCase := testCase
		require.Equal(t, testCase.equal, testCase.a.IsEqual(testCase.b))
		require.Equal(t, testCase.equal, testCase.b.IsEqual(testCase.a))
	}
}

// TestDeriveGroupKeyV0 verifies the correct derivation of the V0 group key.
func TestDeriveGroupKeyV0(t *testing.T) {
	t.Parallel()

	privKey, err := btcec.NewPrivateKey()
	groupPub := privKey.PubKey()
	require.NoError(t, err)
	privKeyCopy := btcec.PrivKeyFromScalar(&privKey.Key)
	genSigner := NewMockGenesisSigner(privKeyCopy)
	genBuilder := MockGroupTxBuilder{}
	fakeKeyDesc := test.PubToKeyDesc(groupPub)
	fakeScriptKey := NewScriptKeyBip86(fakeKeyDesc)

	g := Genesis{
		FirstPrevOut: wire.OutPoint{
			Hash:  hashBytes1,
			Index: 99,
		},
		Tag:         "normal asset 1",
		MetaHash:    [MetaHashLen]byte{1, 2, 3},
		OutputIndex: 21,
		Type:        Collectible,
	}
	groupTweak := g.ID()

	internalKey := input.TweakPrivKey(privKeyCopy, groupTweak[:])
	tweakedKey := txscript.TweakTaprootPrivKey(*internalKey, nil)

	// TweakTaprootPrivKey modifies the private key that is passed in! We
	// need to provide a copy to arrive at the same result.
	protoAsset := NewAssetNoErr(t, g, 1, 0, 0, fakeScriptKey, nil)
	groupReq := NewGroupKeyRequestNoErr(
		t, fakeKeyDesc, fn.None[ExternalKey](), g, protoAsset, nil,
		fn.None[chainhash.Hash](),
	)
	genTx, err := groupReq.BuildGroupVirtualTx(&genBuilder)
	require.NoError(t, err)

	keyGroup, err := DeriveGroupKey(genSigner, *genTx, *groupReq, nil)
	require.NoError(t, err)

	require.Equal(
		t, schnorr.SerializePubKey(tweakedKey.PubKey()),
		schnorr.SerializePubKey(&keyGroup.GroupPubKey),
	)

	// We should also be able to reproduce the correct tweak with a non-nil
	// tapscript root.
	tapTweak := test.RandBytes(32)
	tweakedKey = txscript.TweakTaprootPrivKey(*internalKey, tapTweak)

	groupReq = NewGroupKeyRequestNoErr(
		t, test.PubToKeyDesc(privKey.PubKey()), fn.None[ExternalKey](),
		g, protoAsset, tapTweak, fn.None[chainhash.Hash](),
	)
	genTx, err = groupReq.BuildGroupVirtualTx(&genBuilder)
	require.NoError(t, err)

	keyGroup, err = DeriveGroupKey(genSigner, *genTx, *groupReq, nil)
	require.NoError(t, err)

	require.Equal(
		t, schnorr.SerializePubKey(tweakedKey.PubKey()),
		schnorr.SerializePubKey(&keyGroup.GroupPubKey),
	)

	// Group key tweaking should fail when given invalid tweaks.
	badTweak := test.RandBytes(33)
	_, err = GroupPubKeyV0(groupPub, badTweak, badTweak)
	require.Error(t, err)

	_, err = GroupPubKeyV0(groupPub, groupTweak[:], badTweak)
	require.Error(t, err)
}

// TestGroupKeyDerivationInvalidAsset ensures group key derivation fails
// for assets that are not valid group anchors.
func TestGroupKeyDerivationInvalidAsset(t *testing.T) {
	t.Parallel()

	groupPriv := test.RandPrivKey()
	groupPub := groupPriv.PubKey()
	groupKeyDesc := test.PubToKeyDesc(groupPub)
	genSigner := NewMockGenesisSigner(groupPriv)
	genBuilder := MockGroupTxBuilder{}

	baseGen := RandGenesis(t, Normal)
	collectGen := RandGenesis(t, Collectible)
	baseScriptKey := RandScriptKey(t)
	protoAsset := RandAssetWithValues(t, baseGen, nil, baseScriptKey)
	nonGenProtoAsset := protoAsset.Copy()
	nonGenProtoAsset.PrevWitnesses = []Witness{{
		PrevID: &PrevID{
			OutPoint: wire.OutPoint{
				Hash:  hashBytes1,
				Index: 1,
			},
			ID:        hashBytes1,
			ScriptKey: ToSerialized(pubKey),
		},
		TxWitness:       sigWitness,
		SplitCommitment: nil,
	}}
	groupedProtoAsset := protoAsset.Copy()
	groupedProtoAsset.GroupKey = &GroupKey{
		GroupPubKey: *groupPub,
	}
	groupReq := GroupKeyRequest{
		RawKey:    groupKeyDesc,
		AnchorGen: baseGen,
	}

	// A prototype asset is required for building the genesis virtual TX.
	_, err := groupReq.BuildGroupVirtualTx(&genBuilder)
	require.ErrorContains(t, err, "grouped asset cannot be nil")

	// The prototype asset must have a genesis witness.
	groupReq.NewAsset = nonGenProtoAsset
	_, err = groupReq.BuildGroupVirtualTx(&genBuilder)
	require.ErrorContains(t, err, "asset is not a genesis asset")

	// The prototype asset must not have a group key set.
	groupReq.NewAsset = groupedProtoAsset
	_, err = groupReq.BuildGroupVirtualTx(&genBuilder)
	require.ErrorContains(t, err, "asset already has group key")

	// The anchor genesis used for signing must have the same asset type
	// as the prototype asset being signed.
	groupReq.AnchorGen = collectGen
	groupReq.NewAsset = protoAsset
	_, err = groupReq.BuildGroupVirtualTx(&genBuilder)
	require.ErrorContains(t, err, "asset group type mismatch")

	// The group key request must include an internal key.
	groupReq.AnchorGen = baseGen
	groupReq.RawKey.PubKey = nil
	_, err = groupReq.BuildGroupVirtualTx(&genBuilder)
	require.ErrorContains(t, err, "missing group internal key")

	// The tapscript root in the group key request must be exactly 32 bytes
	// if present.
	groupReq.RawKey = groupKeyDesc
	groupReq.TapscriptRoot = test.RandBytes(33)
	_, err = groupReq.BuildGroupVirtualTx(&genBuilder)
	require.ErrorContains(t, err, "tapscript root must be 32 bytes")

	groupReq.TapscriptRoot = test.RandBytes(32)
	genTx, err := groupReq.BuildGroupVirtualTx(&genBuilder)
	require.NoError(t, err)

	groupKey, err := DeriveGroupKey(genSigner, *genTx, groupReq, nil)
	require.NoError(t, err)
	require.NotNil(t, groupKey)
}
