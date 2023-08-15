package asset

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

var (
	hashBytes1     = fn.ToArray[[32]byte](bytes.Repeat([]byte{1}, 32))
	hashBytes2     = fn.ToArray[[32]byte](bytes.Repeat([]byte{2}, 32))
	pubKeyBytes, _ = hex.DecodeString(
		"03a0afeb165f0ec36880b68e0baabd9ad9c62fd1a69aa998bc30e9a34620" +
			"2e078f",
	)
	pubKey, _   = btcec.ParsePubKey(pubKeyBytes)
	sigBytes, _ = hex.DecodeString(
		"e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca" +
			"821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f47" +
			"7df4900d310536c0",
	)
	sig, _     = schnorr.ParseSignature(sigBytes)
	sigWitness = wire.TxWitness{sig.Serialize()}

	generatedTestVectorName = "asset_tlv_encoding_generated.json"

	allTestVectorFiles = []string{
		generatedTestVectorName,
		"asset_tlv_encoding_error_cases.json",
	}
)

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

// TestAssetEncoding asserts that we can properly encode and decode assets
// through their TLV serialization.
func TestAssetEncoding(t *testing.T) {
	t.Parallel()

	testVectors := &TestVectors{}
	assertAssetEncoding := func(comment string, a *Asset) {
		t.Helper()

		require.True(t, a.DeepEqual(a.Copy()))

		var buf bytes.Buffer
		require.NoError(t, a.Encode(&buf))

		testVectors.ValidTestCases = append(
			testVectors.ValidTestCases, &ValidTestCase{
				Asset:    NewTestFromAsset(t, a),
				Expected: hex.EncodeToString(buf.Bytes()),
				Comment:  comment,
			},
		)

		var b Asset
		require.NoError(t, b.Decode(&buf))

		require.True(t, a.DeepEqual(&b))
	}

	splitGen := Genesis{
		FirstPrevOut: wire.OutPoint{
			Hash:  hashBytes1,
			Index: 1,
		},
		Tag:         "asset",
		MetaHash:    [MetaHashLen]byte{1, 2, 3},
		OutputIndex: 1,
		Type:        1,
	}

	split := &Asset{
		Version:          1,
		Genesis:          splitGen,
		Amount:           1,
		LockTime:         1337,
		RelativeLockTime: 6,
		PrevWitnesses: []Witness{{
			PrevID: &PrevID{
				OutPoint: wire.OutPoint{
					Hash:  hashBytes1,
					Index: 1,
				},
				ID:        hashBytes1,
				ScriptKey: ToSerialized(pubKey),
			},
			TxWitness:       nil,
			SplitCommitment: nil,
		}},
		SplitCommitmentRoot: nil,
		ScriptVersion:       1,
		ScriptKey:           NewScriptKey(pubKey),
		GroupKey: &GroupKey{
			GroupPubKey: *pubKey,
		},
	}

	root := &Asset{
		Version:          1,
		Genesis:          splitGen,
		Amount:           1,
		LockTime:         1337,
		RelativeLockTime: 6,
		PrevWitnesses: []Witness{{
			PrevID: &PrevID{
				OutPoint: wire.OutPoint{
					Hash:  hashBytes2,
					Index: 2,
				},
				ID:        hashBytes2,
				ScriptKey: ToSerialized(pubKey),
			},
			TxWitness:       wire.TxWitness{{2}, {2}},
			SplitCommitment: nil,
		}},
		SplitCommitmentRoot: mssmt.NewComputedNode(hashBytes1, 1337),
		ScriptVersion:       1,
		ScriptKey:           NewScriptKey(pubKey),
		GroupKey: &GroupKey{
			GroupPubKey: *pubKey,
		},
	}
	split.PrevWitnesses[0].SplitCommitment = &SplitCommitment{
		Proof:     *mssmt.RandProof(t),
		RootAsset: *root,
	}
	assertAssetEncoding("random split asset with root asset", split)

	newGen := Genesis{
		FirstPrevOut: wire.OutPoint{
			Hash:  hashBytes2,
			Index: 2,
		},
		Tag:         "asset",
		MetaHash:    [MetaHashLen]byte{1, 2, 3},
		OutputIndex: 2,
		Type:        2,
	}

	comment := "random asset with multiple previous witnesses"
	assertAssetEncoding(comment, &Asset{
		Version:          2,
		Genesis:          newGen,
		Amount:           2,
		LockTime:         1337,
		RelativeLockTime: 6,
		PrevWitnesses: []Witness{{
			PrevID:          nil,
			TxWitness:       nil,
			SplitCommitment: nil,
		}, {
			PrevID:          &PrevID{},
			TxWitness:       nil,
			SplitCommitment: nil,
		}, {
			PrevID: &PrevID{
				OutPoint: wire.OutPoint{
					Hash:  hashBytes2,
					Index: 2,
				},
				ID:        hashBytes2,
				ScriptKey: ToSerialized(pubKey),
			},
			TxWitness:       wire.TxWitness{{2}, {2}},
			SplitCommitment: nil,
		}},
		SplitCommitmentRoot: nil,
		ScriptVersion:       2,
		ScriptKey:           NewScriptKey(pubKey),
		GroupKey:            nil,
	})

	assertAssetEncoding("minimal asset", &Asset{
		Genesis: Genesis{
			MetaHash: [MetaHashLen]byte{},
		},
		ScriptKey: NewScriptKey(pubKey),
	})

	// Write test vectors to file. This is a no-op if the "gen_test_vectors"
	// build tag is not set.
	test.WriteTestVectors(t, generatedTestVectorName, testVectors)
}

// TestAssetType asserts that the number of issued assets is set according to
// the genesis type when creating a new asset.
func TestAssetType(t *testing.T) {
	t.Parallel()

	normalGen := Genesis{
		FirstPrevOut: wire.OutPoint{
			Hash:  hashBytes1,
			Index: 1,
		},
		Tag:         "normal asset",
		MetaHash:    [MetaHashLen]byte{1, 2, 3},
		OutputIndex: 1,
		Type:        Normal,
	}
	collectibleGen := Genesis{
		FirstPrevOut: wire.OutPoint{
			Hash:  hashBytes1,
			Index: 1,
		},
		Tag:         "collectible asset",
		MetaHash:    [MetaHashLen]byte{1, 2, 3},
		OutputIndex: 2,
		Type:        Collectible,
	}
	scriptKey := NewScriptKey(pubKey)

	normal, err := New(normalGen, 741, 0, 0, scriptKey, nil)
	require.NoError(t, err)
	require.EqualValues(t, 741, normal.Amount)

	_, err = New(collectibleGen, 741, 0, 0, scriptKey, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "amount must be 1 for asset")

	collectible, err := New(collectibleGen, 1, 0, 0, scriptKey, nil)
	require.NoError(t, err)
	require.EqualValues(t, 1, collectible.Amount)
}

// TestAssetID makes sure that the asset ID is derived correctly.
func TestAssetID(t *testing.T) {
	t.Parallel()

	g := Genesis{
		FirstPrevOut: wire.OutPoint{
			Hash:  hashBytes1,
			Index: 99,
		},
		Tag:         "collectible asset 1",
		MetaHash:    [MetaHashLen]byte{1, 2, 3},
		OutputIndex: 21,
		Type:        Collectible,
	}
	tagHash := sha256.Sum256([]byte(g.Tag))

	h := sha256.New()
	_ = wire.WriteOutPoint(h, 0, 0, &g.FirstPrevOut)
	_, _ = h.Write(tagHash[:])
	_, _ = h.Write(g.MetaHash[:])
	_, _ = h.Write([]byte{0, 0, 0, 21, 1})
	result := h.Sum(nil)

	id := g.ID()
	require.Equal(t, result, id[:])

	// Make sure we get a different asset ID even if everything is the same
	// except for the type.
	normalWithDifferentType := Genesis{
		FirstPrevOut: wire.OutPoint{
			Hash:  hashBytes1,
			Index: 99,
		},
		Tag:         "collectible asset 1",
		MetaHash:    [MetaHashLen]byte{1, 2, 3},
		OutputIndex: 21,
		Type:        Normal,
	}
	differentID := normalWithDifferentType.ID()
	require.NotEqual(t, id[:], differentID[:])
}

// TestAssetGroupKey tests that the asset key group is derived correctly.
func TestAssetGroupKey(t *testing.T) {
	t.Parallel()

	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	privKeyCopy := btcec.PrivKeyFromScalar(&privKey.Key)
	genSigner := NewRawKeyGenesisSigner(privKeyCopy)
	fakeKeyDesc := keychain.KeyDescriptor{
		PubKey: privKeyCopy.PubKey(),
	}

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

	var groupBytes bytes.Buffer
	_ = wire.WriteOutPoint(&groupBytes, 0, 0, &g.FirstPrevOut)
	_, _ = groupBytes.Write([]byte{0, 0, 0, 21, 1})

	tweakedKey := txscript.TweakTaprootPrivKey(*privKey, groupBytes.Bytes())

	// TweakTaprootPrivKey modifies the private key that is passed in! We
	// need to provide a copy to arrive at the same result.
	keyGroup, err := DeriveGroupKey(genSigner, fakeKeyDesc, g, nil)
	require.NoError(t, err)

	require.Equal(
		t, schnorr.SerializePubKey(tweakedKey.PubKey()),
		schnorr.SerializePubKey(&keyGroup.GroupPubKey),
	)
}

// TestAssetWitness tests that the asset group witness can be serialized and
// parsed correctly, and that signature detection works correctly.
func TestAssetWitnesses(t *testing.T) {
	t.Parallel()

	nonSigWitness := test.RandTxWitnesses(t)
	for len(nonSigWitness) == 0 {
		nonSigWitness = test.RandTxWitnesses(t)
	}

	// A witness must be unmodified after serialization and parsing.
	nonSigWitnessBytes, err := SerializeGroupWitness(nonSigWitness)
	require.NoError(t, err)

	nonSigWitnessParsed, err := ParseGroupWitness(nonSigWitnessBytes)
	require.NoError(t, err)
	require.Equal(t, nonSigWitness, nonSigWitnessParsed)

	// A witness that is a single Schnorr signature must be detected
	// correctly both before and after serialization.
	sigWitnessParsed, isSig := IsGroupSig(sigWitness)
	require.True(t, isSig)
	require.NotNil(t, sigWitnessParsed)

	sigWitnessBytes, err := SerializeGroupWitness(sigWitness)
	require.NoError(t, err)

	sigWitnessParsed, err = ParseGroupSig(sigWitnessBytes)
	require.NoError(t, err)
	require.Equal(t, sig.Serialize(), sigWitnessParsed.Serialize())

	// Adding an annex to the witness stack should not affect signature
	// parsing.
	dummyAnnex := []byte{0x50, 0xde, 0xad, 0xbe, 0xef}
	sigWithAnnex := wire.TxWitness{sigWitness[0], dummyAnnex}
	sigWitnessParsed, isSig = IsGroupSig(sigWithAnnex)
	require.True(t, isSig)
	require.NotNil(t, sigWitnessParsed)

	// Witness that are not a single Schnorr signature must also be
	// detected correctly.
	possibleSig, isSig := IsGroupSig(nonSigWitness)
	require.False(t, isSig)
	require.Nil(t, possibleSig)

	possibleSig, err = ParseGroupSig(nonSigWitnessBytes)
	require.Error(t, err)
	require.Nil(t, possibleSig)
}

// TestUnknownVersion tests that an asset of an unknown version is rejected
// before being inserted into an MS-SMT.
func TestUnknownVersion(t *testing.T) {
	t.Parallel()

	rootGen := Genesis{
		FirstPrevOut: wire.OutPoint{
			Hash:  hashBytes1,
			Index: 1,
		},
		Tag:         "asset",
		MetaHash:    [MetaHashLen]byte{1, 2, 3},
		OutputIndex: 1,
		Type:        1,
	}

	root := &Asset{
		Version:          212,
		Genesis:          rootGen,
		Amount:           1,
		LockTime:         1337,
		RelativeLockTime: 6,
		PrevWitnesses: []Witness{{
			PrevID: &PrevID{
				OutPoint: wire.OutPoint{
					Hash:  hashBytes2,
					Index: 2,
				},
				ID:        hashBytes2,
				ScriptKey: ToSerialized(pubKey),
			},
			TxWitness:       wire.TxWitness{{2}, {2}},
			SplitCommitment: nil,
		}},
		SplitCommitmentRoot: mssmt.NewComputedNode(hashBytes1, 1337),
		ScriptVersion:       1,
		ScriptKey:           NewScriptKey(pubKey),
		GroupKey: &GroupKey{
			GroupPubKey: *pubKey,
			Witness:     sigWitness,
		},
	}

	rootLeaf, err := root.Leaf()
	require.Nil(t, rootLeaf)
	require.ErrorIs(t, err, ErrUnknownVersion)

	root.Version = V0
	rootLeaf, err = root.Leaf()
	require.NotNil(t, rootLeaf)
	require.Nil(t, err)
}

func FuzzAssetDecode(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		r := bytes.NewReader(data)
		a := &Asset{}
		if err := a.Decode(r); err != nil {
			return
		}
	})
}

// TestDecodeHex tests the decoding of a virtual packet from a hex string.
func TestDecodeHex(t *testing.T) {
	t.Parallel()

	// The test data file just contains a random asset from a previous
	// integration test run.
	fileContent, err := os.ReadFile(filepath.Join("testdata", "asset.hex"))
	require.NoError(t, err)
	rawBytes, err := hex.DecodeString(string(fileContent))
	require.NoError(t, err)

	a := &Asset{}
	err = a.Decode(bytes.NewReader(rawBytes))
	require.NoError(t, err)
}

// TestBIPTestVectors tests that the BIP test vectors are passing.
func TestBIPTestVectors(t *testing.T) {
	t.Parallel()

	for idx := range allTestVectorFiles {
		var (
			fileName    = allTestVectorFiles[idx]
			testVectors = &TestVectors{}
		)
		test.ParseTestVectors(t, fileName, &testVectors)
		t.Run(fileName, func(tt *testing.T) {
			tt.Parallel()

			runBIPTestVector(tt, testVectors)
		})
	}
}

// runBIPTestVector runs the tests in a single BIP test vector file.
func runBIPTestVector(t *testing.T, testVectors *TestVectors) {
	for _, validCase := range testVectors.ValidTestCases {
		validCase := validCase

		t.Run(validCase.Comment, func(tt *testing.T) {
			tt.Parallel()

			a := validCase.Asset.ToAsset(tt)

			var buf bytes.Buffer
			err := a.Encode(&buf)
			require.NoError(tt, err)

			areEqual := validCase.Expected == hex.EncodeToString(
				buf.Bytes(),
			)

			// Create nice diff if things don't match.
			if !areEqual {
				expectedBytes, err := hex.DecodeString(
					validCase.Expected,
				)
				require.NoError(tt, err)

				expectedAsset := &Asset{}
				err = expectedAsset.Decode(bytes.NewReader(
					expectedBytes,
				))
				require.NoError(tt, err)

				require.Equal(tt, a, expectedAsset)

				// Make sure we still fail the test.
				require.Equal(
					tt, validCase.Expected,
					hex.EncodeToString(buf.Bytes()),
				)
			}

			// We also want to make sure that the asset is decoded
			// correctly from the encoded TLV stream.
			decoded := &Asset{}
			err = decoded.Decode(&buf)
			require.NoError(tt, err)

			require.Equal(tt, a, decoded)
		})
	}

	for _, invalidCase := range testVectors.ErrorTestCases {
		invalidCase := invalidCase

		t.Run(invalidCase.Comment, func(tt *testing.T) {
			tt.Parallel()

			require.PanicsWithValue(t, invalidCase.Error, func() {
				invalidCase.Asset.ToAsset(tt)
			})
		})
	}
}
