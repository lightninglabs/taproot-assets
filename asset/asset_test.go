package asset

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightningnetwork/lnd/tlv"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
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
	sig, _                    = schnorr.ParseSignature(sigBytes)
	sigWitness                = wire.TxWitness{sig.Serialize()}
	unsupportedTapLeafVersion = txscript.TapscriptLeafVersion(0xf0)
	testTapLeafScript         = []byte{99, 88, 77, 66, 55, 44}

	generatedTestVectorName = "asset_tlv_encoding_generated.json"

	allTestVectorFiles = []string{
		generatedTestVectorName,
		"asset_tlv_encoding_error_cases.json",
	}

	splitGen = Genesis{
		FirstPrevOut: wire.OutPoint{
			Hash:  hashBytes1,
			Index: 1,
		},
		Tag:         "asset",
		MetaHash:    [MetaHashLen]byte{1, 2, 3},
		OutputIndex: 1,
		Type:        1,
	}
	testSplitAsset = &Asset{
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
	testRootAsset = &Asset{
		Version:          1,
		Genesis:          testSplitAsset.Copy().Genesis,
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

	assetHexFileName = filepath.Join("testdata", "asset.hex")
)

// TestGenesisAssetClassification tests that the multiple forms of genesis asset
// are recognized correctly.
func TestGenesisAssetClassification(t *testing.T) {
	t.Parallel()

	baseGen := RandGenesis(t, Normal)
	baseScriptKey := RandScriptKey(t)
	baseAsset := RandAssetWithValues(t, baseGen, nil, baseScriptKey)
	assetValidGroup := RandAsset(t, Collectible)
	assetNeedsWitness := baseAsset.Copy()
	assetNeedsWitness.GroupKey = &GroupKey{
		GroupPubKey: *test.RandPubKey(t),
	}
	nonGenAsset := baseAsset.Copy()
	nonGenAsset.PrevWitnesses = []Witness{{
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
	groupMemberNonGen := nonGenAsset.Copy()
	groupMemberNonGen.GroupKey = &GroupKey{
		GroupPubKey: *test.RandPubKey(t),
	}
	splitAsset := nonGenAsset.Copy()
	splitAsset.PrevWitnesses[0].TxWitness = nil
	splitAsset.PrevWitnesses[0].SplitCommitment = &SplitCommitment{}

	tests := []struct {
		name                                string
		genAsset                            *Asset
		isGenesis, needsWitness, hasWitness bool
	}{
		{
			name:         "group anchor with witness",
			genAsset:     assetValidGroup,
			isGenesis:    false,
			needsWitness: false,
			hasWitness:   true,
		},
		{
			name:         "ungrouped genesis asset",
			genAsset:     baseAsset,
			isGenesis:    true,
			needsWitness: false,
			hasWitness:   false,
		},
		{
			name:         "group anchor without witness",
			genAsset:     assetNeedsWitness,
			isGenesis:    true,
			needsWitness: true,
			hasWitness:   false,
		},
		{
			name:         "non-genesis asset",
			genAsset:     nonGenAsset,
			isGenesis:    false,
			needsWitness: false,
			hasWitness:   false,
		},
		{
			name:         "non-genesis grouped asset",
			genAsset:     groupMemberNonGen,
			isGenesis:    false,
			needsWitness: false,
			hasWitness:   false,
		},
		{
			name:         "split asset",
			genAsset:     splitAsset,
			isGenesis:    false,
			needsWitness: false,
			hasWitness:   false,
		},
	}

	for _, testCase := range tests {
		testCase := testCase
		a := testCase.genAsset

		hasGenWitness := a.HasGenesisWitness()
		require.Equal(t, testCase.isGenesis, hasGenWitness)
		needsGroupWitness := a.NeedsGenesisWitnessForGroup()
		require.Equal(t, testCase.needsWitness, needsGroupWitness)
		hasGroupWitness := a.HasGenesisWitnessForGroup()
		require.Equal(t, testCase.hasWitness, hasGroupWitness)
	}
}

// TestValidateAssetName tests that asset names are validated correctly.
func TestValidateAssetName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		valid bool
	}{
		{
			// A name with spaces is valid.
			name:  "a name with spaces",
			valid: true,
		},
		{
			// Capital letters are valid.
			name:  "ABC",
			valid: true,
		},
		{
			// Numbers are valid.
			name:  "1234",
			valid: true,
		},
		{
			// A mix of lower/upper, spaces, and numbers is valid.
			name:  "Name 1234",
			valid: true,
		},
		{
			// Japanese characters are valid.
			name:  "日本語",
			valid: true,
		},
		{
			// The "place of interest" character takes up multiple
			// bytes and is valid.
			name:  "⌘",
			valid: true,
		},
		{
			// Exclusively whitespace is an invalid name.
			name:  "   ",
			valid: false,
		},
		{
			// An empty name string is invalid.
			name:  "",
			valid: false,
		},
		{
			// A 65 character name is too long and therefore
			// invalid.
			name: "asdasdasdasdasdasdasdasdasdasdasdasdasdasdas" +
				"dasdasdasdadasdasdada",
			valid: false,
		},
		{
			// Invalid if tab in name.
			name:  "tab\ttab",
			valid: false,
		},
		{
			// Invalid if newline in name.
			name:  "newline\nnewline",
			valid: false,
		},
	}

	for _, testCase := range tests {
		testCase := testCase

		err := ValidateAssetName(testCase.name)
		if testCase.valid {
			require.NoError(t, err)
		} else {
			require.Error(t, err)
		}
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
	root := testRootAsset.Copy()
	split := testSplitAsset.Copy()
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
		ScriptKey: NewScriptKey(pubKey),
	})

	assertAssetEncoding("minimal asset with unknown odd type", &Asset{
		Genesis: Genesis{
			MetaHash: [MetaHashLen]byte{},
		},
		ScriptKey: NewScriptKey(pubKey),
		UnknownOddTypes: tlv.TypeMap{
			test.TestVectorAllowedUnknownType: []byte(
				"the great unknown",
			),
		},
	})

	// Write test vectors to file. This is a no-op if the "gen_test_vectors"
	// build tag is not set.
	test.WriteTestVectors(t, generatedTestVectorName, testVectors)
}

// TestAltLeafEncoding runs a property test for AltLeaf validation, encoding,
// and decoding.
func TestAltLeafEncoding(t *testing.T) {
	t.Run("alt leaf encode/decode", rapid.MakeCheck(testAltLeafEncoding))
}

// testAltLeafEncoding tests the AltLeaf validation logic, and that a valid
// AltLeaf can be encoded and decoded correctly.
func testAltLeafEncoding(t *rapid.T) {
	protoLeaf := AltLeafGen(t).Draw(t, "alt_leaf")
	validAltLeafErr := protoLeaf.ValidateAltLeaf()

	// If validation passes, the asset must follow all alt leaf constraints.
	asserts := []AssetAssert{
		AssetVersionAssert(V0),
		AssetGenesisAssert(EmptyGenesis),
		AssetAmountAssert(0),
		AssetLockTimeAssert(0),
		AssetRelativeLockTimeAssert(0),
		AssetHasSplitRootAssert(false),
		AssetGroupKeyAssert(nil),
		AssetHasScriptKeyAssert(true),
	}
	assertErr := CheckAssetAsserts(&protoLeaf, asserts...)

	// If the validation method and these assertions behave differently,
	// either the test or the validation method is incorrect.
	switch {
	case validAltLeafErr == nil && assertErr != nil:
		t.Error(assertErr)

	case validAltLeafErr != nil && assertErr == nil:
		t.Error(validAltLeafErr)

	default:
	}

	// Don't test encoding for invalid alt leaves.
	if validAltLeafErr != nil {
		return
	}

	// If the alt leaf is valid, check that it can be encoded without error,
	// and decoded to an identical alt leaf.
	// fmt.Println("valid leaf")
	var buf bytes.Buffer
	if err := protoLeaf.EncodeAltLeaf(&buf); err != nil {
		t.Error(err)
	}

	var decodedLeaf Asset
	altLeafBytes := bytes.NewReader(buf.Bytes())
	if err := decodedLeaf.DecodeAltLeaf(altLeafBytes); err != nil {
		t.Error(err)
	}

	if !protoLeaf.DeepEqual(&decodedLeaf) {
		t.Errorf("decoded leaf %v does not match input %v", decodedLeaf,
			protoLeaf)
	}

	// Asset.DeepEqual does not inspect UnknownOddTypes, so check for their
	// equality separately.
	if !reflect.DeepEqual(
		protoLeaf.UnknownOddTypes, decodedLeaf.UnknownOddTypes,
	) {

		t.Errorf("decoded leaf unknown types %v does not match input "+
			"%v", decodedLeaf.UnknownOddTypes,
			protoLeaf.UnknownOddTypes)
	}
}

// TestTapLeafEncoding asserts that we can properly encode and decode tapLeafs
// through their TLV serialization, and that invalid tapLeafs are rejected.
func TestTapLeafEncoding(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		leaf  *txscript.TapLeaf
		valid bool
	}{
		{
			name:  "nil leaf",
			leaf:  nil,
			valid: false,
		},
		{
			name:  "empty script",
			leaf:  fn.Ptr(txscript.NewBaseTapLeaf([]byte{})),
			valid: false,
		},
		{
			name: "large leaf script",
			leaf: fn.Ptr(txscript.NewBaseTapLeaf(
				test.RandBytes(blockchain.MaxBlockWeight),
			)),
			valid: true,
		},
		{
			name: "random script with unknown version",
			leaf: fn.Ptr(txscript.NewTapLeaf(
				unsupportedTapLeafVersion, testTapLeafScript,
			)),
			valid: true,
		},
	}

	for _, testCase := range tests {
		tc := testCase

		t.Run(tc.name, func(t *testing.T) {
			leafBytes, err := EncodeTapLeaf(tc.leaf)
			if tc.valid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				return
			}

			leaf, err := DecodeTapLeaf(leafBytes)
			require.NoError(t, err)

			require.Equal(t, tc.leaf.LeafVersion, leaf.LeafVersion)
			require.Equal(t, tc.leaf.Script, leaf.Script)
		})
	}
}

// TestTapBranchEncoding asserts that we can properly encode and decode
// tapBranches, and that invalid slices of byte slices are rejected.
func TestTapBranchEncoding(t *testing.T) {
	tests := []struct {
		name       string
		branchData [][]byte
		valid      bool
	}{
		{
			name:       "empty branch",
			branchData: [][]byte{},
			valid:      false,
		},
		{
			name: "branch with invalid child",
			branchData: [][]byte{
				pubKeyBytes,
				hashBytes2[:],
			},
			valid: false,
		},
		{
			name: "valid branch",
			branchData: [][]byte{
				hashBytes1[:],
				hashBytes2[:],
			},
			valid: true,
		},
	}

	for _, testCase := range tests {
		tc := testCase

		t.Run(tc.name, func(t *testing.T) {
			branch, err := DecodeTapBranchNodes(tc.branchData)

			if tc.valid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				return
			}

			branchBytes := EncodeTapBranchNodes(*branch)
			require.Equal(t, tc.branchData, branchBytes)
		})
	}
}

// TestTapLeafSanity assserts that we reject tapLeafs that fail our sanity
// checks, and accept valid tapLeafs.
func TestTapLeafSanity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		leaf *txscript.TapLeaf
		sane bool
	}{
		{
			name: "nil leaf",
			leaf: nil,
			sane: false,
		},
		{
			name: "unsupported version",
			leaf: fn.Ptr(txscript.NewTapLeaf(
				unsupportedTapLeafVersion, testTapLeafScript,
			)),
			sane: false,
		},
		{
			name: "empty script",
			leaf: fn.Ptr(txscript.NewBaseTapLeaf([]byte{})),
			sane: false,
		},
		{
			name: "large leaf script",
			leaf: fn.Ptr(txscript.NewBaseTapLeaf(
				test.RandBytes(blockchain.MaxBlockWeight),
			)),
			sane: false,
		},
		{
			name: "valid tapleaf",
			leaf: fn.Ptr(
				txscript.NewBaseTapLeaf(testTapLeafScript),
			),
			sane: true,
		},
	}

	for _, testCase := range tests {
		tc := testCase

		t.Run(tc.name, func(t *testing.T) {
			err := CheckTapLeafSanity(tc.leaf)
			if tc.sane {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

// TestAssetIsBurn asserts that the IsBurn method is correct.
func TestAssetIsBurn(t *testing.T) {
	root := testRootAsset.Copy()
	split := testSplitAsset.Copy()
	split.PrevWitnesses[0].SplitCommitment = &SplitCommitment{
		Proof:     *mssmt.RandProof(t),
		RootAsset: *root,
	}

	require.False(t, root.IsBurn())
	require.False(t, split.IsBurn())

	// Update the script key to a burn script key for both of the assets.
	rootPrevID := root.PrevWitnesses[0].PrevID
	root.ScriptKey = NewScriptKey(DeriveBurnKey(*rootPrevID))
	split.ScriptKey = NewScriptKey(DeriveBurnKey(*rootPrevID))

	require.True(t, root.IsBurn())
	require.True(t, split.IsBurn())
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

// TestAssetWitnesses tests that the asset group witness can be serialized and
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

			// Make sure the asset in the test vectors doesn't use
			// a record type we haven't marked as known/supported
			// yet. If the following check fails, you need to update
			// the KnownAssetLeafTypes set.
			for _, record := range a.encodeRecords(EncodeNormal) {
				// Test vectors may contain this one type to
				// demonstrate that it is not rejected.
				if record.Type() ==
					test.TestVectorAllowedUnknownType {

					continue
				}

				require.Contains(
					tt, KnownAssetLeafTypes, record.Type(),
				)
			}

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

// TestAssetEncodingNoWitness tests that we can properly encode and decode an
// asset using the v1 version where the witness is not included.
func TestAssetEncodingNoWitness(t *testing.T) {
	t.Parallel()

	// First, start by copying the root asset re-used across tests.
	root := testRootAsset.Copy()

	// We'll make another copy that we'll use to modify the witness field.
	root2 := root.Copy()

	// We'll now modify the witness field of the second root.
	root2.PrevWitnesses[0].TxWitness[0][0] ^= 1

	// If we encode both of these assets then, then final encoding should
	// be identical as we use the EncodeNoWitness method.
	var b1, b2 bytes.Buffer
	require.NoError(t, root.EncodeNoWitness(&b1))
	require.NoError(t, root2.EncodeNoWitness(&b2))

	require.Equal(t, b1.Bytes(), b2.Bytes())

	// The leaf encoding for these two should also be identical.
	root1Leaf, err := root.Leaf()
	require.NoError(t, err)
	root2Leaf, err := root2.Leaf()
	require.NoError(t, err)

	require.Equal(t, root1Leaf.NodeHash(), root2Leaf.NodeHash())
}

// TestNewAssetWithCustomVersion tests that a custom version can be set for
// newly created assets.
func TestNewAssetWithCustomVersion(t *testing.T) {
	t.Parallel()

	// We'll use the root asset as a template, to re-use some of its static
	// data.
	rootAsset := testRootAsset.Copy()

	const newVersion = 10

	assetCustomVersion, err := New(
		rootAsset.Genesis, rootAsset.Amount, 0, 0, rootAsset.ScriptKey, nil,
		WithAssetVersion(newVersion),
	)
	require.NoError(t, err)

	require.Equal(t, int(assetCustomVersion.Version), newVersion)
}

// TestCopySpendTemplate tests that the spend template is copied correctly.
func TestCopySpendTemplate(t *testing.T) {
	newAsset := RandAsset(t, Normal)
	newAsset.SplitCommitmentRoot = mssmt.NewComputedNode(hashBytes1, 1337)
	newAsset.RelativeLockTime = 1
	newAsset.LockTime = 2

	// The template should have the relevant set of fields blanked.
	spendTemplate := newAsset.CopySpendTemplate()
	require.Zero(t, spendTemplate.SplitCommitmentRoot)
	require.Zero(t, spendTemplate.RelativeLockTime)
	require.Zero(t, spendTemplate.LockTime)

	// If blank these fields of the OG asset, then things should be
	// identical.
	newAsset.SplitCommitmentRoot = nil
	newAsset.RelativeLockTime = 0
	newAsset.LockTime = 0

	require.True(t, newAsset.DeepEqual(spendTemplate))
}

// TestExternalKeyPubKey tests that the public key can be derived from an
// external key.
func TestExternalKeyPubKey(t *testing.T) {
	t.Parallel()

	dummyXPub := func() hdkeychain.ExtendedKey {
		xpubStr := "xpub6BynCcnXLYNnnMUZARkHxbP9pG6h5rES8Zb8aHtGwmFX" +
			"9DdjJiyT9PNwkSMZfS3CvGRpvV21SkLRM6xhtshvA3DnJbQsvjD" +
			"yySWGArynQNf"
		xpub, err := hdkeychain.NewKeyFromString(xpubStr)
		require.NoError(t, err, "failed to create xpub from string")
		return *xpub
	}

	dummyXPubTestnet := func() hdkeychain.ExtendedKey {
		xpubStr := "tpubDDfTBtwwqxXuCej7pKYfbXeCW3inAtv1cw4knmvYTTHk" +
			"w3NoKaeCNH5XdY6n6fnBPc1gWEgeurfmBVzJLfBB1hGU64LsHFz" +
			"Jv4ASqaHyALH"
		xpub, err := hdkeychain.NewKeyFromString(xpubStr)
		require.NoError(t, err, "failed to create xpub from string")
		return *xpub
	}

	testCases := []struct {
		name           string
		externalKey    ExternalKey
		expectedPubKey string
		expectError    bool
		expectedError  string
	}{
		{
			name: "valid BIP-86 external key",
			externalKey: ExternalKey{
				XPub:              dummyXPub(),
				MasterFingerprint: 0x12345678,
				DerivationPath: []uint32{
					86 + hdkeychain.HardenedKeyStart,
					0 + hdkeychain.HardenedKeyStart,
					0 + hdkeychain.HardenedKeyStart, 0, 0,
				},
			},
			expectError: false,

			// The pubkey was generated with "chantools derivekey
			// --rootkey xpub... --path "m/0/0" --neuter" command.
			expectedPubKey: "02c0ca6c5d4dc4899de975f17f1023e424a" +
				"93a7ba6339cbaf514689f75d51787cc",
		},
		{
			name: "invalid derivation path length",
			externalKey: ExternalKey{
				XPub:              dummyXPub(),
				MasterFingerprint: 0x12345678,
				DerivationPath: []uint32{
					86 + hdkeychain.HardenedKeyStart,
					0 + hdkeychain.HardenedKeyStart,
					0 + hdkeychain.HardenedKeyStart,
				},
			},
			expectError: true,
			expectedError: "derivation path must have exactly 5 " +
				"components",
		},
		{
			name: "invalid BIP-86 derivation path",
			externalKey: ExternalKey{
				XPub:              dummyXPub(),
				MasterFingerprint: 0x12345678,
				DerivationPath: []uint32{
					44 + hdkeychain.HardenedKeyStart,
					0 + hdkeychain.HardenedKeyStart,
					0 + hdkeychain.HardenedKeyStart, 0, 0,
				},
			},
			expectError: true,
			expectedError: "xpub must be derived from BIP-0086 " +
				"(Taproot) derivation path",
		},
		{
			name: "valid BIP-86 external key, custom coin_type",
			externalKey: ExternalKey{
				XPub:              dummyXPub(),
				MasterFingerprint: 0x12345678,
				DerivationPath: []uint32{
					86 + hdkeychain.HardenedKeyStart,
					42 + hdkeychain.HardenedKeyStart,
					0 + hdkeychain.HardenedKeyStart, 0, 0,
				},
			},
			expectError: false,

			// The pubkey was generated with "chantools derivekey
			// --rootkey xpub... --path m/0/0 --neuter" command.
			expectedPubKey: "02c0ca6c5d4dc4899de975f17f1023e424a" +
				"93a7ba6339cbaf514689f75d51787cc",
		},
		{
			name: "valid BIP-86 external key, custom account",
			externalKey: ExternalKey{
				XPub:              dummyXPub(),
				MasterFingerprint: 0x12345678,
				DerivationPath: []uint32{
					86 + hdkeychain.HardenedKeyStart,
					0 + hdkeychain.HardenedKeyStart,
					42 + hdkeychain.HardenedKeyStart, 0, 0,
				},
			},
			expectError: false,

			// The pubkey was generated with "chantools derivekey
			// --rootkey xpub... --path m/0/0 --neuter" command.
			expectedPubKey: "02c0ca6c5d4dc4899de975f17f1023e424a" +
				"93a7ba6339cbaf514689f75d51787cc",
		},
		{
			name: "valid BIP-86 external key, change output",
			externalKey: ExternalKey{
				XPub:              dummyXPub(),
				MasterFingerprint: 0x12345678,
				DerivationPath: []uint32{
					86 + hdkeychain.HardenedKeyStart,
					0 + hdkeychain.HardenedKeyStart,
					0 + hdkeychain.HardenedKeyStart, 1, 0,
				},
			},
			expectError: false,

			// The pubkey was generated with "chantools derivekey
			// --rootkey xpub... --path m/1/0 --neuter" command.
			expectedPubKey: "02ce0e73519634aaf1a34cc17afb517a697" +
				"95c063386030f1b1b724410a84aa709",
		},
		{
			name: "valid BIP-86 external key, change=2",
			externalKey: ExternalKey{
				XPub:              dummyXPub(),
				MasterFingerprint: 0x12345678,
				DerivationPath: []uint32{
					86 + hdkeychain.HardenedKeyStart,
					0 + hdkeychain.HardenedKeyStart,
					0 + hdkeychain.HardenedKeyStart, 2, 0,
				},
			},
			expectError: false,

			// The pubkey was generated with "chantools derivekey
			// --rootkey xpub... --path m/2/0 --neuter" command.
			expectedPubKey: "0278b9669141d21f0598cc44a427c5d03a3" +
				"5d6aaed5555931a99a1659dfea4ebcf",
		},
		{
			name: "valid BIP-86 external key, index=2",
			externalKey: ExternalKey{
				XPub:              dummyXPub(),
				MasterFingerprint: 0x12345678,
				DerivationPath: []uint32{
					86 + hdkeychain.HardenedKeyStart,
					0 + hdkeychain.HardenedKeyStart,
					0 + hdkeychain.HardenedKeyStart, 0, 2,
				},
			},
			expectError: false,

			// The pubkey was generated with "chantools derivekey
			// --rootkey xpub... --path "m/0/2" --neuter" command.
			expectedPubKey: "0375e49d472c25d1138a5526b9b7a0198e1" +
				"d692cc3fd0133f260aca446e1244ff9",
		},
		{
			name: "valid BIP-86 external key, testnet",
			externalKey: ExternalKey{
				XPub:              dummyXPubTestnet(),
				MasterFingerprint: 0x12345678,
				DerivationPath: []uint32{
					86 + hdkeychain.HardenedKeyStart,
					1 + hdkeychain.HardenedKeyStart,
					0 + hdkeychain.HardenedKeyStart, 0, 0,
				},
			},
			expectError: false,

			// The pubkey was generated with "chantools derivekey
			// --testnet --rootkey xpub... --path "m/0/0" --neuter".
			expectedPubKey: "0280a3fcbeb7f770af6dd45cb0f4d02e104" +
				"4eafe0d8b05bcaec79dc0478c7fa0da",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(tt *testing.T) {
			pubKey, err := tc.externalKey.PubKey()

			if tc.expectError {
				require.Error(tt, err, tc.name)
				if tc.expectedError != "" {
					require.Contains(
						tt, err.Error(),
						tc.expectedError,
					)
				}

				return
			}

			require.NoError(tt, err)
			require.IsType(tt, btcec.PublicKey{}, pubKey)
			pubKeyHex := hex.EncodeToString(
				pubKey.SerializeCompressed(),
			)
			require.Equal(tt, tc.expectedPubKey, pubKeyHex)
		})
	}
}

// TestDecodeAsset tests that we can decode an asset from a hex file. This is
// mostly useful for debugging purposes.
func TestDecodeAsset(t *testing.T) {
	fileContent, err := os.ReadFile(assetHexFileName)
	require.NoError(t, err)

	assetBytes, err := hex.DecodeString(string(fileContent))
	require.NoError(t, err)

	var a Asset
	err = a.Decode(bytes.NewReader(assetBytes))
	require.NoError(t, err)

	ta := NewTestFromAsset(t, &a)
	assetJSON, err := json.MarshalIndent(ta, "", "\t")
	require.NoError(t, err)

	t.Logf("Decoded asset: %v", string(assetJSON))
}
