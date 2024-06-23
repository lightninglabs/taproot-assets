package tappsbt

import (
	"bytes"
	"encoding/hex"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	assetmock "github.com/lightninglabs/taproot-assets/internal/mock/asset"
	proofmock "github.com/lightninglabs/taproot-assets/internal/mock/proof"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/json"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

const (
	// testDataFileName is the name of the directory with the test data.
	testDataFileName = "testdata"
)

var (
	testParams = &address.MainNetTap

	// Block 100002 with 9 transactions on bitcoin mainnet.
	oddTxBlockHexFileName = filepath.Join(
		testDataFileName, "odd-block.hex",
	)
)

// RandPacket generates a random virtual packet for testing purposes.
func RandPacket(t testing.TB, setVersion bool) *tappsbt.VPacket {
	testPubKey := test.RandPubKey(t)
	op := test.RandOp(t)
	keyDesc := keychain.KeyDescriptor{
		PubKey: testPubKey,
		KeyLocator: keychain.KeyLocator{
			Family: 123,
			Index:  456,
		},
	}
	inputScriptKey := asset.ScriptKey{
		TweakedScriptKey: &asset.TweakedScriptKey{
			RawKey: keyDesc,
			Tweak:  []byte("merkle root"),
		},
	}
	inputScriptKey.PubKey = txscript.ComputeTaprootOutputKey(
		keyDesc.PubKey, inputScriptKey.Tweak,
	)

	bip32Derivation, trBip32Derivation := tappsbt.Bip32DerivationFromKeyDesc(
		keyDesc, testParams.HDCoinType,
	)
	bip32Derivations := []*psbt.Bip32Derivation{bip32Derivation}
	trBip32Derivations := []*psbt.TaprootBip32Derivation{trBip32Derivation}
	testAsset := assetmock.RandAsset(t, asset.Normal)
	testAsset.ScriptKey = inputScriptKey

	testOutputAsset := assetmock.RandAsset(t, asset.Normal)
	testOutputAsset.ScriptKey = asset.NewScriptKeyBip86(keyDesc)

	// The raw key won't be serialized within the asset, so let's blank it
	// out here to get a fully, byte-by-byte comparable PSBT.
	testAsset.GroupKey.RawKey = keychain.KeyDescriptor{}
	testAsset.GroupKey.Witness = nil
	testOutputAsset.GroupKey.RawKey = keychain.KeyDescriptor{}
	testOutputAsset.GroupKey.Witness = nil
	testOutputAsset.ScriptKey.TweakedScriptKey = nil
	leaf1 := txscript.TapLeaf{
		LeafVersion: txscript.BaseLeafVersion,
		Script:      []byte("not a valid script"),
	}
	testPreimage1, err := commitment.NewPreimageFromLeaf(leaf1)
	require.NoError(t, err)
	testPreimage2 := commitment.NewPreimageFromBranch(
		txscript.NewTapBranch(leaf1, leaf1),
	)

	oddTxBlockHex, err := os.ReadFile(oddTxBlockHexFileName)
	require.NoError(t, err)

	oddTxBlockBytes, err := hex.DecodeString(
		strings.Trim(string(oddTxBlockHex), "\n"),
	)
	require.NoError(t, err)

	var oddTxBlock wire.MsgBlock
	err = oddTxBlock.Deserialize(bytes.NewReader(oddTxBlockBytes))
	require.NoError(t, err)

	inputProof := proofmock.RandProof(
		t, testAsset.Genesis, inputScriptKey.PubKey, oddTxBlock, 1, 0,
	)

	courierAddress, err := url.Parse("https://example.com")
	require.NoError(t, err)

	vPacket := &tappsbt.VPacket{
		Inputs: []*tappsbt.VInput{{
			PrevID: asset.PrevID{
				OutPoint:  op,
				ID:        assetmock.RandID(t),
				ScriptKey: assetmock.RandSerializedKey(t),
			},
			Anchor: tappsbt.Anchor{
				Value:             777,
				PkScript:          []byte("anchor pkscript"),
				SigHashType:       txscript.SigHashSingle,
				InternalKey:       testPubKey,
				MerkleRoot:        []byte("merkle root"),
				TapscriptSibling:  []byte("sibling"),
				Bip32Derivation:   bip32Derivations,
				TrBip32Derivation: trBip32Derivations,
			},
			Proof: &inputProof,
		}, {
			// Empty input.
		}},
		Outputs: []*tappsbt.VOutput{{
			Amount: 123,
			AssetVersion: asset.Version(
				test.RandIntn(2),
			),
			Type:                               tappsbt.TypeSplitRoot,
			Interactive:                        true,
			AnchorOutputIndex:                  0,
			AnchorOutputInternalKey:            testPubKey,
			AnchorOutputBip32Derivation:        bip32Derivations,
			AnchorOutputTaprootBip32Derivation: trBip32Derivations,
			Asset:                              testOutputAsset,
			ScriptKey:                          testOutputAsset.ScriptKey,
			SplitAsset:                         testOutputAsset,
			AnchorOutputTapscriptSibling:       testPreimage1,
			ProofDeliveryAddress:               courierAddress,
			ProofSuffix:                        &inputProof,
			RelativeLockTime:                   345,
			LockTime:                           456,
		}, {
			Amount: 345,
			AssetVersion: asset.Version(
				test.RandIntn(2),
			),
			Type:                               tappsbt.TypeSplitRoot,
			Interactive:                        false,
			AnchorOutputIndex:                  1,
			AnchorOutputInternalKey:            testPubKey,
			AnchorOutputBip32Derivation:        bip32Derivations,
			AnchorOutputTaprootBip32Derivation: trBip32Derivations,
			Asset:                              testOutputAsset,
			ScriptKey:                          testOutputAsset.ScriptKey,
			AnchorOutputTapscriptSibling:       &testPreimage2,
		}},
		ChainParams: testParams,
	}
	vPacket.SetInputAsset(0, testAsset)

	if setVersion {
		vPacket.Version = test.RandFlip(tappsbt.V0, tappsbt.V1)
	}

	return vPacket
}

type ValidTestCase struct {
	Packet   *json.VPacket `json:"packet"`
	Expected string        `json:"expected"`
	Comment  string        `json:"comment"`
}

type ErrorTestCase struct {
	Packet  *json.VPacket `json:"packet"`
	Error   string        `json:"error"`
	Comment string        `json:"comment"`
}

type TestVectors struct {
	ValidTestCases []*ValidTestCase `json:"valid_test_cases"`
	ErrorTestCases []*ErrorTestCase `json:"error_test_cases"`
}
