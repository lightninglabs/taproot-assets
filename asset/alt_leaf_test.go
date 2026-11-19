package asset_test

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/asset/assetmock"
	"pgregory.net/rapid"
)

// TestAltLeafEncoding runs a property test for AltLeaf validation, encoding,
// and decoding.
func TestAltLeafEncoding(t *testing.T) {
	t.Run("alt leaf encode/decode", rapid.MakeCheck(testAltLeafEncoding))
}

// testAltLeafEncoding tests the AltLeaf validation logic, and that a valid
// AltLeaf can be encoded and decoded correctly.
func testAltLeafEncoding(t *rapid.T) {
	protoLeaf := assetmock.AltLeafGen(t).Draw(t, "alt_leaf")
	validAltLeafErr := protoLeaf.ValidateAltLeaf()

	// If validation passes, the asset must follow all alt leaf constraints.
	asserts := []asset.AssetAssert{
		asset.AssetVersionAssert(asset.V0),
		asset.AssetGenesisAssert(asset.EmptyGenesis),
		asset.AssetAmountAssert(0),
		asset.AssetLockTimeAssert(0),
		asset.AssetRelativeLockTimeAssert(0),
		asset.AssetHasSplitRootAssert(false),
		asset.AssetGroupKeyAssert(nil),
		asset.AssetHasScriptKeyAssert(true),
	}
	assertErr := asset.CheckAssetAsserts(&protoLeaf, asserts...)

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

	var decodedLeaf asset.Asset
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
