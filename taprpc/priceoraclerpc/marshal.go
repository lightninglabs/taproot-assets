package priceoraclerpc

import (
	"bytes"
	"encoding/hex"

	"github.com/lightninglabs/taproot-assets/taprpc/rfqrpc"
)

// IsAssetBtc is a helper function that returns true if the given asset
// specifier represents BTC, and false otherwise.
func IsAssetBtc(assetSpecifier *rfqrpc.AssetSpecifier) bool {
	// An unset asset specifier does not represent BTC.
	if assetSpecifier == nil {
		return false
	}

	// Verify that the asset specifier has a valid asset ID (either bytes or
	// string). The asset ID must be all zeros for the asset specifier to
	// represent BTC.
	assetIdBytes := assetSpecifier.GetAssetId()
	assetIdStr := assetSpecifier.GetAssetIdStr()

	if len(assetIdBytes) != 32 && assetIdStr == "" {
		return false
	}

	var assetId [32]byte
	copy(assetId[:], assetIdBytes)

	var zeroAssetId [32]byte
	zeroAssetHexStr := hex.EncodeToString(zeroAssetId[:])

	isAssetIdZero := bytes.Equal(assetId[:], zeroAssetId[:]) ||
		assetIdStr == zeroAssetHexStr

	// Ensure that the asset specifier does not have any group key related
	// fields set. When specifying BTC, the group key fields must be unset.
	groupKeySet := assetSpecifier.GetGroupKey() != nil ||
		assetSpecifier.GetGroupKeyStr() != ""

	return isAssetIdZero && !groupKeySet
}
