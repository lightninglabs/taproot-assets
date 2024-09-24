package priceoraclerpc

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
)

// IsAssetBtc is a helper function that returns true if the given asset
// specifier represents BTC, and false otherwise.
func IsAssetBtc(assetSpecifier *AssetSpecifier) bool {
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

// MarshalBigIntFixedPoint converts a BigIntFixedPoint to an RPC FixedPoint.
func MarshalBigIntFixedPoint(fp rfqmsg.BigIntFixedPoint) (*FixedPoint, error) {
	return &FixedPoint{
		Coefficient: fp.Coefficient.String(),
		Scale:       uint32(fp.Scale),
	}, nil
}

// UnmarshalFixedPoint converts an RPC FixedPoint to a BigIntFixedPoint.
func UnmarshalFixedPoint(fp *FixedPoint) (*rfqmsg.BigIntFixedPoint, error) {
	// Return an error is the scale component of the fixed point is greater
	// than the max value of uint8.
	if fp.Scale > 255 {
		return nil, fmt.Errorf("scale value overflow: %v", fp.Scale)
	}
	scale := uint8(fp.Scale)

	cBigInt := new(big.Int)
	cBigInt.SetString(fp.Coefficient, 10)

	return &rfqmsg.BigIntFixedPoint{
		Coefficient: rfqmath.NewBigInt(cBigInt),
		Scale:       scale,
	}, nil
}
