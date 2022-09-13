package taroscript

import (
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/commitment"
)

// TxValidator is the interface used to validate an asset transfer
// with the Taro VM.
type TxValidator interface {
	// Execute creates an instance of the Taro VM and validates
	// an asset transfer, including the attached witnesses.
	Execute(newAsset *asset.Asset, splitAsset *commitment.SplitAsset,
		prevAssets commitment.InputSet) error
}
