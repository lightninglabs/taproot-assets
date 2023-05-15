package taprootassets

import (
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/tapscript"
	"github.com/lightninglabs/taproot-assets/vm"
)

// ValidatorV0 is an implementation of the tapscript.TxValidator interface
// that supports Taro script version 0.
type ValidatorV0 struct{}

// Execute creates and runs an instance of the Taro script V0 VM.
func (v *ValidatorV0) Execute(newAsset *asset.Asset,
	splitAssets []*commitment.SplitAsset,
	prevAssets commitment.InputSet) error {

	engine, err := vm.New(newAsset, splitAssets, prevAssets)
	if err != nil {
		return err
	}

	if err = engine.Execute(); err != nil {
		return err
	}

	return nil
}

// A compile time assertion to ensure ValidatorV0 meets the
// tapscript.TxValidator interface.
var _ tapscript.TxValidator = (*ValidatorV0)(nil)
