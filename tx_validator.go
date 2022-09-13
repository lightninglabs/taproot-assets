package taro

import (
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/commitment"
	"github.com/lightninglabs/taro/taroscript"
	"github.com/lightninglabs/taro/vm"
)

// ValidatorV0 is an implementation of the taroscript.TxValidator interface
// that supports Taro script version 0.
type ValidatorV0 struct{}

// Execute creates and runs an instance of the Taro script V0 VM.
func (v *ValidatorV0) Execute(newAsset *asset.Asset,
	splitAsset *commitment.SplitAsset,
	prevAssets commitment.InputSet) error {

	engine, err := vm.New(newAsset, splitAsset, prevAssets)
	if err != nil {
		return err
	}

	if err = engine.Execute(); err != nil {
		return err
	}

	return nil
}

// A compile time assertion to ensure ValidatorV0 meets the
// taroscript.TxValidator interface.
var _ taroscript.TxValidator = (*ValidatorV0)(nil)
