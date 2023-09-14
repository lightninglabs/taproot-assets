package tapscript

import (
	"fmt"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
)

// MockGroupTxBuilder is an implementation of the asset.GenesisTxBuilder
// interface that constructs virtual transactions for grouped asset genesis.
type BaseGroupTxBuilder struct{}

func BuildGenesisTx(newAsset *asset.Asset) (*wire.MsgTx,
	*wire.TxOut, error) {

	// First, we check that the passed asset is a genesis grouped asset
	// that has no group witness.
	if !newAsset.NeedsGenesisWitnessForGroup() {
		return nil, nil, fmt.Errorf("asset is not a genesis grouped" +
			"asset")
	}

	prevOut, err := asset.InputGenesisAssetPrevOut(*newAsset)
	if err != nil {
		return nil, nil, err
	}

	// Now, create the virtual transaction that represents this asset
	// minting.
	virtualTx, _, err := VirtualTx(newAsset, nil)
	if err != nil {
		return nil, nil, err
	}
	populatedVirtualTx := VirtualTxWithInput(
		virtualTx, newAsset, 0, nil,
	)

	return populatedVirtualTx, prevOut, nil
}

func (m *BaseGroupTxBuilder) BuildGenesisTx(newAsset *asset.Asset) (*wire.MsgTx,
	*wire.TxOut, error) {

	return BuildGenesisTx(newAsset)
}

// A compile time assertion to ensure that GroupTxBuilder meets the
// asset.GenesisTxBuilder interface.
var _ asset.GenesisTxBuilder = (*BaseGroupTxBuilder)(nil)
