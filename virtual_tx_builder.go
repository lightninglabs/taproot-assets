package taprootassets

import (
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/tapscript"
)

// GroupTxBuilder is an implementation of the asset.GenesisTxBuilder interface
// that constructs virtual transactions for grouped asset genesis.
type GroupTxBuilder struct{}

func (b *GroupTxBuilder) BuildGenesisTx(newAsset *asset.Asset) (*wire.MsgTx,
	*wire.TxOut, error) {

	txBuilder := tapscript.BaseGroupTxBuilder{}
	return txBuilder.BuildGenesisTx(newAsset)
}

// A compile time assertion to ensure that GroupTxBuilder meets the
// asset.GenesisTxBuilder interface.
var _ asset.GenesisTxBuilder = (*GroupTxBuilder)(nil)
