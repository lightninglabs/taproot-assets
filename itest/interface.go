package itest

import (
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/assetwalletrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/rfqrpc"
	unirpc "github.com/lightninglabs/taproot-assets/taprpc/universerpc"
)

// TapdClient is the interface that is used to interact with a tapd instance.
type TapdClient interface {
	taprpc.TaprootAssetsClient
	unirpc.UniverseClient
	mintrpc.MintClient
	rfqrpc.RfqClient
	assetwalletrpc.AssetWalletClient
}
