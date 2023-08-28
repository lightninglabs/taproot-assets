package itest

import (
	"github.com/lightninglabs/taproot-assets/taprpc"
	unirpc "github.com/lightninglabs/taproot-assets/taprpc/universerpc"
)

// TapdClient is the interface that is used to interact with a tapd instance.
type TapdClient interface {
	taprpc.TaprootAssetsClient
	unirpc.UniverseClient
}
