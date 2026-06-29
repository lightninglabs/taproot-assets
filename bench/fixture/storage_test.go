package fixture

import (
	"context"
	"testing"

	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/stretchr/testify/require"
)

// TestStorageFixture verifies the Storage fixture wires every subsystem the
// rpcserver consumes, by issuing one read-only RPC against each layer.
func TestStorageFixture(t *testing.T) {
	t.Parallel()

	f := NewStorage(t)
	ctx := context.Background()

	// AssetStore is reachable: ListAssets returns an empty page.
	la, err := f.Server.ListAssets(ctx, &taprpc.ListAssetRequest{})
	require.NoError(t, err)
	require.Empty(t, la.Assets)

	// TapAddrBook is reachable: QueryAddrs returns an empty page.
	qa, err := f.Server.QueryAddrs(ctx, &taprpc.QueryAddrRequest{})
	require.NoError(t, err)
	require.Empty(t, qa.Addrs)

	// DecodeAddr round-trips: encode a random regtest address and decode
	// it through the RPC. Verifies the AddrBook + TapAddrBook wiring.
	addr, _, _ := address.RandAddrWithVersion(
		t, &address.RegressionNetTap,
		address.RandProofCourierAddr(t), address.V1,
	)
	encoded, err := addr.Tap.EncodeAddress()
	require.NoError(t, err)

	decoded, err := f.Server.DecodeAddr(ctx, &taprpc.DecodeAddrRequest{
		Addr: encoded,
	})
	require.NoError(t, err)
	require.Equal(t, encoded, decoded.Encoded)
}
