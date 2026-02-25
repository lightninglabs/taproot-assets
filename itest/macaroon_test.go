package itest

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"

	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightningnetwork/lnd/macaroons"
	"github.com/stretchr/testify/require"
	"gopkg.in/macaroon-bakery.v2/bakery/checkers"
	"gopkg.in/macaroon.v2"
)

// testBakeMacaroonPermissions ensures that baked macaroons only allow the
// specified permission set.
func testBakeMacaroonPermissions(t *harnessTest) {
	ctx := context.Background()

	t.t.Log("Verifying BakeMacaroon and GetInfo are denied without any " +
		"macaroon.")
	noMacConn, err := dialServer(
		t.tapd.rpcHost(), t.tapd.tlsCertPath, "",
	)
	require.NoError(t.t, err)
	defer noMacConn.Close()

	noMacClient := taprpc.NewTaprootAssetsClient(noMacConn)

	_, err = noMacClient.BakeMacaroon(ctx, &taprpc.BakeMacaroonRequest{
		Permissions: []*taprpc.MacaroonPermission{{
			Entity: "daemon",
			Action: "read",
		}},
	})
	require.Error(t.t, err)

	_, err = noMacClient.GetInfo(ctx, &taprpc.GetInfoRequest{})
	require.Error(t.t, err)

	t.t.Log("Baking a read-only macaroon with the admin client")
	resp, err := t.tapd.BakeMacaroon(ctx, &taprpc.BakeMacaroonRequest{
		Permissions: []*taprpc.MacaroonPermission{{
			Entity: "daemon",
			Action: "read",
		}},
	})
	require.NoError(t.t, err)

	macBytes, err := hex.DecodeString(resp.Macaroon)
	require.NoError(t.t, err)

	macPath := filepath.Join(t.tapd.cfg.BaseDir, "readonly.macaroon")
	err = os.WriteFile(macPath, macBytes, 0600)
	require.NoError(t.t, err)

	t.t.Log("Connecting with the read-only macaroon")
	conn, err := dialServer(
		t.tapd.rpcHost(), t.tapd.tlsCertPath, macPath,
	)
	require.NoError(t.t, err)
	defer conn.Close()

	readClient := taprpc.NewTaprootAssetsClient(conn)

	t.t.Log("Ensuring BakeMacaroon is denied with read-only permissions")
	_, err = readClient.BakeMacaroon(ctx, &taprpc.BakeMacaroonRequest{
		Permissions: []*taprpc.MacaroonPermission{{
			Entity: "daemon",
			Action: "read",
		}},
	})
	require.Error(t.t, err)
	require.Contains(t.t, err.Error(), "permission denied")

	t.t.Log("Confirming read-only access allows GetInfo but denies NewAddr")
	_, err = readClient.GetInfo(ctx, &taprpc.GetInfoRequest{})
	require.NoError(t.t, err)

	_, err = readClient.NewAddr(ctx, &taprpc.NewAddrRequest{})
	require.Error(t.t, err)
	require.Contains(t.t, err.Error(), "permission denied")

	t.t.Log("Baking a daemon write macaroon with the admin client")
	writeResp, err := t.tapd.BakeMacaroon(ctx, &taprpc.BakeMacaroonRequest{
		Permissions: []*taprpc.MacaroonPermission{{
			Entity: "daemon",
			Action: "write",
		}},
	})
	require.NoError(t.t, err)

	writeMacBytes, err := hex.DecodeString(writeResp.Macaroon)
	require.NoError(t.t, err)

	writeMacPath := filepath.Join(
		t.tapd.cfg.BaseDir, "daemon-write.macaroon",
	)
	err = os.WriteFile(writeMacPath, writeMacBytes, 0600)
	require.NoError(t.t, err)

	t.t.Log("Connecting with the daemon write macaroon")
	writeConn, err := dialServer(
		t.tapd.rpcHost(), t.tapd.tlsCertPath,
		writeMacPath,
	)
	require.NoError(t.t, err)
	defer writeConn.Close()

	writeClient := taprpc.NewTaprootAssetsClient(writeConn)

	t.t.Log("Confirming write permissions allow DebugLevel")
	_, err = writeClient.DebugLevel(ctx, &taprpc.DebugLevelRequest{
		Show: true,
	})
	require.NoError(t.t, err)

	t.t.Log("Baking a macaroon via tapcli with offline caveats")
	cliRespGeneric, err := ExecTapCLI(
		ctx, t.tapd, "bakemacaroon", "--timeout=60",
		"--ip_address=127.0.0.1",
		"--custom_caveat_name=itest-caveat",
		"--custom_caveat_condition=itest-condition",
		"daemon:read",
	)
	require.NoError(t.t, err)

	cliResp := cliRespGeneric.(*taprpc.BakeMacaroonResponse)
	cliMacBytes, err := hex.DecodeString(cliResp.Macaroon)
	require.NoError(t.t, err)

	cliMac := &macaroon.Macaroon{}
	require.NoError(t.t, cliMac.UnmarshalBinary(cliMacBytes))

	require.True(t.t, macaroons.HasCustomCaveat(cliMac, "itest-caveat"))
	require.Equal(
		t.t, "itest-condition",
		macaroons.GetCustomCaveatCondition(cliMac, "itest-caveat"),
	)

	var hasTimeout, hasIPLock bool
	for _, caveat := range cliMac.Caveats() {
		cond := string(caveat.Id)
		if strings.HasPrefix(cond, checkers.CondTimeBefore+" ") {
			hasTimeout = true
		}
		if cond == "ipaddr 127.0.0.1" {
			hasIPLock = true
		}
	}
	require.True(t.t, hasTimeout)
	require.True(t.t, hasIPLock)
}
