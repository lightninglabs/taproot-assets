package itest

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/lightninglabs/taproot-assets/taprpc"
	wrpc "github.com/lightninglabs/taproot-assets/taprpc/assetwalletrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/authmailboxrpc"
	mintrpc "github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	rfqrpc "github.com/lightninglabs/taproot-assets/taprpc/rfqrpc"
	tchrpc "github.com/lightninglabs/taproot-assets/taprpc/tapchannelrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/tapdevrpc"
	unirpc "github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/invoicesrpc"
	"github.com/lightningnetwork/lnd/lnrpc/routerrpc"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"github.com/lightningnetwork/lnd/lntest/port"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// IntegratedNodeConfig holds the configuration for an integrated lnd+tapd
// node.
type IntegratedNodeConfig struct {
	// Name is the human-readable name for this node (e.g. "Alice").
	Name string

	// BinaryPath is the path to the tapd-integrated binary.
	BinaryPath string

	// BaseDir is the temp directory for this node's data.
	BaseDir string

	// RPCPort is the lnd gRPC port (also serves tapd services).
	RPCPort int

	// P2PPort is the lnd peer-to-peer port.
	P2PPort int

	// NetParams is the chain parameters to use.
	NetParams *chaincfg.Params

	// ExtraLndArgs are additional args passed under the --lnd.* namespace.
	ExtraLndArgs []string

	// ExtraTapdArgs are additional args under --taproot-assets.*.
	ExtraTapdArgs []string
}

// IntegratedNode manages a running integrated lnd+tapd binary process and
// provides gRPC clients for both lnd and tapd RPCs.
type IntegratedNode struct {
	t   *testing.T
	Cfg *IntegratedNodeConfig

	// PubKey is the compressed public key of this node, populated after
	// Start().
	PubKey [33]byte

	// PubKeyStr is the hex-encoded public key string, populated after
	// Start().
	PubKeyStr string

	// cmd is the running integrated binary process.
	cmd *exec.Cmd

	// conn is the gRPC connection to the integrated binary.
	conn *grpc.ClientConn

	// LND RPC clients.
	lnrpc.LightningClient
	lnrpc.StateClient
	routerrpc.RouterClient
	invoicesrpc.InvoicesClient
	walletrpc.WalletKitClient

	// Tapd RPC clients.
	taprpc.TaprootAssetsClient
	wrpc.AssetWalletClient
	mintrpc.MintClient
	rfqrpc.RfqClient
	tchrpc.TaprootAssetChannelsClient
	unirpc.UniverseClient
	tapdevrpc.TapDevClient
	authmailboxrpc.MailboxClient
}

// NewIntegratedNode creates a new IntegratedNode with allocated ports and
// temp directories. The node is not started yet; call Start() to launch it.
func NewIntegratedNode(t *testing.T, name, binaryPath string,
	netParams *chaincfg.Params, extraLndArgs,
	extraTapdArgs []string) *IntegratedNode {

	t.Helper()

	baseDir := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.MkdirAll(baseDir, 0700))

	cfg := &IntegratedNodeConfig{
		Name:          name,
		BinaryPath:    binaryPath,
		BaseDir:       baseDir,
		RPCPort:       port.NextAvailablePort(),
		P2PPort:       port.NextAvailablePort(),
		NetParams:     netParams,
		ExtraLndArgs:  extraLndArgs,
		ExtraTapdArgs: extraTapdArgs,
	}

	return &IntegratedNode{
		t:   t,
		Cfg: cfg,
	}
}

// Start launches the integrated binary as an external process and waits for
// its gRPC server to become available.
func (n *IntegratedNode) Start() {
	n.t.Helper()

	lndDir := filepath.Join(n.Cfg.BaseDir, "lnd")
	tapdDir := filepath.Join(n.Cfg.BaseDir, "tapd")

	require.NoError(n.t, os.MkdirAll(lndDir, 0700))
	require.NoError(n.t, os.MkdirAll(tapdDir, 0700))

	args := []string{
		// LND args.
		fmt.Sprintf("--lnd.lnddir=%s", lndDir),
		fmt.Sprintf("--lnd.rpclisten=127.0.0.1:%d", n.Cfg.RPCPort),
		fmt.Sprintf("--lnd.listen=127.0.0.1:%d", n.Cfg.P2PPort),
		"--lnd.noseedbackup",
		"--lnd.no-macaroons",
		"--lnd.norest",
		"--lnd.debuglevel=debug",
		"--lnd.bitcoin.active",
		"--lnd.bitcoin.regtest",
		"--lnd.bitcoin.node=btcd",

		// Tapd args.
		fmt.Sprintf("--taproot-assets.tapddir=%s", tapdDir),
		"--taproot-assets.network=regtest",
	}

	// Add chain backend args if provided in extra args, otherwise the
	// caller is responsible for providing them.
	args = append(args, prefixArgs("--lnd.", n.Cfg.ExtraLndArgs)...)
	args = append(args, prefixArgs(
		"--taproot-assets.", n.Cfg.ExtraTapdArgs,
	)...)

	//nolint:gosec
	n.cmd = exec.Command(n.Cfg.BinaryPath, args...)
	n.cmd.Stdout = os.Stdout
	n.cmd.Stderr = os.Stderr

	n.t.Logf("Starting integrated node %s on port %d",
		n.Cfg.Name, n.Cfg.RPCPort)

	require.NoError(n.t, n.cmd.Start())

	// Wait for gRPC to become available.
	n.waitForGRPC()

	// Initialize all RPC clients.
	n.initClients()

	// Fetch the node's identity pubkey.
	n.fetchNodeInfo()

	n.t.Logf("Integrated node %s (%s) started successfully",
		n.Cfg.Name, n.PubKeyStr[:12])
}

// Stop sends SIGINT to the integrated binary and waits for it to exit.
func (n *IntegratedNode) Stop() {
	n.t.Helper()

	if n.conn != nil {
		_ = n.conn.Close()
		n.conn = nil
	}

	if n.cmd == nil || n.cmd.Process == nil {
		return
	}

	n.t.Logf("Stopping integrated node %s", n.Cfg.Name)

	// Send SIGINT for graceful shutdown.
	err := n.cmd.Process.Signal(syscall.SIGINT)
	if err != nil {
		n.t.Logf("Error sending SIGINT to %s: %v",
			n.Cfg.Name, err)

		return
	}

	// Wait with timeout.
	done := make(chan error, 1)
	go func() {
		done <- n.cmd.Wait()
	}()

	select {
	case err := <-done:
		if err != nil {
			n.t.Logf("Node %s exited with error: %v",
				n.Cfg.Name, err)
		}

	case <-time.After(30 * time.Second):
		n.t.Logf("Node %s did not stop in time, killing",
			n.Cfg.Name)
		_ = n.cmd.Process.Kill()
	}
}

// waitForGRPC polls the gRPC endpoint until it accepts TCP connections or a
// timeout is reached.
func (n *IntegratedNode) waitForGRPC() {
	n.t.Helper()

	addr := fmt.Sprintf("127.0.0.1:%d", n.Cfg.RPCPort)

	err := wait.NoError(func() error {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			return err
		}
		_ = conn.Close()

		return nil
	}, 30*time.Second)

	require.NoError(n.t, err, "gRPC server for %s did not become "+
		"available", n.Cfg.Name)
}

// initClients creates a gRPC connection and initializes all RPC clients.
// lnd's gRPC port always uses TLS, so we connect with InsecureSkipVerify
// since we don't need to verify the self-signed cert in tests.
func (n *IntegratedNode) initClients() {
	n.t.Helper()

	addr := fmt.Sprintf("127.0.0.1:%d", n.Cfg.RPCPort)
	tlsCreds := credentials.NewTLS(&tls.Config{
		InsecureSkipVerify: true, // nolint:gosec
	})

	var err error
	n.conn, err = grpc.Dial(
		addr,
		grpc.WithTransportCredentials(tlsCreds),
	)
	require.NoError(n.t, err)

	// LND clients.
	n.LightningClient = lnrpc.NewLightningClient(n.conn)
	n.StateClient = lnrpc.NewStateClient(n.conn)
	n.RouterClient = routerrpc.NewRouterClient(n.conn)
	n.InvoicesClient = invoicesrpc.NewInvoicesClient(n.conn)
	n.WalletKitClient = walletrpc.NewWalletKitClient(n.conn)

	// Tapd clients.
	n.TaprootAssetsClient = taprpc.NewTaprootAssetsClient(n.conn)
	n.AssetWalletClient = wrpc.NewAssetWalletClient(n.conn)
	n.MintClient = mintrpc.NewMintClient(n.conn)
	n.RfqClient = rfqrpc.NewRfqClient(n.conn)
	n.TaprootAssetChannelsClient = tchrpc.NewTaprootAssetChannelsClient(
		n.conn,
	)
	n.UniverseClient = unirpc.NewUniverseClient(n.conn)
	n.TapDevClient = tapdevrpc.NewTapDevClient(n.conn)
	n.MailboxClient = authmailboxrpc.NewMailboxClient(n.conn)
}

// RPCAddr returns the host:port address of this node's gRPC server.
func (n *IntegratedNode) RPCAddr() string {
	return fmt.Sprintf("127.0.0.1:%d", n.Cfg.RPCPort)
}

// P2PAddr returns the host:port address of this node's P2P listener.
func (n *IntegratedNode) P2PAddr() string {
	return fmt.Sprintf("127.0.0.1:%d", n.Cfg.P2PPort)
}

// fetchNodeInfo queries lnd's GetInfo to populate the node's identity pubkey.
func (n *IntegratedNode) fetchNodeInfo() {
	n.t.Helper()

	ctx, cancel := context.WithTimeout(
		context.Background(), 30*time.Second,
	)
	defer cancel()

	var info *lnrpc.GetInfoResponse
	err := wait.NoError(func() error {
		var err error
		info, err = n.LightningClient.GetInfo(
			ctx, &lnrpc.GetInfoRequest{},
		)
		return err
	}, 30*time.Second)
	require.NoError(n.t, err, "failed to get info for %s", n.Cfg.Name)

	pubKeyBytes, err := hex.DecodeString(info.IdentityPubkey)
	require.NoError(n.t, err, "invalid pubkey hex")

	copy(n.PubKey[:], pubKeyBytes)
	n.PubKeyStr = info.IdentityPubkey
}

// WaitForReady polls lnd's GetInfo until it reports the node is fully synced
// and ready to accept operations.
func (n *IntegratedNode) WaitForReady(ctx context.Context) {
	n.t.Helper()

	err := wait.NoError(func() error {
		info, err := n.LightningClient.GetInfo(
			ctx, &lnrpc.GetInfoRequest{},
		)
		if err != nil {
			return err
		}

		if !info.SyncedToChain {
			return fmt.Errorf("node %s not synced to chain",
				n.Cfg.Name)
		}

		return nil
	}, 30*time.Second)

	require.NoError(n.t, err, "node %s did not become ready",
		n.Cfg.Name)
}

// prefixArgs ensures each flag-style arg has the given prefix (e.g.
// "--lnd."). Args that already carry the prefix are passed through
// unchanged; args starting with "--" get the prefix prepended after the
// dashes. Non-flag tokens are skipped.
func prefixArgs(prefix string, args []string) []string {
	result := make([]string, 0, len(args))
	for _, arg := range args {
		if len(arg) < 2 || arg[0:2] != "--" {
			// Not a flag, skip.
			continue
		}

		// Already prefixed, pass through.
		if strings.HasPrefix(arg, prefix) {
			result = append(result, arg)
			continue
		}

		// Prepend prefix after the leading "--".
		result = append(result, prefix+arg[2:])
	}

	return result
}
