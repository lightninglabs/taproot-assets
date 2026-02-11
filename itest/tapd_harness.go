package itest

import (
	"bytes"
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/lightninglabs/taproot-assets/cmd/commands"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/rfq"
	"github.com/lightninglabs/taproot-assets/rpcserver"
	"github.com/lightninglabs/taproot-assets/tapdb"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/assetwalletrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/authmailboxrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/rfqrpc"
	tchrpc "github.com/lightninglabs/taproot-assets/taprpc/tapchannelrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/tapdevrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lntest/node"
	"github.com/lightningnetwork/lnd/lntest/port"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/lightningnetwork/lnd/macaroons"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials"
	"gopkg.in/macaroon.v2"
)

var (
	// dbbackend is a command line flag for specifying the database backend
	// to use when starting a tap daemon.
	dbbackend = flag.String("dbbackend", "sqlite", "Set the database "+
		"backend to use when starting a tap daemon.")

	// postgresTimeout is a command line flag for specifying the amount of
	// time to allow the postgres fixture to run in total. Needs to be
	// increased for long-running tests.
	postgresTimeout = flag.Duration("postgrestimeout",
		tapdb.DefaultPostgresFixtureLifetime, "The amount of time to "+
			"allow the postgres fixture to run in total. Needs "+
			"to be increased for long-running tests.")

	// defaultHashmailBackoffConfig is the default backoff config we'll use
	// for sending proofs with the hashmail courier.
	defaultHashmailBackoffConfig = proof.BackoffCfg{
		BackoffResetWait: time.Second,
		NumTries:         10,
		InitialBackoff:   300 * time.Millisecond,
		MaxBackoff:       2 * time.Second,
	}

	// defaultUniverseRpcBackoffConfig is the default backoff config we'll
	// use for sending proofs with the universe RPC courier.
	defaultUniverseRpcBackoffConfig = proof.BackoffCfg{
		SkipInitDelay:    true,
		BackoffResetWait: time.Second,
		NumTries:         10,
		InitialBackoff:   300 * time.Millisecond,
		MaxBackoff:       2 * time.Second,
	}

	// defaultProofRetrievalDelay is the default delay we'll use for the
	// custodian to wait from observing a transaction on-chan to retrieving
	// the proof from the courier.
	defaultProofRetrievalDelay = 200 * time.Millisecond
)

const (
	// defaultProofTransferReceiverAckTimeout is the default itest specific
	// timeout we'll use for waiting for a receiver to acknowledge a proof
	// transfer.
	defaultProofTransferReceiverAckTimeout = 500 * time.Millisecond
)

// tapdHarness is a test harness that holds everything that is needed to
// start an instance of the tapd server as a separate process.
type tapdHarness struct {
	cfg *tapdConfig

	// cliArgs holds the CLI arguments used to start the tapd process.
	cliArgs []string

	// rpcListenAddr is the address that the tapd RPC server listens on.
	rpcListenAddr string

	// restListenAddr is the address that the tapd REST server listens on.
	restListenAddr string

	// tlsCertPath is the path to the TLS certificate for this tapd
	// instance.
	tlsCertPath string

	// macPath is the path to the admin macaroon for this tapd instance.
	macPath string

	// hashmailBackoffCfg is the backoff config used for the hashmail
	// courier. Stored here so tests can access expected values.
	hashmailBackoffCfg proof.BackoffCfg

	// universeRpcBackoffCfg is the backoff config used for the universe
	// RPC courier. Stored here so tests can access expected values.
	universeRpcBackoffCfg proof.BackoffCfg

	// cmd is the running tapd process.
	cmd *exec.Cmd

	// processDone is closed when the tapd process exits. Used to
	// coordinate between the background wait goroutine in start() and
	// the stop() method.
	processDone chan struct{}

	// logFile is the log file for this tapd instance's output.
	logFile *os.File

	ht *harnessTest

	taprpc.TaprootAssetsClient
	assetwalletrpc.AssetWalletClient
	mintrpc.MintClient
	rfqrpc.RfqClient
	tchrpc.TaprootAssetChannelsClient
	universerpc.UniverseClient
	tapdevrpc.TapDevClient
	authmailboxrpc.MailboxClient
}

// tapdConfig holds all configuration items that are required to start a tapd
// server.
type tapdConfig struct {
	LndNode   *node.HarnessNode
	NetParams *chaincfg.Params
	BaseDir   string
}

type harnessOpts struct {
	proofSendBackoffCfg          *proof.BackoffCfg
	proofReceiverAckTimeout      *time.Duration
	proofCourier                 proof.CourierHarness
	custodianProofRetrievalDelay *time.Duration
	addrAssetSyncerDisable       bool
	oracleServerAddress          string
	portfolioPilotAddress        string

	// fedSyncTickerInterval is the interval at which the federation envoy
	// sync ticker will fire.
	fedSyncTickerInterval *time.Duration

	// sqliteDatabaseFilePath is the path to the SQLite database file to
	// use.
	sqliteDatabaseFilePath *string

	// disableSyncCache is a flag that can be set to true to disable the
	// universe syncer cache.
	disableSyncCache bool

	// sendPriceHint indicates whether the tapd should send price hints from
	// the local oracle to the counterparty when requesting a quote.
	sendPriceHint bool

	// disableSupplyVerifierChainWatch when true prevents the supply
	// verifier from starting state machines to watch on-chain outputs for
	// spends. This option is intended for universe servers, where supply
	// verification should only occur for commitments submitted by peers,
	// not via on-chain spend detection.
	disableSupplyVerifierChainWatch bool

	// disableSweepOrphanUtxos indicates whether sweeping of orphaned anchor
	// UTXOs into anchor transactions should be disabled.
	disableSweepOrphanUtxos bool
}

type harnessOption func(*harnessOpts)

func defaultHarnessOpts() *harnessOpts {
	return &harnessOpts{
		// Disable orphan UTXO sweeping in tests by default to avoid
		// interference with test assertions.
		disableSweepOrphanUtxos: true,
	}
}

// withOracleAddress is a functional option that sets the oracle address option
// to the provided string.
func withOracleAddress(addr string) harnessOption {
	return func(ho *harnessOpts) {
		ho.oracleServerAddress = addr
	}
}

// withPortfolioPilotAddress is a functional option that sets the portfolio
// pilot server address option to the provided string.
func withPortfolioPilotAddress(addr string) harnessOption {
	return func(ho *harnessOpts) {
		ho.portfolioPilotAddress = addr
	}
}

// withDisableSupplyVerifierChainWatch is a functional option that disables
// the supply verifier chain watch functionality. This is intended for universe
// servers where supply verification should only occur for commitments submitted
// by peers, not via on-chain spend detection.
func withDisableSupplyVerifierChainWatch() harnessOption {
	return func(ho *harnessOpts) {
		ho.disableSupplyVerifierChainWatch = true
	}
}

// newTapdHarness creates a new tapd server harness with the given
// configuration. The tapd instance will be started as a separate OS process
// with its own log file.
func newTapdHarness(t *testing.T, ht *harnessTest, cfg tapdConfig,
	harnessOpts ...harnessOption) (*tapdHarness, error) {

	opts := defaultHarnessOpts()
	for _, harnessOpt := range harnessOpts {
		harnessOpt(opts)
	}

	if cfg.BaseDir == "" {
		var err error
		cfg.BaseDir, err = os.MkdirTemp("", "itest-tapd")
		if err != nil {
			return nil, err
		}
	}

	rpcPort := port.NextAvailablePort()
	restPort := port.NextAvailablePort()
	rpcListenAddr := fmt.Sprintf("127.0.0.1:%d", rpcPort)
	restListenAddr := fmt.Sprintf("127.0.0.1:%d", restPort)

	// Build the LND connection info.
	lndMacPath := filepath.Join(
		cfg.LndNode.Cfg.DataDir, "chain", "bitcoin",
		cfg.NetParams.Name, "admin.macaroon",
	)

	// Construct CLI arguments for the tapd process.
	args := []string{
		"--tapddir=" + cfg.BaseDir,
		"--network=" + cfg.NetParams.Name,
		"--debuglevel=" + *logLevel,
		"--rpclisten=" + rpcListenAddr,
		"--restlisten=" + restListenAddr,
		"--lnd.host=" + cfg.LndNode.Cfg.RPCAddr(),
		"--lnd.macaroonpath=" + lndMacPath,
		"--lnd.tlspath=" + cfg.LndNode.Cfg.TLSCertPath,
		"--allow-public-uni-proof-courier",
		"--universe.public-access=rw",
		"--universe.sync-all-assets",
		"--logging.file.max-files=99",
		"--logging.file.max-file-size=999",
	}

	// Resolve the proof courier address.
	proofCourierAddr := ""
	switch typedProofCourier := (opts.proofCourier).(type) {
	case *ApertureHarness:
		proofCourierAddr = fmt.Sprintf(
			"%s://%s", proof.HashmailCourierType,
			typedProofCourier.ListenAddr,
		)
	case *universeServerHarness:
		proofCourierAddr = fmt.Sprintf(
			"%s://%s", proof.UniverseRpcCourierType,
			typedProofCourier.ListenAddr,
		)
	case *proof.MockProofCourier:
		proofCourierAddr = fmt.Sprintf(
			"%s://%s", proof.MockCourierType, "dummyhost:1234",
		)
	}
	if proofCourierAddr != "" {
		args = append(args, "--proofcourieraddr="+proofCourierAddr)
	}
	ht.t.Logf("Using proof courier address: %v", proofCourierAddr)

	// Configure proof courier backoff settings. Store on harness for
	// test access.
	hashmailBackoffCfg := defaultHashmailBackoffConfig
	universeRpcBackoffCfg := defaultUniverseRpcBackoffConfig
	if opts.proofSendBackoffCfg != nil {
		hashmailBackoffCfg = *opts.proofSendBackoffCfg
		universeRpcBackoffCfg = *opts.proofSendBackoffCfg
	}
	args = append(args, fmt.Sprintf(
		"--hashmailcourier.backoffresetwait=%s",
		hashmailBackoffCfg.BackoffResetWait,
	))
	args = append(args, fmt.Sprintf(
		"--hashmailcourier.numtries=%d",
		hashmailBackoffCfg.NumTries,
	))
	args = append(args, fmt.Sprintf(
		"--hashmailcourier.initialbackoff=%s",
		hashmailBackoffCfg.InitialBackoff,
	))
	args = append(args, fmt.Sprintf(
		"--hashmailcourier.maxbackoff=%s",
		hashmailBackoffCfg.MaxBackoff,
	))

	receiverAckTimeout := defaultProofTransferReceiverAckTimeout
	if opts.proofReceiverAckTimeout != nil {
		receiverAckTimeout = *opts.proofReceiverAckTimeout
	}
	args = append(args, fmt.Sprintf(
		"--hashmailcourier.receiveracktimeout=%s",
		receiverAckTimeout,
	))

	args = append(args, fmt.Sprintf(
		"--universerpccourier.backoffresetwait=%s",
		universeRpcBackoffCfg.BackoffResetWait,
	))
	args = append(args, fmt.Sprintf(
		"--universerpccourier.numtries=%d",
		universeRpcBackoffCfg.NumTries,
	))
	args = append(args, fmt.Sprintf(
		"--universerpccourier.initialbackoff=%s",
		universeRpcBackoffCfg.InitialBackoff,
	))
	args = append(args, fmt.Sprintf(
		"--universerpccourier.maxbackoff=%s",
		universeRpcBackoffCfg.MaxBackoff,
	))
	args = append(args,
		"--universerpccourier.servicerequestimeout=5s",
	)
	if universeRpcBackoffCfg.SkipInitDelay {
		args = append(args,
			"--universerpccourier.skipinitdelay",
		)
	}

	// Custodian proof retrieval delay.
	custodianDelay := defaultProofRetrievalDelay
	if opts.custodianProofRetrievalDelay != nil {
		custodianDelay = *opts.custodianProofRetrievalDelay
	}
	args = append(args, fmt.Sprintf(
		"--custodianproofretrievaldelay=%s", custodianDelay,
	))

	// Database backend.
	switch *dbbackend {
	case "sqlite":
		// Default, nothing extra needed.

	case "postgres":
		fixture := tapdb.NewTestPgFixture(
			t, *postgresTimeout, !*noDelete,
		)
		t.Cleanup(func() {
			if !*noDelete {
				fixture.TearDown(t)
			}
		})
		pgCfg := fixture.GetConfig()
		args = append(args,
			"--databasebackend=postgres",
			"--postgres.host="+pgCfg.Host,
			fmt.Sprintf("--postgres.port=%d", pgCfg.Port),
			"--postgres.user="+pgCfg.User,
			"--postgres.password="+pgCfg.Password,
			"--postgres.dbname="+pgCfg.DBName,
		)
	}

	// Set the SQLite database file path if it was specified.
	if opts.sqliteDatabaseFilePath != nil {
		args = append(args, fmt.Sprintf(
			"--sqlite.dbfile=%s", *opts.sqliteDatabaseFilePath,
		))
	}

	// Address book syncer disable.
	if opts.addrAssetSyncerDisable {
		args = append(args, "--address.disable-syncer")
	}

	// Supply verifier chain watch disable.
	if opts.disableSupplyVerifierChainWatch {
		args = append(args,
			"--universe.disable-supply-verifier-chain-watch",
		)
	}

	// Disable sweep orphan UTXOs.
	if opts.disableSweepOrphanUtxos {
		args = append(args, "--wallet.disable-sweep-orphan-utxos")
	}

	// Federation sync ticker interval.
	if opts.fedSyncTickerInterval != nil {
		args = append(args, fmt.Sprintf(
			"--universe.syncinterval=%s",
			*opts.fedSyncTickerInterval,
		))
	}

	// Sync cache.
	if !opts.disableSyncCache {
		args = append(args,
			"--universe.multiverse-caches.syncer-cache-enabled",
		)
	}

	// Oracle and RFQ settings.
	switch {
	case len(opts.oracleServerAddress) > 0:
		args = append(args, fmt.Sprintf(
			"--experimental.rfq.priceoracleaddress=%s",
			opts.oracleServerAddress,
		))
		args = append(args,
			"--experimental.rfq.priceoracletlsinsecure",
		)
	default:
		args = append(args, fmt.Sprintf(
			"--experimental.rfq.priceoracleaddress=%s",
			rfq.MockPriceOracleServiceAddress,
		))
		args = append(args,
			"--experimental.rfq.mockoracleassetsperbtc=5820600",
		)
	}

	args = append(args, fmt.Sprintf(
		"--experimental.rfq.acceptpricedeviationppm=%d",
		rfq.DefaultAcceptPriceDeviationPpm,
	))

	if len(opts.portfolioPilotAddress) > 0 {
		args = append(args, fmt.Sprintf(
			"--experimental.rfq.portfoliopilotaddress=%s",
			opts.portfolioPilotAddress,
		))
	}

	if opts.sendPriceHint {
		args = append(args, "--experimental.rfq.sendpricehint")
	}

	// Compute the expected TLS cert path and macaroon path based on
	// the tapd directory structure that the tapd process will create.
	tlsCertPath := filepath.Join(cfg.BaseDir, "tls.cert")
	macPath := filepath.Join(
		cfg.BaseDir, "data", cfg.NetParams.Name, "admin.macaroon",
	)

	return &tapdHarness{
		cfg:                   &cfg,
		cliArgs:               args,
		rpcListenAddr:         rpcListenAddr,
		restListenAddr:        restListenAddr,
		tlsCertPath:           tlsCertPath,
		macPath:               macPath,
		hashmailBackoffCfg:    hashmailBackoffCfg,
		universeRpcBackoffCfg: universeRpcBackoffCfg,
		ht:                    ht,
	}, nil
}

// ExecTapCLI uses the CLI parser to invoke the specified tapd harness via RPC,
// passing the provided arguments. It returns the response or an error.
func ExecTapCLI(ctx context.Context, tapClient *tapdHarness,
	args ...string) (interface{}, error) {

	if ctx == nil {
		return nil, fmt.Errorf("context cannot be nil")
	}

	// Construct a response channel to receive the response from the CLI
	// command.
	responseChan := make(chan lfn.Result[interface{}], 1)

	// Construct an app which supports the tapcli command set.
	opt := []commands.ActionOption{
		commands.ActionWithCtx(ctx),
		commands.ActionWithClient(tapClient),
		commands.ActionWithSilencePrint(true),
		commands.ActionRespChan(responseChan),
	}

	app := commands.NewApp(opt...)
	app.Name = "tapcli-itest"

	// Prepend a dummy path to the args to satisfy the CLI argument parser.
	args = append([]string{"dummy-path"}, args...)

	// Run the app within the current goroutine. This does not start a
	// separate process.
	if err := app.Run(args); err != nil {
		return nil, err
	}

	// Wait for a response of context cancellation.
	select {
	case respResult := <-responseChan:
		resp, err := respResult.Unpack()
		if err != nil {
			return nil, err
		}

		return resp, nil

	case <-ctx.Done():
		// Handle context cancellation.
		return nil, ctx.Err()
	}
}

// rpcHost returns the RPC host for the tapd server.
func (hs *tapdHarness) rpcHost() string {
	return hs.rpcListenAddr
}

// setCliFlag sets or updates a CLI flag in the harness's argument list.
// This can be used between stop() and start() to modify configuration before
// restarting. The flag name should not include the "--" prefix.
func (hs *tapdHarness) setCliFlag(flag, value string) {
	prefix := "--" + flag + "="
	for i, arg := range hs.cliArgs {
		if strings.HasPrefix(arg, prefix) {
			hs.cliArgs[i] = prefix + value
			return
		}
	}

	// Flag not found, append it.
	hs.cliArgs = append(hs.cliArgs, prefix+value)
}

// setBoolFlag adds or removes a boolean CLI flag. When value is true, the
// flag is added (--key). When false, it is removed (relying on tapd defaults).
// NOTE: go-flags does not support --flag=false for boolean options, so there
// is currently no way to explicitly disable a boolean flag that defaults to
// true via the CLI. This is a known limitation (see sweep-orphan-utxos).
func (hs *tapdHarness) setBoolFlag(key string, value bool) {
	flag := "--" + key
	if value {
		// Add the flag if not already present.
		for _, arg := range hs.cliArgs {
			if arg == flag {
				return
			}
		}
		hs.cliArgs = append(hs.cliArgs, flag)
	} else {
		// Remove the flag if present.
		for i, arg := range hs.cliArgs {
			if arg == flag {
				hs.cliArgs = append(
					hs.cliArgs[:i],
					hs.cliArgs[i+1:]...,
				)
				return
			}
		}
	}
}

// updateLndNode updates the LND connection config in the CLI args to point to
// a different LND node. This is used when restoring an LND node from seed and
// reconnecting tapd to it.
func (hs *tapdHarness) updateLndNode(lndNode *node.HarnessNode) {
	hs.cfg.LndNode = lndNode

	lndMacPath := filepath.Join(
		lndNode.Cfg.DataDir, "chain", "bitcoin",
		hs.cfg.NetParams.Name, "admin.macaroon",
	)

	hs.setCliFlag("lnd.host", lndNode.Cfg.RPCAddr())
	hs.setCliFlag("lnd.macaroonpath", lndMacPath)
	hs.setCliFlag("lnd.tlspath", lndNode.Cfg.TLSCertPath)
}

// start spins up the tapd process and waits for it to be ready for gRPC
// connections.
func (hs *tapdHarness) start(expectErrExit bool) error {
	//nolint:gosec
	hs.cmd = exec.Command("./tapd-itest", hs.cliArgs...)

	// Set up per-instance log file for this tapd node.
	if err := hs.addLogFile(); err != nil {
		return fmt.Errorf("could not create log file: %w", err)
	}

	// Start the process.
	if err := hs.cmd.Start(); err != nil {
		return fmt.Errorf("failed to start tapd: %w", err)
	}

	hs.ht.t.Logf("Started tapd (name=%v, dir=%v) with PID=%d",
		hs.cfg.LndNode.Cfg.Name, hs.cfg.BaseDir,
		hs.cmd.Process.Pid)

	// Wait for the process to exit in the background. If it exits
	// unexpectedly, log the error. Signal processDone when complete
	// so stop() can wait for the process to fully exit.
	hs.processDone = make(chan struct{})
	go func() {
		err := hs.cmd.Wait()
		if err != nil && !expectErrExit {
			hs.ht.t.Logf("tapd process (name=%v) exited with "+
				"error: %v", hs.cfg.LndNode.Cfg.Name, err)
		}
		close(hs.processDone)
	}()

	// Wait until the RPC server is actually listening.
	err := wait.NoError(func() error {
		_, err := net.Dial("tcp", hs.rpcListenAddr)
		return err
	}, defaultTimeout)
	if err != nil {
		return fmt.Errorf("error waiting for tapd to start: %w", err)
	}

	// Create our client to interact with the tapd RPC server directly.
	rpcConn, err := dialServer(
		hs.rpcListenAddr, hs.tlsCertPath, hs.macPath,
	)
	if err != nil {
		return fmt.Errorf("could not connect to %v: %w",
			hs.rpcListenAddr, err)
	}
	hs.TaprootAssetsClient = taprpc.NewTaprootAssetsClient(rpcConn)
	hs.AssetWalletClient = assetwalletrpc.NewAssetWalletClient(rpcConn)
	hs.MintClient = mintrpc.NewMintClient(rpcConn)
	hs.RfqClient = rfqrpc.NewRfqClient(rpcConn)
	hs.TaprootAssetChannelsClient = tchrpc.NewTaprootAssetChannelsClient(
		rpcConn,
	)
	hs.UniverseClient = universerpc.NewUniverseClient(rpcConn)
	hs.TapDevClient = tapdevrpc.NewTapDevClient(rpcConn)
	hs.MailboxClient = authmailboxrpc.NewMailboxClient(rpcConn)

	return nil
}

// addLogFile creates a per-instance log file and redirects the tapd process's
// stdout and stderr to it. This follows the same pattern used by lnd's test
// harness for per-node log separation.
//
// The file is named: tapd-{lndNodeID}-{testCaseName}-{nodeName}.log
//
// This ensures unique filenames even when multiple test cases within the
// same tranche create nodes with the same name (e.g., "Alice").
func (hs *tapdHarness) addLogFile() error {
	dir := node.GetLogDir()

	lndCfg := hs.cfg.LndNode.Cfg
	fileName := fmt.Sprintf(
		"%s/tapd-%d-%s-%s.log", dir,
		lndCfg.NodeID, lndCfg.LogFilenamePrefix, lndCfg.Name,
	)

	// Create the log directory if it doesn't exist.
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create log dir: %w", err)
	}

	file, err := os.OpenFile(
		fileName, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0666,
	)
	if err != nil {
		return err
	}

	// Pass both stdout and stderr to the log file.
	hs.cmd.Stdout = file
	hs.cmd.Stderr = file

	hs.logFile = file

	return nil
}

// stop shuts down the tapd process and deletes its temporary data directory.
func (hs *tapdHarness) stop(deleteData bool) error {
	var stopErr error

	// Try graceful shutdown via RPC first.
	if hs.TaprootAssetsClient != nil {
		ctx, cancel := context.WithTimeout(
			context.Background(), 5*time.Second,
		)
		_, err := hs.StopDaemon(ctx, &taprpc.StopRequest{})
		cancel()

		if err != nil {
			hs.ht.t.Logf("RPC StopDaemon failed for tapd "+
				"(name=%v): %v, sending interrupt",
				hs.cfg.LndNode.Cfg.Name, err)

			// Fall back to sending an interrupt signal.
			if hs.cmd != nil && hs.cmd.Process != nil {
				_ = hs.cmd.Process.Signal(os.Interrupt)
			}
		}
	} else if hs.cmd != nil && hs.cmd.Process != nil {
		// No RPC client available, send interrupt.
		_ = hs.cmd.Process.Signal(os.Interrupt)
	}

	// Wait for the process to fully exit using the processDone channel
	// that is closed by the background goroutine in start().
	if hs.processDone != nil {
		select {
		case <-hs.processDone:
		case <-time.After(20 * time.Second):
			// Force kill if graceful shutdown didn't work.
			hs.ht.t.Logf("tapd (name=%v) didn't exit in time, "+
				"force killing", hs.cfg.LndNode.Cfg.Name)
			if hs.cmd != nil && hs.cmd.Process != nil {
				killErr := hs.cmd.Process.Kill()
				if killErr != nil {
					stopErr = fmt.Errorf("failed to kill "+
						"tapd: %w", killErr)
				}

				// Wait for kill to complete.
				<-hs.processDone
			}
		}
	}

	// Close the log file.
	if hs.logFile != nil {
		_ = hs.logFile.Close()
		hs.logFile = nil
	}

	// Reset RPC clients so they get re-created on next start().
	hs.TaprootAssetsClient = nil

	// Clean up data directory.
	if deleteData {
		_ = os.RemoveAll(hs.cfg.BaseDir)
	}

	return stopErr
}

// assetIDWithBalance returns the asset ID of an asset that has at least the
// given balance. If no such asset is found, nil is returned.
func (hs *tapdHarness) assetIDWithBalance(t *testing.T, ctx context.Context,
	minBalance uint64, assetType taprpc.AssetType) *taprpc.Asset {

	balances, err := hs.ListBalances(ctx, &taprpc.ListBalancesRequest{
		GroupBy: &taprpc.ListBalancesRequest_AssetId{
			AssetId: true,
		},
	})
	require.NoError(t, err)

	for assetIDHex, balance := range balances.AssetBalances {
		if balance.Balance >= minBalance &&
			balance.AssetGenesis.AssetType == assetType {

			assetIDBytes, err := hex.DecodeString(assetIDHex)
			require.NoError(t, err)

			assets, err := hs.ListAssets(
				ctx, &taprpc.ListAssetRequest{},
			)
			require.NoError(t, err)

			for _, asset := range assets.Assets {
				if bytes.Equal(
					asset.AssetGenesis.AssetId,
					assetIDBytes,
				) {

					return asset
				}
			}
		}
	}

	return nil
}

// listTransfersSince returns all transfers that have been made since the last
// transfer in the given list. If the list is empty, all transfers are returned.
func (hs *tapdHarness) listTransfersSince(t *testing.T, ctx context.Context,
	existingTransfers []*taprpc.AssetTransfer) []*taprpc.AssetTransfer {

	resp, err := hs.ListTransfers(ctx, &taprpc.ListTransfersRequest{})
	require.NoError(t, err)

	if len(existingTransfers) == 0 {
		return resp.Transfers
	}

	newIndex := len(existingTransfers)
	return resp.Transfers[newIndex:]
}

// dialServer creates a gRPC client connection to the given host using a default
// timeout context.
func dialServer(rpcHost, tlsCertPath, macaroonPath string) (*grpc.ClientConn,
	error) {

	defaultOpts, err := defaultDialOptions(tlsCertPath, macaroonPath)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()
	return grpc.DialContext(ctx, rpcHost, defaultOpts...)
}

// defaultDialOptions returns the default RPC dial options.
func defaultDialOptions(serverCertPath, macaroonPath string) ([]grpc.DialOption,
	error) {

	baseOpts := []grpc.DialOption{
		grpc.WithBlock(),
		grpc.WithConnectParams(grpc.ConnectParams{
			Backoff:           backoff.DefaultConfig,
			MinConnectTimeout: 10 * time.Second,
		}),
		grpc.WithDefaultCallOptions(rpcserver.MaxMsgReceiveSize),
	}

	if serverCertPath != "" {
		err := wait.Predicate(func() bool {
			return lnrpc.FileExists(serverCertPath)
		}, defaultTimeout)
		if err != nil {
			return nil, err
		}

		creds, err := credentials.NewClientTLSFromFile(
			serverCertPath, "",
		)
		if err != nil {
			return nil, err
		}
		baseOpts = append(baseOpts, grpc.WithTransportCredentials(creds))
	} else {
		baseOpts = append(baseOpts, grpc.WithInsecure())
	}

	if macaroonPath != "" {
		macaroonOptions, err := readMacaroon(macaroonPath)
		if err != nil {
			return nil, fmt.Errorf("unable to load macaroon %s: %w",
				macaroonPath, err)
		}
		baseOpts = append(baseOpts, macaroonOptions)
	}

	return baseOpts, nil
}

// readMacaroon tries to read the macaroon file at the specified path and create
// gRPC dial options from it.
func readMacaroon(macaroonPath string) (grpc.DialOption, error) {
	// Load the specified macaroon file.
	macBytes, err := os.ReadFile(macaroonPath)
	if err != nil {
		return nil, fmt.Errorf("unable to read macaroon path : %w", err)
	}

	mac := &macaroon.Macaroon{}
	if err = mac.UnmarshalBinary(macBytes); err != nil {
		return nil, fmt.Errorf("unable to decode macaroon: %w", err)
	}

	// Now we append the macaroon credentials to the dial options.
	cred, err := macaroons.NewMacaroonCredential(mac)
	if err != nil {
		return nil, fmt.Errorf("error creating mac cred: %w", err)
	}
	return grpc.WithPerRPCCredentials(cred), nil
}
