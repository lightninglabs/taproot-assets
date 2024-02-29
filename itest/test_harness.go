package itest

import (
	"context"
	"flag"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/go-errors/errors"
	"github.com/lightninglabs/aperture"
	"github.com/lightninglabs/lndclient"
	tap "github.com/lightninglabs/taproot-assets"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/taprpc"
	unirpc "github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	"github.com/lightningnetwork/lnd/build"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lntest"
	"github.com/lightningnetwork/lnd/lntest/node"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/lightningnetwork/lnd/signal"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

var (
	harnessNetParams = &chaincfg.RegressionNetParams

	// lastPort is the last port determined to be free for use by a new
	// node. It should be used atomically.
	lastPort uint32 = defaultNodePort

	// lndDefaultArgs is the list of default arguments that we pass into the
	// lnd harness when creating a new node.
	lndDefaultArgs []string

	// noDelete is a command line flag for disabling deleting the tapd
	// data directories.
	noDelete = flag.Bool("nodelete", false, "Set to true to keep all "+
		"tapd data directories after completing the tests")

	// logLevel is a command line flag for setting the log level of the
	// integration test output.
	logLevel = flag.String("loglevel", "info", "Set the log level of the "+
		"integration test output")
)

const (
	minerMempoolTimeout = wait.MinerMempoolTimeout
	defaultWaitTimeout  = lntest.DefaultTimeout

	// defaultNodePort is the start of the range for listening ports of
	// harness nodes. Ports are monotonically increasing starting from this
	// number and are determined by the results of nextAvailablePort(). The
	// start port should be distinct from lntest's one to not get a conflict
	// with the lnd nodes that are also started.
	defaultNodePort = 19655

	// defaultTimeout is a timeout that will be used for various wait
	// scenarios where no custom timeout value is defined.
	defaultTimeout = time.Second * 10
)

// testCase is a struct that holds a single test case.
type testCase struct {
	name             string
	test             func(t *harnessTest)
	proofCourierType proof.CourierType
}

// harnessTest wraps a regular testing.T providing enhanced error detection
// and propagation. All error will be augmented with a full stack-trace in
// order to aid in debugging. Additionally, any panics caused by active
// test cases will also be handled and represented as fatals.
type harnessTest struct {
	t *testing.T

	// testCase is populated during test execution and represents the
	// current test case.
	testCase *testCase

	// proofCourier is a reference to the current proof courier
	// harness.
	//
	// NOTE: This will be nil if not yet set up.
	proofCourier proof.CourierHarness

	// lndHarness is a reference to the current network harness. Will be
	// nil if not yet set up.
	lndHarness *lntest.HarnessTest

	universeServer *universeServerHarness

	tapd *tapdHarness

	logWriter *build.RotatingLogWriter

	interceptor signal.Interceptor
}

// newHarnessTest creates a new instance of a harnessTest from a regular
// testing.T instance.
func (h *harnessTest) newHarnessTest(t *testing.T, net *lntest.HarnessTest,
	universeServer *universeServerHarness, tapd *tapdHarness,
	proofCourier proof.CourierHarness) *harnessTest {

	return &harnessTest{
		t:              t,
		proofCourier:   proofCourier,
		lndHarness:     net,
		universeServer: universeServer,
		tapd:           tapd,
		logWriter:      h.logWriter,
		interceptor:    h.interceptor,
	}
}

// Skipf calls the underlying testing.T's Skip method, causing the current test
// to be skipped.
func (h *harnessTest) Skipf(format string, args ...interface{}) {
	h.t.Skipf(format, args...)
}

// Fatalf causes the current active test case to fail with a fatal error. All
// integration tests should mark test failures solely with this method due to
// the error stack traces it produces.
func (h *harnessTest) Fatalf(format string, a ...interface{}) {
	stacktrace := errors.Wrap(fmt.Sprintf(format, a...), 1).ErrorStack()

	if h.testCase != nil {
		h.t.Fatalf("Failed: (%v): exited with error: \n"+
			"%v", h.testCase.name, stacktrace)
	} else {
		h.t.Fatalf("Error outside of test: %v", stacktrace)
	}
}

// RunTestCase executes a harness test case. Any errors or panics will be
// represented as fatal.
func (h *harnessTest) RunTestCase(testCase *testCase) {
	h.testCase = testCase
	defer func() {
		h.testCase = nil
	}()

	defer func() {
		if err := recover(); err != nil {
			description := errors.Wrap(err, 2).ErrorStack()
			h.t.Fatalf("Failed: (%v) panicked with: \n%v",
				h.testCase.name, description)
		}
	}()

	testCase.test(h)
}

func (h *harnessTest) Logf(format string, args ...interface{}) {
	h.t.Logf(format, args...)
}

func (h *harnessTest) Log(args ...interface{}) {
	h.t.Log(args...)
}

func (h *harnessTest) LogfTimestamped(format string, args ...interface{}) {
	LogfTimestamped(h.t, format, args...)
}

// shutdown stops both the mock universe and tapd server.
func (h *harnessTest) shutdown(_ *testing.T) error {
	err := h.universeServer.Stop()
	if err != nil {
		return fmt.Errorf("unable to stop universe server harness: "+
			"%w", err)
	}

	if h.proofCourier != nil {
		err := h.proofCourier.Stop()
		if err != nil {
			return fmt.Errorf("unable to stop proof courier "+
				"harness: %w", err)
		}
	}

	err = h.tapd.stop(!*noDelete)
	if err != nil {
		return fmt.Errorf("unable to stop tapd: %w", err)
	}

	return nil
}

// setupLogging initializes the logging subsystem for the server and client
// packages.
func (h *harnessTest) setupLogging() {
	h.logWriter = build.NewRotatingLogWriter()

	var err error
	h.interceptor, err = signal.Intercept()
	require.NoError(h.t, err)

	tap.SetupLoggers(h.logWriter, h.interceptor)
	aperture.SetupLoggers(h.logWriter, h.interceptor)

	h.logWriter.SetLogLevels(*logLevel)
}

func (h *harnessTest) newLndClient(
	n *node.HarnessNode) (*lndclient.GrpcLndServices, error) {

	return lndclient.NewLndServices(&lndclient.LndServicesConfig{
		LndAddress:         n.Cfg.RPCAddr(),
		Network:            lndclient.Network(n.Cfg.NetParams.Name),
		CustomMacaroonPath: n.Cfg.AdminMacPath,
		TLSPath:            n.Cfg.TLSCertPath,
	})
}

func (h *harnessTest) syncUniverseState(target, syncer *tapdHarness,
	numExpectedAssets int) {

	ctxt, cancel := context.WithTimeout(
		context.Background(), defaultWaitTimeout,
	)
	defer cancel()

	syncDiff, err := syncer.SyncUniverse(ctxt, &unirpc.SyncRequest{
		UniverseHost: target.rpcHost(),
		SyncMode:     unirpc.UniverseSyncMode_SYNC_ISSUANCE_ONLY,
	})
	require.NoError(h.t, err)
	numAssets := len(syncDiff.SyncedUniverses)

	require.Equal(h.t, numExpectedAssets, numAssets)
}

// addFederationServer adds a new federation server to the given tapd harness.
func (h *harnessTest) addFederationServer(host string, target *tapdHarness) {
	ctxt, cancel := context.WithTimeout(
		context.Background(), defaultWaitTimeout,
	)
	defer cancel()

	_, err := target.AddFederationServer(
		ctxt, &unirpc.AddFederationServerRequest{
			Servers: []*unirpc.UniverseFederationServer{
				{
					Host: host,
				},
			},
		},
	)
	require.NoError(h.t, err)
}

// nextAvailablePort returns the first port that is available for listening by
// a new node. It panics if no port is found and the maximum available TCP port
// is reached.
func nextAvailablePort() int {
	port := atomic.AddUint32(&lastPort, 1)
	for port < 65535 {
		// If there are no errors while attempting to listen on this
		// port, close the socket and return it as available. While it
		// could be the case that some other process picks up this port
		// between the time the socket is closed and it's reopened in
		// the harness node, in practice in CI servers this seems much
		// less likely than simply some other process already being
		// bound at the start of the tests.
		addr := fmt.Sprintf("127.0.0.1:%d", port)
		l, err := net.Listen("tcp4", addr)
		if err == nil {
			err := l.Close()
			if err == nil {
				return int(port)
			}
		}
		port = atomic.AddUint32(&lastPort, 1)
	}

	// No ports available? Must be a mistake.
	panic("no ports available for listening")
}

// setupHarnesses creates new server and client harnesses that are connected
// to each other through an in-memory gRPC connection.
func setupHarnesses(t *testing.T, ht *harnessTest,
	lndHarness *lntest.HarnessTest, uniServerLndHarness *node.HarnessNode,
	proofCourierType proof.CourierType) (*tapdHarness,
	*universeServerHarness, proof.CourierHarness) {

	// Create a new universe server harness and start it.
	t.Log("Starting universe server harness")
	universeServer := newUniverseServerHarness(t, ht, uniServerLndHarness)

	t.Logf("Starting universe server harness, listening on %v",
		universeServer.ListenAddr)

	err := universeServer.Start(nil)
	require.NoError(t, err, "universe server harness")

	// If a proof courier type is specified, start test specific proof
	// courier service and attach to test harness.
	var proofCourier proof.CourierHarness
	switch proofCourierType {
	case proof.HashmailCourierType:
		port := nextAvailablePort()
		apertureHarness := NewApertureHarness(ht.t, port)
		err := apertureHarness.Start(nil)
		require.NoError(t, err, "aperture proof courier harness")

		proofCourier = apertureHarness

	// If nothing is specified, we use the universe RPC proof courier by
	// default.
	default:
		proofCourier = universeServer
	}

	// Create a tapd that uses Alice and connect it to the universe server.
	tapdHarness := setupTapdHarness(
		t, ht, lndHarness.Alice, universeServer,
		func(params *tapdHarnessParams) {
			params.proofCourier = proofCourier
		},
	)
	return tapdHarness, universeServer, proofCourier
}

// tapdHarnessParams contains parameters that can be set when creating a new
// tapdHarness.
type tapdHarnessParams struct {
	// proofCourier is the proof courier harness that will be used by
	// the tapd harness.
	proofCourier proof.CourierHarness

	// proofSendBackoffCfg is the backoff configuration that is used when
	// sending proofs to the tap daemon.
	proofSendBackoffCfg *proof.BackoffCfg

	// proofReceiverAckTimeout is the timeout that is used when waiting for
	// an ack from the proof receiver.
	proofReceiverAckTimeout *time.Duration

	// custodianProofRetrievalDelay is the time duration the custodian waits
	// having identified an asset transfer on-chain and before retrieving
	// the corresponding proof via the proof courier service.
	custodianProofRetrievalDelay *time.Duration

	// addrAssetSyncerDisable is a flag that determines if the address book
	// will try and bootstrap unknown assets on address creation.
	addrAssetSyncerDisable bool

	// expectErrExit indicates whether tapd is expected to exit with an
	// error.
	expectErrExit bool

	// startupSyncNode if present, then this node will be used to
	// synchronize the Universe state of the newly created node.
	startupSyncNode *tapdHarness

	// startupSyncNumAssets is the number of assets that are expected to be
	// synced from the above node.
	startupSyncNumAssets int

	// fedSyncTickerInterval is the interval at which the federation envoy
	// sync ticker will fire.
	fedSyncTickerInterval *time.Duration

	// noDefaultUniverseSync indicates whether the default universe server
	// should be added as a federation server or not.
	noDefaultUniverseSync bool

	// sqliteDatabaseFilePath is the path to the SQLite database file to
	// use.
	sqliteDatabaseFilePath *string
}

type Option func(*tapdHarnessParams)

// setupTapdHarness creates a new tapd that connects to the given lnd node
// and to the given universe server.
func setupTapdHarness(t *testing.T, ht *harnessTest,
	node *node.HarnessNode, universe *universeServerHarness,
	opts ...Option) *tapdHarness {

	// Set parameters by executing option functions.
	params := &tapdHarnessParams{}
	for _, opt := range opts {
		opt(params)
	}

	// If present, use the proof courier specified in the optional
	// parameters. Otherwise, use the proof courier specified in the test
	// case harness.
	//
	// A new tapd node spun up within a test case will default to using the
	// same proof courier as the primary test case tapd node.
	selectedProofCourier := ht.proofCourier
	if params.proofCourier != nil {
		selectedProofCourier = params.proofCourier
	}

	harnessOpts := func(ho *harnessOpts) {
		ho.proofSendBackoffCfg = params.proofSendBackoffCfg
		ho.proofReceiverAckTimeout = params.proofReceiverAckTimeout
		ho.proofCourier = selectedProofCourier
		ho.custodianProofRetrievalDelay = params.custodianProofRetrievalDelay
		ho.addrAssetSyncerDisable = params.addrAssetSyncerDisable
		ho.fedSyncTickerInterval = params.fedSyncTickerInterval
		ho.sqliteDatabaseFilePath = params.sqliteDatabaseFilePath
	}

	tapdCfg := tapdConfig{
		NetParams: harnessNetParams,
		LndNode:   node,
	}
	tapdHarness, err := newTapdHarness(t, ht, tapdCfg, harnessOpts)
	require.NoError(t, err)

	// Start the tapd harness now.
	err = tapdHarness.start(params.expectErrExit)
	require.NoError(t, err)

	// Add the default universe server as a federation server, unless
	// specifically indicated by the caller.
	if !params.noDefaultUniverseSync {
		ht.addFederationServer(universe.service.rpcHost(), tapdHarness)
	}

	// Before we exit, we'll check to see if we need to sync the universe
	// state.
	if params.startupSyncNode != nil {
		ht.syncUniverseState(
			params.startupSyncNode, tapdHarness,
			params.startupSyncNumAssets,
		)
	}

	return tapdHarness
}

// isMempoolEmpty checks whether the mempool remains empty for the given
// timeout.
func isMempoolEmpty(miner *rpcclient.Client, timeout time.Duration) (bool,
	error) {

	breakTimeout := time.After(timeout)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	var err error
	var mempool []*chainhash.Hash
	for {
		select {
		case <-breakTimeout:
			return true, nil

		case <-ticker.C:
			mempool, err = miner.GetRawMempool()
			if err != nil {
				return false, err
			}
			if len(mempool) > 0 {
				return false, nil
			}
		}
	}
}

// waitForNTxsInMempool polls until finding the desired number of transactions
// in the provided miner's mempool. An error is returned if this number is not
// met after the given timeout.
func waitForNTxsInMempool(miner *rpcclient.Client, n int,
	timeout time.Duration) ([]*chainhash.Hash, error) {

	breakTimeout := time.After(timeout)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	var err error
	var mempool []*chainhash.Hash
	for {
		select {
		case <-breakTimeout:
			return nil, fmt.Errorf("wanted %v, found %v txs "+
				"in mempool: %v", n, len(mempool), mempool)
		case <-ticker.C:
			mempool, err = miner.GetRawMempool()
			if err != nil {
				return nil, err
			}

			if len(mempool) == n {
				return mempool, nil
			}
		}
	}
}

// shutdownAndAssert shuts down the given node and asserts that no errors
// occur.
func shutdownAndAssert(t *harnessTest, node *node.HarnessNode,
	tapd *tapdHarness) {

	if tapd != nil {
		require.NoError(t.t, tapd.stop(!*noDelete))
	}

	t.lndHarness.Shutdown(node)
}

func formatProtoJSON(resp proto.Message) (string, error) {
	jsonBytes, err := taprpc.ProtoJSONMarshalOpts.Marshal(resp)
	if err != nil {
		return "", err
	}

	return string(jsonBytes), nil
}

// lndKeyDescToTap converts an lnd key descriptor to a tap key descriptor.
func lndKeyDescToTap(lnd keychain.KeyDescriptor) *taprpc.KeyDescriptor {
	return &taprpc.KeyDescriptor{
		RawKeyBytes: lnd.PubKey.SerializeCompressed(),
		KeyLoc: &taprpc.KeyLocator{
			KeyFamily: int32(lnd.Family),
			KeyIndex:  int32(lnd.Index),
		},
	}
}

// LogfTimestamped logs the given message with the current timestamp.
func LogfTimestamped(t *testing.T, format string, args ...interface{}) {
	timestamp := time.Now().Format(time.RFC3339Nano)
	args = append([]interface{}{timestamp}, args...)
	t.Logf("%s: "+format, args...)
}
