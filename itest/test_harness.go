package itest

import (
	"bytes"
	"flag"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/wire"
	"github.com/go-errors/errors"
	"github.com/lightninglabs/aperture"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/protobuf-hex-display/jsonpb"
	"github.com/lightninglabs/protobuf-hex-display/proto"
	"github.com/lightninglabs/taro"
	"github.com/lightninglabs/taro/tarorpc"
	"github.com/lightningnetwork/lnd/build"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lntest"
	"github.com/lightningnetwork/lnd/signal"
	"github.com/stretchr/testify/require"
)

var (
	harnessNetParams = &chaincfg.RegressionNetParams

	// lastPort is the last port determined to be free for use by a new
	// node. It should be used atomically.
	lastPort uint32 = defaultNodePort

	// lndDefaultArgs is the list of default arguments that we pass into the
	// lnd harness when creating a new node. Currently, this just enables
	// anchors as they are on by default in 0.14.1.
	lndDefaultArgs = []string{
		"--protocol.anchors",
	}

	// noDelete is a command line flag for disabling deleting the tarod
	// data directories.
	noDelete = flag.Bool("nodelete", false, "Set to true to keep all "+
		"tarod data directories after completing the tests")
)

const (
	minerMempoolTimeout = lntest.MinerMempoolTimeout
	defaultWaitTimeout  = lntest.DefaultTimeout * 60

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
	name           string
	test           func(t *harnessTest)
	enableHashMail bool
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

	// apertureHarness is a reference to the current aperture harness.
	// Will be nil if not yet set up.
	apertureHarness *ApertureHarness

	// lndHarness is a reference to the current network harness. Will be
	// nil if not yet set up.
	lndHarness *lntest.NetworkHarness

	universeServer *serverHarness

	tarod *tarodHarness

	logWriter *build.RotatingLogWriter

	interceptor signal.Interceptor
}

// newHarnessTest creates a new instance of a harnessTest from a regular
// testing.T instance.
func (h *harnessTest) newHarnessTest(t *testing.T, net *lntest.NetworkHarness,
	universeServer *serverHarness, tarod *tarodHarness) *harnessTest {

	return &harnessTest{
		t:               t,
		apertureHarness: h.apertureHarness,
		lndHarness:      net,
		universeServer:  universeServer,
		tarod:           tarod,
		logWriter:       h.logWriter,
		interceptor:     h.interceptor,
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
	if h.lndHarness != nil {
		h.lndHarness.SaveProfilesPages(h.t)
	}

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

// shutdown stops both the mock universe and tarod server.
func (h *harnessTest) shutdown(t *testing.T) error {
	h.universeServer.stop()
	return h.tarod.stop(!*noDelete)
}

// setupLogging initializes the logging subsystem for the server and client
// packages.
func (h *harnessTest) setupLogging() {
	h.logWriter = build.NewRotatingLogWriter()

	var err error
	h.interceptor, err = signal.Intercept()
	require.NoError(h.t, err)

	taro.SetupLoggers(h.logWriter, h.interceptor)
	aperture.SetupLoggers(h.logWriter, h.interceptor)
}

func (h *harnessTest) newLndClient(
	n *lntest.HarnessNode) (*lndclient.GrpcLndServices, error) {

	return lndclient.NewLndServices(&lndclient.LndServicesConfig{
		LndAddress:         n.Cfg.RPCAddr(),
		Network:            lndclient.Network(n.Cfg.NetParams.Name),
		CustomMacaroonPath: n.Cfg.AdminMacPath,
		TLSPath:            n.Cfg.TLSCertPath,
	})
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
	lndHarness *lntest.NetworkHarness,
	enableHashMail bool) (*tarodHarness, *serverHarness) {

	mockServerAddr := fmt.Sprintf(
		lntest.ListenerFormat, lntest.NextAvailablePort(),
	)
	universeServer := newServerHarness(mockServerAddr)
	err := universeServer.start()
	require.NoError(t, err)

	// Create a tarod that uses Bob and connect it to the universe server.
	tarodHarness := setupTarodHarness(
		t, ht, lndHarness.BackendCfg, lndHarness.Alice, universeServer,
		func(params *tarodHarnessParams) {
			params.enableHashMail = enableHashMail
		},
	)
	return tarodHarness, universeServer
}

// tarodHarnessParams contains parameters that can be set when creating a new
// tarodHarness.
type tarodHarnessParams struct {
	// enableHashMail enables hashmail in the taro daemon.
	enableHashMail bool

	// expectErrExit indicates whether tarod is expected to exit with an
	// error.
	expectErrExit bool
}

type Option func(*tarodHarnessParams)

// setupTarodHarness creates a new tarod that connects to the given lnd node
// and to the given universe server.
func setupTarodHarness(t *testing.T, ht *harnessTest,
	backend lntest.BackendConfig, node *lntest.HarnessNode,
	universe *serverHarness, opts ...Option) *tarodHarness {

	// Set parameters by executing option functions.
	params := &tarodHarnessParams{}
	for _, opt := range opts {
		opt(params)
	}

	tarodHarness, err := newTarodHarness(ht, tarodConfig{
		NetParams: harnessNetParams,
		LndNode:   node,
	}, params.enableHashMail)
	require.NoError(t, err)

	// Start the tarod harness now.
	err = tarodHarness.start(params.expectErrExit)
	require.NoError(t, err)
	return tarodHarness
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

// assertTxInBlock checks that a given transaction can be found in the block's
// transaction list.
func assertTxInBlock(t *harnessTest, block *wire.MsgBlock,
	txid *chainhash.Hash) *wire.MsgTx {

	for _, tx := range block.Transactions {
		sha := tx.TxHash()
		if bytes.Equal(txid[:], sha[:]) {
			return tx
		}
	}

	t.Fatalf("tx was not included in block")
	return nil
}

// mineBlocks mine 'num' of blocks and check that blocks are present in
// node blockchain. numTxs should be set to the number of transactions
// (excluding the coinbase) we expect to be included in the first mined block.
func mineBlocks(t *harnessTest, net *lntest.NetworkHarness,
	num uint32, numTxs int) []*wire.MsgBlock {

	// If we expect transactions to be included in the blocks we'll mine,
	// we wait here until they are seen in the miner's mempool.
	var txids []*chainhash.Hash
	var err error
	if numTxs > 0 {
		txids, err = waitForNTxsInMempool(
			net.Miner.Client, numTxs, minerMempoolTimeout,
		)
		if err != nil {
			t.Fatalf("unable to find txns in mempool: %v", err)
		}
	}

	blocks := make([]*wire.MsgBlock, num)

	blockHashes, err := net.Miner.Client.Generate(num)
	if err != nil {
		t.Fatalf("unable to generate blocks: %v", err)
	}

	for i, blockHash := range blockHashes {
		block, err := net.Miner.Client.GetBlock(blockHash)
		if err != nil {
			t.Fatalf("unable to get block: %v", err)
		}

		blocks[i] = block
	}

	// Finally, assert that all the transactions were included in the first
	// block.
	for _, txid := range txids {
		assertTxInBlock(t, blocks[0], txid)
	}

	return blocks
}

// shutdownAndAssert shuts down the given node and asserts that no errors
// occur.
func shutdownAndAssert(t *harnessTest, node *lntest.HarnessNode,
	tarod *tarodHarness) {

	if tarod != nil {
		require.NoError(t.t, tarod.stop(!*noDelete))
	}

	require.NoError(t.t, t.lndHarness.ShutdownNode(node))
}

func formatProtoJSON(resp proto.Message) (string, error) {
	jsonMarshaler := &jsonpb.Marshaler{
		EmitDefaults: true,
		OrigName:     true,
		Indent:       "    ",
	}

	jsonStr, err := jsonMarshaler.MarshalToString(resp)
	if err != nil {
		return "", err
	}

	return jsonStr, nil
}

// lndKeyDescToTaro converts an lnd key descriptor to a taro key descriptor.
func lndKeyDescToTaro(lnd keychain.KeyDescriptor) *tarorpc.KeyDescriptor {
	return &tarorpc.KeyDescriptor{
		RawKeyBytes: lnd.PubKey.SerializeCompressed(),
		KeyLoc: &tarorpc.KeyLocator{
			KeyFamily: int32(lnd.Family),
			KeyIndex:  int32(lnd.Index),
		},
	}
}
