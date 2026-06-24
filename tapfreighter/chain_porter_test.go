package tapfreighter

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btclog/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/stretchr/testify/require"
)

func TestRunChainPorter(t *testing.T) {
	t.Parallel()
}

func init() {
	rand.Seed(time.Now().Unix())

	logger := btclog.NewSLogger(btclog.NewDefaultHandler(os.Stdout))
	UseLogger(logger.SubSystem(Subsystem))
}

// TestVerifySplitCommitmentWitnesses exercises the split witness verifier with
// table-driven vPacket fixtures.
func TestVerifySplitCommitmentWitnesses(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		vPkt        func() tappsbt.VPacket
		expectError bool
	}{
		{
			name: "split leaf with root witness passes",
			vPkt: func() tappsbt.VPacket {
				root := asset.Asset{
					PrevWitnesses: []asset.Witness{{
						PrevID:    &asset.ZeroPrevID,
						TxWitness: wire.TxWitness{{1}},
					}},
				}

				prevWitnesses := []asset.Witness{{
					PrevID: &asset.ZeroPrevID,
					SplitCommitment: &asset.SplitCommitment{
						RootAsset: root,
					},
				}}
				splitLeaf := &asset.Asset{
					PrevWitnesses: prevWitnesses,
				}

				return tappsbt.VPacket{
					Outputs: []*tappsbt.VOutput{{
						Asset: splitLeaf,
					}},
				}
			},
			expectError: false,
		},
		{
			name: "split leaf missing root witness fails",
			vPkt: func() tappsbt.VPacket {
				root := asset.Asset{
					PrevWitnesses: []asset.Witness{{
						PrevID:    &asset.ZeroPrevID,
						TxWitness: wire.TxWitness{},
					}},
				}

				prevWitnesses := []asset.Witness{{
					PrevID: &asset.ZeroPrevID,
					SplitCommitment: &asset.SplitCommitment{
						RootAsset: root,
					},
				}}
				splitLeaf := &asset.Asset{
					PrevWitnesses: prevWitnesses,
				}

				return tappsbt.VPacket{
					Outputs: []*tappsbt.VOutput{{
						Asset: splitLeaf,
					}},
				}
			},
			expectError: true,
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := verifySplitCommitmentWitnesses(tc.vPkt())
			if tc.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
		})
	}
}

// fakeExportLog is a minimal ExportLog implementation for exercising the
// porter's broadcast conflict resolution. Only the methods used by the
// porter's spend resolution are implemented; calling any other method panics
// via the embedded nil interface.
type fakeExportLog struct {
	ExportLog

	pkScripts    map[wire.OutPoint][]byte
	superseded   []chainhash.Hash
	supersedeOps [][]wire.OutPoint
}

func (f *fakeExportLog) FetchAnchorOutputPkScripts(_ context.Context,
	anchorPoints []wire.OutPoint) (map[wire.OutPoint][]byte, error) {

	result := make(map[wire.OutPoint][]byte, len(anchorPoints))
	for _, op := range anchorPoints {
		pkScript, ok := f.pkScripts[op]
		if !ok {
			return nil, fmt.Errorf("unknown anchor outpoint %v",
				op)
		}
		result[op] = pkScript
	}

	return result, nil
}

func (f *fakeExportLog) MarkTransferSuperseded(_ context.Context,
	anchorTxHash chainhash.Hash, spentOutpoints []wire.OutPoint) error {

	f.superseded = append(f.superseded, anchorTxHash)
	f.supersedeOps = append(f.supersedeOps, spentOutpoints)

	return nil
}

// TestLocateConfirmedInputSpend tests the chain query that decides the fate
// of a transfer whose anchor transaction broadcast was rejected as a double
// spend: a confirmed spend of any transfer input identifies the spender,
// while unknown outpoints or absent spends are inconclusive.
func TestLocateConfirmedInputSpend(t *testing.T) {
	t.Parallel()

	var (
		spenderHash = chainhash.Hash{0x42}
		opAsset     = wire.OutPoint{Hash: chainhash.Hash{1}, Index: 0}
		opZeroValue = wire.OutPoint{Hash: chainhash.Hash{2}, Index: 1}
	)

	parcel := &OutboundParcel{
		AnchorTxHeightHint: 100,
		Inputs: []TransferInput{{
			PrevID: asset.PrevID{OutPoint: opAsset},
		}},
		ZeroValueInputs: []*ZeroValueInput{{
			OutPoint: opZeroValue,
		}},
	}

	newPorter := func(exportLog ExportLog,
		bridge ChainBridge) *ChainPorter {

		return NewChainPorter(&ChainPorterConfig{
			ExportLog:   exportLog,
			ChainBridge: bridge,
		})
	}

	pkScripts := map[wire.OutPoint][]byte{
		opAsset:     {txscript.OP_1},
		opZeroValue: {txscript.OP_1},
	}

	// A confirmed spend of any of the parcel's inputs (here the swept
	// zero-value UTXO) identifies the spender.
	t.Run("confirmed input spend found", func(t *testing.T) {
		bridge := tapgarden.NewMockChainBridge()
		bridge.SetSpend(opZeroValue, &chainntnfs.SpendDetail{
			SpentOutPoint: &opZeroValue,
			SpenderTxHash: &spenderHash,
		})

		porter := newPorter(
			&fakeExportLog{pkScripts: pkScripts}, bridge,
		)

		spender := porter.locateConfirmedInputSpend(
			context.Background(), parcel,
		)
		require.NotNil(t, spender)
		require.Equal(t, spenderHash, *spender)
	})

	// If no spend registration succeeds, the query is inconclusive and
	// returns immediately.
	t.Run("unknown outpoints are inconclusive", func(t *testing.T) {
		bridge := tapgarden.NewMockChainBridge()
		bridge.SetSpend(opAsset, &chainntnfs.SpendDetail{
			SpentOutPoint: &opAsset,
			SpenderTxHash: &spenderHash,
		})

		// The export log doesn't know any of the parcel's outpoints,
		// so no spend registration is ever made.
		porter := newPorter(&fakeExportLog{}, bridge)

		spender := porter.locateConfirmedInputSpend(
			context.Background(), parcel,
		)
		require.Nil(t, spender)
	})

	// If no confirmed spend is dispatched, the query times out and is
	// inconclusive. We bound it with a deadline well below the default
	// spend query timeout.
	t.Run("no confirmed spend times out", func(t *testing.T) {
		bridge := tapgarden.NewMockChainBridge()

		porter := newPorter(
			&fakeExportLog{pkScripts: pkScripts}, bridge,
		)

		ctx, cancel := context.WithTimeout(
			context.Background(), 200*time.Millisecond,
		)
		defer cancel()

		spender := porter.locateConfirmedInputSpend(ctx, parcel)
		require.Nil(t, spender)
	})
}

// TestWaitForTransferTxConfSpendResolution tests that a spend of one of the
// parcel's inputs by the parcel's own anchor transaction is ignored in favour
// of the confirmation event (so the parcel completes normally). The
// conflicting-spend supersede path is covered separately by
// TestWaitForTransferTxConfSupersedesAtSafeDepth (positive) and
// TestWaitForTransferTxConfReorgRescue (negative) below.
func TestWaitForTransferTxConfSpendResolution(t *testing.T) {
	t.Parallel()

	newParcelPkg := func() (*sendPackage, wire.OutPoint) {
		anchorTx := wire.NewMsgTx(2)
		anchorTx.AddTxIn(&wire.TxIn{})
		anchorTx.AddTxOut(&wire.TxOut{
			PkScript: bytes.Repeat([]byte{0x01}, 34),
			Value:    1000,
		})

		inputOp := wire.OutPoint{
			Hash:  chainhash.Hash{1},
			Index: uint32(rand.Int31n(10)),
		}

		return &sendPackage{
			SendState: SendStateWaitTxConf,
			OutboundPkg: &OutboundParcel{
				AnchorTx:           anchorTx,
				AnchorTxHeightHint: 100,
				Inputs: []TransferInput{{
					PrevID: asset.PrevID{
						OutPoint: inputOp,
					},
				}},
			},
		}, inputOp
	}

	// serviceConfReqs consumes the mock bridge's confirmation
	// registration signals for the duration of the test.
	serviceConfReqs := func(t *testing.T,
		bridge *tapgarden.MockChainBridge) chan int {

		reqNums := make(chan int, 1)
		done := make(chan struct{})
		t.Cleanup(func() { close(done) })

		go func() {
			for {
				select {
				case reqNo := <-bridge.ConfReqSignal:
					select {
					case reqNums <- reqNo:
					case <-done:
						return
					}

				case <-done:
					return
				}
			}
		}()

		return reqNums
	}

	// A spend by the parcel's own anchor transaction is not a conflict:
	// the parcel keeps waiting, and completes once the confirmation
	// event arrives.
	t.Run("own spend awaits confirmation", func(t *testing.T) {
		pkg, inputOp := newParcelPkg()
		anchorTx := pkg.OutboundPkg.AnchorTx
		anchorTxHash := anchorTx.TxHash()

		bridge := tapgarden.NewMockChainBridge()
		bridge.SetSpend(inputOp, &chainntnfs.SpendDetail{
			SpentOutPoint: &inputOp,
			SpenderTxHash: &anchorTxHash,
		})
		reqNums := serviceConfReqs(t, bridge)

		exportLog := &fakeExportLog{
			pkScripts: map[wire.OutPoint][]byte{
				inputOp: {txscript.OP_1},
			},
		}

		porter := NewChainPorter(&ChainPorterConfig{
			ExportLog:   exportLog,
			ChainBridge: bridge,
		})

		// Dispatch the confirmation event once the conf notification
		// has been registered.
		blockHash := chainhash.Hash{0x07}
		go func() {
			reqNo := <-reqNums
			bridge.SendConfNtfn(reqNo, &blockHash, 123, 1, nil,
				anchorTx)
		}()

		err := porter.waitForTransferTxConf(pkg)
		require.NoError(t, err)
		require.Empty(t, exportLog.superseded)

		require.Equal(
			t, SendStateStorePostAnchorTxConf, pkg.SendState,
		)
		require.NotNil(t, pkg.TransferTxConfEvent)
		require.Equal(
			t, blockHash,
			pkg.OutboundPkg.AnchorTxBlockHash.UnwrapOr(
				chainhash.Hash{},
			),
		)
	})
}

// TestWaitForConfEventOnceRequiresFullSpendCoverage tests that a registration
// failure for any input surfaces as a retryable error from
// waitForConfEventOnce, so the caller re-attempts the whole watch through
// its existing backoff loop. Silently dropping coverage of an input would
// recreate the original stranding bug: a foreign confirmed spend of the
// unwatched input would go unnoticed.
func TestWaitForConfEventOnceRequiresFullSpendCoverage(t *testing.T) {
	t.Parallel()

	anchorTx := wire.NewMsgTx(2)
	anchorTx.AddTxIn(&wire.TxIn{})
	anchorTx.AddTxOut(&wire.TxOut{
		PkScript: bytes.Repeat([]byte{0x01}, 34),
		Value:    1000,
	})

	knownInput := wire.OutPoint{Hash: chainhash.Hash{1}}
	unknownInput := wire.OutPoint{Hash: chainhash.Hash{2}}

	parcel := &OutboundParcel{
		AnchorTx:           anchorTx,
		AnchorTxHeightHint: 100,
		Inputs: []TransferInput{
			{PrevID: asset.PrevID{OutPoint: knownInput}},
			{PrevID: asset.PrevID{OutPoint: unknownInput}},
		},
	}

	bridge := tapgarden.NewMockChainBridge()
	go func() {
		for range bridge.ConfReqSignal {
		}
	}()

	// Only the first input has a pkScript on record. The second
	// input's pkScript lookup will fail, which must surface as an
	// error rather than a silent partial watch.
	exportLog := &fakeExportLog{
		pkScripts: map[wire.OutPoint][]byte{
			knownInput: {txscript.OP_1},
		},
	}

	porter := NewChainPorter(&ChainPorterConfig{
		ExportLog:   exportLog,
		ChainBridge: bridge,
	})

	confEvent, spender, terminal, err := porter.waitForConfEventOnce(
		context.Background(), parcel,
	)
	require.Error(t, err)
	require.Nil(t, confEvent)
	require.Nil(t, spender)
	require.False(
		t, terminal, "registration failure must be retryable, not "+
			"terminal — otherwise the parcel aborts instead of "+
			"being re-watched",
	)
}

// newSpenderPkg returns a freshly populated sendPackage in the
// waiting-for-conf state along with the single transfer input outpoint and a
// minimal valid spender tx (one input, one output) that the porter can use
// when registering the spender-finality conf watch.
func newSpenderPkg(t *testing.T) (*sendPackage, wire.OutPoint, *wire.MsgTx) {
	t.Helper()

	anchorTx := wire.NewMsgTx(2)
	anchorTx.AddTxIn(&wire.TxIn{})
	anchorTx.AddTxOut(&wire.TxOut{
		PkScript: bytes.Repeat([]byte{0x01}, 34),
		Value:    1000,
	})

	inputOp := wire.OutPoint{
		Hash:  chainhash.Hash{1},
		Index: uint32(rand.Int31n(10)),
	}

	spenderTx := wire.NewMsgTx(2)
	spenderTx.AddTxIn(&wire.TxIn{PreviousOutPoint: inputOp})
	spenderTx.AddTxOut(&wire.TxOut{
		PkScript: bytes.Repeat([]byte{0x02}, 34),
		Value:    900,
	})

	pkg := &sendPackage{
		SendState: SendStateWaitTxConf,
		OutboundPkg: &OutboundParcel{
			AnchorTx:           anchorTx,
			AnchorTxHeightHint: 100,
			Inputs: []TransferInput{{
				PrevID: asset.PrevID{OutPoint: inputOp},
			}},
		},
	}

	return pkg, inputOp, spenderTx
}

// drainConfReqs spawns a goroutine that forwards every confirmation
// registration the mock bridge receives to the returned channel, until the
// test ends.
func drainConfReqs(t *testing.T,
	bridge *tapgarden.MockChainBridge) chan int {

	t.Helper()
	out := make(chan int, 4)
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })

	go func() {
		for {
			select {
			case reqNo := <-bridge.ConfReqSignal:
				select {
				case out <- reqNo:
				case <-done:
					return
				}

			case <-done:
				return
			}
		}
	}()

	return out
}

// TestWaitForTransferTxConfReorgRescue exercises the finality gate on
// supersession: a 1-confirmation foreign spend of a transfer input must NOT
// immediately mark the transfer superseded. If that spend is then reorged
// out, the porter must abandon the supersession and let the parcel's own
// anchor confirmation drive the transfer to completion.
//
// Without the finality gate, the parcel was superseded the moment a
// 1-conf foreign spend was seen, and any subsequent reorg permanently
// stranded a transfer that could otherwise have completed normally.
func TestWaitForTransferTxConfReorgRescue(t *testing.T) {
	t.Parallel()

	pkg, inputOp, spenderTx := newSpenderPkg(t)
	anchorTx := pkg.OutboundPkg.AnchorTx
	anchorTxHash := anchorTx.TxHash()
	spenderHash := spenderTx.TxHash()

	const safeDepth = 3
	bridge := tapgarden.NewMockChainBridge()
	bridge.SetSpend(inputOp, &chainntnfs.SpendDetail{
		SpentOutPoint:  &inputOp,
		SpenderTxHash:  &spenderHash,
		SpendingTx:     spenderTx,
		SpendingHeight: 200,
	})
	reqNums := drainConfReqs(t, bridge)

	exportLog := &fakeExportLog{
		pkScripts: map[wire.OutPoint][]byte{
			inputOp: {txscript.OP_1},
		},
	}

	porter := NewChainPorter(&ChainPorterConfig{
		ExportLog:   exportLog,
		ChainBridge: bridge,
		SafeDepth:   safeDepth,
	})

	errCh := make(chan error, 1)
	go func() { errCh <- porter.waitForTransferTxConf(pkg) }()

	// The porter registers two conf ntfns: one on its own anchor, and
	// one on the spender for finality. Drain both before proceeding.
	var ownAnchorReq, spenderReq int
	select {
	case ownAnchorReq = <-reqNums:
	case <-time.After(time.Second):
		t.Fatal("own anchor conf ntfn was never registered")
	}
	select {
	case spenderReq = <-reqNums:
	case <-time.After(time.Second):
		t.Fatal("spender finality conf ntfn was never registered; " +
			"supersession is being decided on a single conf")
	}
	_ = spenderReq

	// At this point the 1-conf foreign spend has been observed and the
	// finality watch is in place; supersession must not have happened.
	require.Empty(t, exportLog.superseded)

	// Reorg the spend. The porter should drop the finality watch and
	// go back to waiting for its own anchor.
	bridge.SendSpendReorg(inputOp)

	// Now dispatch the own anchor's confirmation event.
	blockHash := chainhash.Hash{0x07}
	bridge.SendConfNtfn(ownAnchorReq, &blockHash, 123, 1, nil, anchorTx)

	select {
	case err := <-errCh:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("waitForTransferTxConf did not return after own " +
			"anchor confirmed post-reorg")
	}

	require.Empty(t, exportLog.superseded)
	require.Equal(t, SendStateStorePostAnchorTxConf, pkg.SendState)
	require.NotNil(t, pkg.TransferTxConfEvent)
	require.Equal(
		t, anchorTxHash, pkg.TransferTxConfEvent.Tx.TxHash(),
	)
}

// TestWaitForTransferTxConfSupersedesAtSafeDepth is the positive complement
// of the reorg-rescue test: when a conflicting spender does reach SafeDepth
// confirmations without being reorged out, supersession does fire.
func TestWaitForTransferTxConfSupersedesAtSafeDepth(t *testing.T) {
	t.Parallel()

	pkg, inputOp, spenderTx := newSpenderPkg(t)
	anchorTxHash := pkg.OutboundPkg.AnchorTx.TxHash()
	spenderHash := spenderTx.TxHash()

	const safeDepth = 3
	bridge := tapgarden.NewMockChainBridge()
	bridge.SetSpend(inputOp, &chainntnfs.SpendDetail{
		SpentOutPoint:  &inputOp,
		SpenderTxHash:  &spenderHash,
		SpendingTx:     spenderTx,
		SpendingHeight: 200,
	})
	reqNums := drainConfReqs(t, bridge)

	exportLog := &fakeExportLog{
		pkScripts: map[wire.OutPoint][]byte{
			inputOp: {txscript.OP_1},
		},
	}

	porter := NewChainPorter(&ChainPorterConfig{
		ExportLog:   exportLog,
		ChainBridge: bridge,
		SafeDepth:   safeDepth,
	})

	errCh := make(chan error, 1)
	go func() { errCh <- porter.waitForTransferTxConf(pkg) }()

	// Drain the own-anchor and spender-finality conf registrations.
	var spenderReq int
	select {
	case <-reqNums:
	case <-time.After(time.Second):
		t.Fatal("own anchor conf ntfn was never registered")
	}
	select {
	case spenderReq = <-reqNums:
	case <-time.After(time.Second):
		t.Fatal("spender finality conf ntfn was never registered")
	}

	// Fire the spender's SafeDepth-conf event.
	spenderBlock := chainhash.Hash{0x09}
	bridge.SendConfNtfn(
		spenderReq, &spenderBlock, 203, 1, nil, spenderTx,
	)

	select {
	case err := <-errCh:
		require.ErrorIs(t, err, ErrTransferSuperseded)
	case <-time.After(2 * time.Second):
		t.Fatal("waitForTransferTxConf did not return after spender " +
			"reached SafeDepth")
	}

	require.Equal(
		t, []chainhash.Hash{anchorTxHash}, exportLog.superseded,
	)
	require.Equal(
		t, [][]wire.OutPoint{{inputOp}}, exportLog.supersedeOps,
		"only the outpoint actually consumed on-chain by the "+
			"spender must be forwarded for spent-marking",
	)
}

// TestWaitForTransferTxConfRetriesOnSpenderRegistrationFailure verifies that
// a transient failure registering the SafeDepth conf watch on a conflicting
// spender does not silently strand the transfer. The spend event has
// already been consumed from the stream and will not re-fire absent another
// reorg, so the function must return a retryable (non-terminal) error so
// the outer backoff loop re-registers the whole watch set and redelivers
// the historical spend.
func TestWaitForTransferTxConfRetriesOnSpenderRegistrationFailure(
	t *testing.T) {

	t.Parallel()

	pkg, inputOp, spenderTx := newSpenderPkg(t)
	spenderHash := spenderTx.TxHash()

	const safeDepth = 3
	bridge := tapgarden.NewMockChainBridge()
	bridge.SetSpend(inputOp, &chainntnfs.SpendDetail{
		SpentOutPoint:  &inputOp,
		SpenderTxHash:  &spenderHash,
		SpendingTx:     spenderTx,
		SpendingHeight: 200,
	})

	// Arm the bridge to fail the next conf registration for the
	// spender specifically. Targeting by txid (rather than by count)
	// avoids racing against the porter's registration order.
	bridge.FailConfFor(spenderHash)

	exportLog := &fakeExportLog{
		pkScripts: map[wire.OutPoint][]byte{
			inputOp: {txscript.OP_1},
		},
	}

	porter := NewChainPorter(&ChainPorterConfig{
		ExportLog:   exportLog,
		ChainBridge: bridge,
		SafeDepth:   safeDepth,
	})

	// Drain conf registration signals in the background so the porter's
	// registrations don't block.
	go func() {
		for range bridge.ConfReqSignal {
		}
	}()

	confEvent, spender, terminal, err := porter.waitForConfEventOnce(
		context.Background(), pkg.OutboundPkg,
	)
	require.Error(t, err)
	require.ErrorContains(t, err, "watch finality")
	require.Nil(t, confEvent)
	require.Nil(t, spender)
	require.False(
		t, terminal, "spender registration failure must be "+
			"retryable, not terminal — silent stranding is the "+
			"failure mode the finality gate exists to prevent",
	)
	require.Empty(t, exportLog.superseded)
}

// TestWaitForTransferTxConfPerInputFinality covers the multi-input case
// where two inputs have distinct conflicting spenders. A reorg of one
// spender must not cancel the in-flight finality watch on the other, and
// the surviving spender must still drive supersession when it reaches
// SafeDepth. A single shared "pending spender" slot would lose this case:
// the second spend would cancel the first watch, and the subsequent reorg
// of the second would clear all state — leaving the first spender's
// supersession opportunity on the floor until restart.
func TestWaitForTransferTxConfPerInputFinality(t *testing.T) {
	t.Parallel()

	anchorTx := wire.NewMsgTx(2)
	anchorTx.AddTxIn(&wire.TxIn{})
	anchorTx.AddTxOut(&wire.TxOut{
		PkScript: bytes.Repeat([]byte{0x01}, 34),
		Value:    1000,
	})
	anchorTxHash := anchorTx.TxHash()

	opA := wire.OutPoint{Hash: chainhash.Hash{1}, Index: 0}
	opB := wire.OutPoint{Hash: chainhash.Hash{2}, Index: 1}

	mkSpenderTx := func(in wire.OutPoint, fillByte byte) *wire.MsgTx {
		tx := wire.NewMsgTx(2)
		tx.AddTxIn(&wire.TxIn{PreviousOutPoint: in})
		tx.AddTxOut(&wire.TxOut{
			PkScript: bytes.Repeat([]byte{fillByte}, 34),
			Value:    900,
		})
		return tx
	}
	spenderTxA := mkSpenderTx(opA, 0x0a)
	spenderTxB := mkSpenderTx(opB, 0x0b)
	spenderHashA := spenderTxA.TxHash()
	spenderHashB := spenderTxB.TxHash()

	pkg := &sendPackage{
		SendState: SendStateWaitTxConf,
		OutboundPkg: &OutboundParcel{
			AnchorTx:           anchorTx,
			AnchorTxHeightHint: 100,
			Inputs: []TransferInput{
				{PrevID: asset.PrevID{OutPoint: opA}},
				{PrevID: asset.PrevID{OutPoint: opB}},
			},
		},
	}

	const safeDepth = 3
	bridge := tapgarden.NewMockChainBridge()
	bridge.SetSpend(opA, &chainntnfs.SpendDetail{
		SpentOutPoint:  &opA,
		SpenderTxHash:  &spenderHashA,
		SpendingTx:     spenderTxA,
		SpendingHeight: 200,
	})
	bridge.SetSpend(opB, &chainntnfs.SpendDetail{
		SpentOutPoint:  &opB,
		SpenderTxHash:  &spenderHashB,
		SpendingTx:     spenderTxB,
		SpendingHeight: 200,
	})
	drainConfReqs(t, bridge)

	exportLog := &fakeExportLog{
		pkScripts: map[wire.OutPoint][]byte{
			opA: {txscript.OP_1},
			opB: {txscript.OP_1},
		},
	}

	porter := NewChainPorter(&ChainPorterConfig{
		ExportLog:   exportLog,
		ChainBridge: bridge,
		SafeDepth:   safeDepth,
	})

	errCh := make(chan error, 1)
	go func() { errCh <- porter.waitForTransferTxConf(pkg) }()

	// Wait until both finality watches have been registered. They are
	// independent so the order is not deterministic; poll the per-txid
	// map until both spenders show up.
	require.Eventually(t, func() bool {
		_, okA := bridge.ConfReqForTxid(spenderHashA)
		_, okB := bridge.ConfReqForTxid(spenderHashB)
		return okA && okB
	}, time.Second, 10*time.Millisecond,
		"both spender finality conf ntfns were never registered")

	// Reorg input B's spend. The porter must cancel only B's watch and
	// leave A's intact.
	bridge.SendSpendReorg(opB)

	// Give the porter a moment to process the reorg before firing A's
	// SafeDepth conf — the cancellation of B's watch is purely a
	// background side effect, not observable from the outside, so a
	// brief sleep is the most direct sync we have.
	time.Sleep(50 * time.Millisecond)

	reqA, ok := bridge.ConfReqForTxid(spenderHashA)
	require.True(t, ok)

	blockA := chainhash.Hash{0x0a}
	bridge.SendConfNtfn(reqA, &blockA, 203, 1, nil, spenderTxA)

	select {
	case err := <-errCh:
		require.ErrorIs(t, err, ErrTransferSuperseded)
	case <-time.After(2 * time.Second):
		t.Fatal("waitForTransferTxConf did not return after spender " +
			"A reached SafeDepth post-reorg of spender B")
	}

	require.Equal(
		t, []chainhash.Hash{anchorTxHash}, exportLog.superseded,
	)
	// Only A's outpoint must be forwarded for spent-marking: B's
	// spender was reorged out, so B's input is presumed unspent.
	require.Equal(
		t, [][]wire.OutPoint{{opA}}, exportLog.supersedeOps,
		"only the input consumed by the spender that reached "+
			"SafeDepth must be marked spent",
	)
}

// TestWaitForTransferTxConfRecoversPerInputSpendError verifies that a
// single per-input spend ntfn stream error is recovered by re-registering
// only that input's spend ntfn, without tearing down the confirmation
// watch or the other inputs' watches. A chronically-flapping per-input
// stream should not be able to block an imminent own-anchor confirmation,
// which would happen under the old "drop everything on any spend stream
// error" behaviour.
func TestWaitForTransferTxConfRecoversPerInputSpendError(t *testing.T) {
	t.Parallel()

	anchorTx := wire.NewMsgTx(2)
	anchorTx.AddTxIn(&wire.TxIn{})
	anchorTx.AddTxOut(&wire.TxOut{
		PkScript: bytes.Repeat([]byte{0x01}, 34),
		Value:    1000,
	})
	anchorTxHash := anchorTx.TxHash()

	opA := wire.OutPoint{Hash: chainhash.Hash{1}, Index: 0}
	opB := wire.OutPoint{Hash: chainhash.Hash{2}, Index: 1}

	pkg := &sendPackage{
		SendState: SendStateWaitTxConf,
		OutboundPkg: &OutboundParcel{
			AnchorTx:           anchorTx,
			AnchorTxHeightHint: 100,
			Inputs: []TransferInput{
				{PrevID: asset.PrevID{OutPoint: opA}},
				{PrevID: asset.PrevID{OutPoint: opB}},
			},
		},
	}

	bridge := tapgarden.NewMockChainBridge()
	reqNums := drainConfReqs(t, bridge)

	exportLog := &fakeExportLog{
		pkScripts: map[wire.OutPoint][]byte{
			opA: {txscript.OP_1},
			opB: {txscript.OP_1},
		},
	}

	porter := NewChainPorter(&ChainPorterConfig{
		ExportLog:   exportLog,
		ChainBridge: bridge,
		SafeDepth:   3,
	})

	errCh := make(chan error, 1)
	go func() { errCh <- porter.waitForTransferTxConf(pkg) }()

	// Wait for the own-anchor conf registration.
	var ownAnchorReq int
	select {
	case ownAnchorReq = <-reqNums:
	case <-time.After(time.Second):
		t.Fatal("own anchor conf ntfn was never registered")
	}

	// Fan a stream error into input A's spend ntfn. The porter must
	// re-register A's spend ntfn (without disturbing input B or the
	// own-anchor conf), so the test can then complete normally by
	// dispatching the own-anchor conf event.
	bridge.SendSpendErr(opA, fmt.Errorf("transient stream blip"))

	// Give the porter a moment to react to the per-input error. The
	// re-registration is purely a background side effect — no
	// observable signal — so a brief sleep is the most direct sync.
	time.Sleep(50 * time.Millisecond)

	// Dispatch the own-anchor conf event. If the per-input error had
	// torn down the entire watch (as in the pre-fix behaviour), this
	// SendConfNtfn would block forever because the registered req has
	// been cancelled.
	blockHash := chainhash.Hash{0x07}
	bridge.SendConfNtfn(ownAnchorReq, &blockHash, 123, 1, nil, anchorTx)

	select {
	case err := <-errCh:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("waitForTransferTxConf did not return after own " +
			"anchor confirmed; per-input spend error likely " +
			"tore down the conf watch")
	}

	require.Empty(t, exportLog.superseded,
		"the spend stream error must not cause supersession")
	require.Equal(t, SendStateStorePostAnchorTxConf, pkg.SendState)
	require.NotNil(t, pkg.TransferTxConfEvent)
	require.Equal(
		t, anchorTxHash, pkg.TransferTxConfEvent.Tx.TxHash(),
	)
}
