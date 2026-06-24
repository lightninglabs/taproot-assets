package tapfreighter

import (
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
