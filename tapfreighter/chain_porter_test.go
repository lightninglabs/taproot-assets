package tapfreighter

import (
	"context"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btclog/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/tapsend"
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

// mockChainLookup is a simple mock for asset.ChainLookup that allows
// controlling return values for timelock tests.
type mockChainLookup struct {
	txBlockHeight uint32
	meanTime      time.Time
}

func (m *mockChainLookup) CurrentHeight(context.Context) (uint32, error) {
	return 0, nil
}

func (m *mockChainLookup) TxBlockHeight(context.Context,
	chainhash.Hash) (uint32, error) {

	return m.txBlockHeight, nil
}

func (m *mockChainLookup) MeanBlockTimestamp(context.Context,
	uint32) (time.Time, error) {

	return m.meanTime, nil
}

// mockChainBridgeForTimelocks wraps tapgarden.MockChainBridge but returns
// a custom ChainLookup for testing.
type mockChainBridgeForTimelocks struct {
	*tapgarden.MockChainBridge
	chainLookup asset.ChainLookup
}

func (m *mockChainBridgeForTimelocks) GenProofChainLookup(
	*proof.Proof) (asset.ChainLookup, error) {

	return m.chainLookup, nil
}

// TestVerifyAssetTimelocks exercises the asset timelock verification with
// table-driven vPacket fixtures.
func TestVerifyAssetTimelocks(t *testing.T) {
	t.Parallel()

	// Helper to keep lines under 80 chars.
	testOutPoint := wire.OutPoint{Hash: chainhash.Hash{1}}

	// Default mock chain lookup with input tx confirmed at height 100.
	defaultChainLookup := &mockChainLookup{
		txBlockHeight: 100,
		meanTime:      time.Now(),
	}

	testCases := []struct {
		name        string
		blockHeight uint32
		packets     func() []*tappsbt.VPacket
		chainLookup asset.ChainLookup
		expectError bool
		errContains string // expected substring in error message
	}{
		{
			name:        "no timelocks passes",
			blockHeight: 200,
			packets: func() []*tappsbt.VPacket {
				a := &asset.Asset{
					LockTime:         0,
					RelativeLockTime: 0,
					PrevWitnesses: []asset.Witness{{
						PrevID: &asset.PrevID{
							OutPoint: testOutPoint,
						},
					}},
				}
				return []*tappsbt.VPacket{{
					Inputs: []*tappsbt.VInput{{
						Proof: &proof.Proof{},
					}},
					Outputs: []*tappsbt.VOutput{{
						Asset: a,
					}},
				}}
			},
			chainLookup: defaultChainLookup,
			expectError: false,
		},
		{
			name:        "nil asset output passes (skipped)",
			blockHeight: 200,
			packets: func() []*tappsbt.VPacket {
				return []*tappsbt.VPacket{{
					Inputs: []*tappsbt.VInput{{
						Proof: &proof.Proof{},
					}},
					Outputs: []*tappsbt.VOutput{{
						Asset: nil,
					}},
				}}
			},
			chainLookup: defaultChainLookup,
			expectError: false,
		},
		{
			name:        "absolute locktime satisfied passes",
			blockHeight: 150,
			packets: func() []*tappsbt.VPacket {
				a := &asset.Asset{
					LockTime:         100,
					RelativeLockTime: 0,
					PrevWitnesses: []asset.Witness{{
						PrevID: &asset.PrevID{
							OutPoint: testOutPoint,
						},
					}},
				}
				return []*tappsbt.VPacket{{
					Inputs: []*tappsbt.VInput{{
						Proof: &proof.Proof{},
					}},
					Outputs: []*tappsbt.VOutput{{
						Asset: a,
					}},
				}}
			},
			chainLookup: defaultChainLookup,
			expectError: false,
		},
		{
			name:        "absolute locktime at height passes",
			blockHeight: 100,
			packets: func() []*tappsbt.VPacket {
				a := &asset.Asset{
					LockTime:         100,
					RelativeLockTime: 0,
					PrevWitnesses: []asset.Witness{{
						PrevID: &asset.PrevID{
							OutPoint: testOutPoint,
						},
					}},
				}
				return []*tappsbt.VPacket{{
					Inputs: []*tappsbt.VInput{{
						Proof: &proof.Proof{},
					}},
					Outputs: []*tappsbt.VOutput{{
						Asset: a,
					}},
				}}
			},
			chainLookup: defaultChainLookup,
			expectError: false,
		},
		{
			name:        "absolute locktime not satisfied fails",
			blockHeight: 99,
			packets: func() []*tappsbt.VPacket {
				a := &asset.Asset{
					LockTime:         100,
					RelativeLockTime: 0,
					PrevWitnesses: []asset.Witness{{
						PrevID: &asset.PrevID{
							OutPoint: testOutPoint,
						},
					}},
				}
				return []*tappsbt.VPacket{{
					Inputs: []*tappsbt.VInput{{
						Proof: &proof.Proof{},
					}},
					Outputs: []*tappsbt.VOutput{{
						Asset: a,
					}},
				}}
			},
			chainLookup: defaultChainLookup,
			expectError: true,
			errContains: "asset timelock not satisfied",
		},
		{
			name:        "relative locktime satisfied passes",
			blockHeight: 120, // input at 100, relative lock of 10
			packets: func() []*tappsbt.VPacket {
				a := &asset.Asset{
					LockTime:         0,
					RelativeLockTime: 10,
					PrevWitnesses: []asset.Witness{{
						PrevID: &asset.PrevID{
							OutPoint: testOutPoint,
						},
					}},
				}
				return []*tappsbt.VPacket{{
					Inputs: []*tappsbt.VInput{{
						Proof: &proof.Proof{},
					}},
					Outputs: []*tappsbt.VOutput{{
						Asset: a,
					}},
				}}
			},
			chainLookup: defaultChainLookup,
			expectError: false,
		},
		{
			name:        "relative locktime not satisfied fails",
			blockHeight: 105, // input at 100, relative lock of 10
			packets: func() []*tappsbt.VPacket {
				a := &asset.Asset{
					LockTime:         0,
					RelativeLockTime: 10,
					PrevWitnesses: []asset.Witness{{
						PrevID: &asset.PrevID{
							OutPoint: testOutPoint,
						},
					}},
				}
				return []*tappsbt.VPacket{{
					Inputs: []*tappsbt.VInput{{
						Proof: &proof.Proof{},
					}},
					Outputs: []*tappsbt.VOutput{{
						Asset: a,
					}},
				}}
			},
			chainLookup: defaultChainLookup,
			expectError: true,
			errContains: "asset timelock not satisfied",
		},
		{
			name:        "timestamp locktime satisfied passes",
			blockHeight: 200,
			packets: func() []*tappsbt.VPacket {
				// Use a timestamp above the threshold.
				// The mock returns time.Now() which should
				// be well past this old timestamp.
				threshold := txscript.LockTimeThreshold
				timestampLock := threshold + 1000
				a := &asset.Asset{
					LockTime:         uint64(timestampLock),
					RelativeLockTime: 0,
					PrevWitnesses: []asset.Witness{{
						PrevID: &asset.PrevID{
							OutPoint: testOutPoint,
						},
					}},
				}
				return []*tappsbt.VPacket{{
					Inputs: []*tappsbt.VInput{{
						Proof: &proof.Proof{},
					}},
					Outputs: []*tappsbt.VOutput{{
						Asset: a,
					}},
				}}
			},
			chainLookup: defaultChainLookup,
			expectError: false,
		},
		{
			name:        "no proof height-based locktime passes",
			blockHeight: 150,
			packets: func() []*tappsbt.VPacket {
				// Height-based absolute locks don't need
				// chainLookup, only the blockHeight.
				a := &asset.Asset{
					LockTime:         100,
					RelativeLockTime: 0,
					PrevWitnesses: []asset.Witness{{
						PrevID: &asset.PrevID{
							OutPoint: testOutPoint,
						},
					}},
				}
				// No inputs with proofs.
				return []*tappsbt.VPacket{{
					Inputs: []*tappsbt.VInput{},
					Outputs: []*tappsbt.VOutput{{
						Asset: a,
					}},
				}}
			},
			chainLookup: defaultChainLookup,
			expectError: false,
		},
		{
			name:        "no proof with relative locktime fails",
			blockHeight: 120,
			packets: func() []*tappsbt.VPacket {
				// Relative locks require chainLookup for
				// TxBlockHeight, so missing proof should fail.
				a := &asset.Asset{
					LockTime:         0,
					RelativeLockTime: 10,
					PrevWitnesses: []asset.Witness{{
						PrevID: &asset.PrevID{
							OutPoint: testOutPoint,
						},
					}},
				}
				// No inputs with proofs.
				return []*tappsbt.VPacket{{
					Inputs: []*tappsbt.VInput{},
					Outputs: []*tappsbt.VOutput{{
						Asset: a,
					}},
				}}
			},
			chainLookup: defaultChainLookup,
			expectError: true,
			errContains: "no input proof available",
		},
		{
			name:        "no proof timestamp locktime fails",
			blockHeight: 200,
			packets: func() []*tappsbt.VPacket {
				// Timestamp-based locks require chainLookup for
				// MeanBlockTimestamp, so missing proof fails.
				threshold := txscript.LockTimeThreshold
				timestampLock := threshold + 1000
				a := &asset.Asset{
					LockTime:         uint64(timestampLock),
					RelativeLockTime: 0,
					PrevWitnesses: []asset.Witness{{
						PrevID: &asset.PrevID{
							OutPoint: testOutPoint,
						},
					}},
				}
				// No inputs with proofs.
				return []*tappsbt.VPacket{{
					Inputs: []*tappsbt.VInput{},
					Outputs: []*tappsbt.VOutput{{
						Asset: a,
					}},
				}}
			},
			chainLookup: defaultChainLookup,
			expectError: true,
			errContains: "no input proof available",
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mockBridge := &mockChainBridgeForTimelocks{
				MockChainBridge: tapgarden.NewMockChainBridge(),
				chainLookup:     tc.chainLookup,
			}

			porter := &ChainPorter{
				cfg: &ChainPorterConfig{
					ChainBridge: mockBridge,
				},
			}

			ctx := context.Background()
			err := porter.verifyAssetTimelocks(
				ctx, tc.packets(), tc.blockHeight,
			)

			if tc.expectError {
				require.Error(t, err)
				if tc.errContains != "" {
					require.Contains(t, err.Error(),
						tc.errContains)
				}
				return
			}

			require.NoError(t, err)
		})
	}
}

// TestVerifyAnchorTimeLocks exercises the BTC anchor timelock verification.
func TestVerifyAnchorTimeLocks(t *testing.T) {
	t.Parallel()

	// Helper values and functions to keep lines under 80 chars.
	op := wire.OutPoint{Hash: chainhash.Hash{1}}
	maxSeq := wire.MaxTxInSequenceNum
	csvOff := uint32(wire.SequenceLockTimeDisabled)
	csvSec := uint32(wire.SequenceLockTimeIsSeconds)

	mkAnchor := func(lt uint32, seq uint32) *tapsend.AnchorTransaction {
		return &tapsend.AnchorTransaction{
			FinalTx: &wire.MsgTx{
				LockTime: lt,
				TxIn: []*wire.TxIn{{
					PreviousOutPoint: op, Sequence: seq,
				}},
			},
		}
	}

	mkPktAbs := func(lockTime uint64) []*tappsbt.VPacket {
		return []*tappsbt.VPacket{{
			Outputs: []*tappsbt.VOutput{{
				LockTime: lockTime,
				Asset:    &asset.Asset{},
			}},
		}}
	}

	mkPktRel := func(relLock uint64) []*tappsbt.VPacket {
		prevID := &asset.PrevID{OutPoint: op}
		return []*tappsbt.VPacket{{
			Outputs: []*tappsbt.VOutput{{
				RelativeLockTime: relLock,
				Asset: &asset.Asset{
					PrevWitnesses: []asset.Witness{{
						PrevID: prevID,
					}},
				},
			}},
		}}
	}

	testCases := []struct {
		name        string
		anchorTx    *tapsend.AnchorTransaction
		packets     []*tappsbt.VPacket
		expectError bool
		errContains string
	}{
		{
			name:        "nil anchor tx passes",
			anchorTx:    nil,
			packets:     []*tappsbt.VPacket{},
			expectError: false,
		},
		{
			name:     "no timelocks passes",
			anchorTx: mkAnchor(0, maxSeq),
			packets: []*tappsbt.VPacket{{
				Outputs: []*tappsbt.VOutput{{
					Asset: &asset.Asset{},
				}},
			}},
			expectError: false,
		},
		{
			name:        "abs locktime matching nLockTime passes",
			anchorTx:    mkAnchor(100, maxSeq-1),
			packets:     mkPktAbs(100),
			expectError: false,
		},
		{
			name:        "abs locktime low nLockTime fails",
			anchorTx:    mkAnchor(50, maxSeq-1),
			packets:     mkPktAbs(100),
			expectError: true,
			errContains: "nLockTime",
		},
		{
			name:        "abs locktime unenforced max seq fails",
			anchorTx:    mkAnchor(100, maxSeq),
			packets:     mkPktAbs(100),
			expectError: true,
			errContains: "all inputs have max sequence",
		},
		{
			name:        "rel locktime matching sequence passes",
			anchorTx:    mkAnchor(0, 10),
			packets:     mkPktRel(10),
			expectError: false,
		},
		{
			name:        "rel locktime insufficient sequence fails",
			anchorTx:    mkAnchor(0, 5),
			packets:     mkPktRel(10),
			expectError: true,
			errContains: "sequence",
		},
		{
			name:        "relative locktime CSV disabled fails",
			anchorTx:    mkAnchor(0, csvOff|10),
			packets:     mkPktRel(10),
			expectError: true,
			errContains: "CSV disabled",
		},
		{
			name:        "relative locktime type mismatch fails",
			anchorTx:    mkAnchor(0, 10),
			packets:     mkPktRel(uint64(csvSec | 10)),
			expectError: true,
			errContains: "type mismatch",
		},
		{
			name:        "seconds-based relative locktime passes",
			anchorTx:    mkAnchor(0, csvSec|10),
			packets:     mkPktRel(uint64(csvSec | 10)),
			expectError: false,
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := verifyAnchorTimeLocks(tc.anchorTx, tc.packets)

			if tc.expectError {
				require.Error(t, err)
				if tc.errContains != "" {
					require.Contains(
						t, err.Error(), tc.errContains,
					)
				}
				return
			}

			require.NoError(t, err)
		})
	}
}
