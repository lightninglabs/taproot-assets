package tapfreighter

import (
	"errors"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btclog/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/diagnostics"
	"github.com/lightninglabs/taproot-assets/tappsbt"
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

func TestBuildPreBroadcastProofFailureReport(t *testing.T) {
	t.Parallel()

	inputProofs := []diagnostics.ArtifactFile{
		{
			FileName: "input-proof-0.bin",
			Data:     []byte{1, 2, 3},
		},
	}

	report := buildPreBroadcastProofFailureReport(
		errors.New("boom"), 4, 7, []byte{9, 9}, inputProofs,
	)

	require.Equal(
		t, diagnostics.StageProofVerificationPreBroadcast,
		report.Stage,
	)
	require.Equal(t, "boom", report.Error)
	require.NotNil(t, report.VPacketIndex)
	require.Equal(t, 4, *report.VPacketIndex)
	require.NotNil(t, report.VPacketOutputIndex)
	require.Equal(t, 7, *report.VPacketOutputIndex)
	require.Len(t, report.OutputProofs, 1)
	require.Equal(t, "output-proof.bin", report.OutputProofs[0].FileName)
	require.Equal(t, []byte{9, 9}, report.OutputProofs[0].Data)
	require.Len(t, report.InputProofs, 1)
}

func TestBuildPostBroadcastProofFailureReport(t *testing.T) {
	t.Parallel()

	inputProofs := []diagnostics.ArtifactFile{
		{
			FileName: "input-proof-0.bin",
			Data:     []byte{1, 2, 3},
		},
	}

	report := buildPostBroadcastProofFailureReport(
		errors.New("verify failed"), "abcd", 2, []byte{7, 8},
		inputProofs,
	)

	require.Equal(
		t, diagnostics.StageProofVerificationPostBroadcast,
		report.Stage,
	)
	require.Equal(t, "verify failed", report.Error)
	require.Equal(t, "abcd", report.AnchorTxID)
	require.NotNil(t, report.TransferOutputIndex)
	require.Equal(t, 2, *report.TransferOutputIndex)
	require.Len(t, report.OutputProofs, 1)
	require.Equal(t, "output-proof-2.bin", report.OutputProofs[0].FileName)
	require.Equal(t, []byte{7, 8}, report.OutputProofs[0].Data)
	require.Len(t, report.InputProofs, 1)
}
