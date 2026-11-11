package tapfreighter

import (
	"context"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btclog/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
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

// stubProofArchive reports which input outpoints it holds and records the
// proofs imported into it.
type stubProofArchive struct {
	held     map[wire.OutPoint]bool
	imported []proof.VerifiedAnnotatedProof
}

func (s *stubProofArchive) HasProof(_ context.Context,
	id proof.Locator) (bool, error) {

	return s.held[*id.OutPoint], nil
}

func (s *stubProofArchive) ImportVerifiedProofs(_ context.Context, _ bool,
	proofs ...proof.VerifiedAnnotatedProof) error {

	s.imported = append(s.imported, proofs...)
	return nil
}

// countingProofExporter serves one result for every locator and counts the
// lookups.
type countingProofExporter struct {
	blob  proof.Blob
	err   error
	calls int
}

func (c *countingProofExporter) FetchProof(_ context.Context,
	_ proof.Locator) (proof.Blob, error) {

	c.calls++
	return c.blob, c.err
}

// TestArchiveInputProofs checks which input proofs are copied into the file
// archive before a transfer is stored.
func TestArchiveInputProofs(t *testing.T) {
	t.Parallel()

	prevID := asset.PrevID{
		OutPoint:  test.RandOp(t),
		ID:        asset.RandID(t),
		ScriptKey: asset.ToSerialized(test.RandPubKey(t)),
	}
	pkg := &sendPackage{
		VirtualPackets: []*tappsbt.VPacket{{
			Inputs: []*tappsbt.VInput{
				{PrevID: prevID},
				{PrevID: prevID},
			},
		}},
	}

	testCases := []struct {
		name      string
		inWallet  bool
		archived  bool
		reader    *countingProofExporter
		wantErr   error
		wantCalls int
	}{{
		name:     "wallet input is not archived",
		inWallet: true,
		reader:   &countingProofExporter{},
	}, {
		name:     "archived input is not fetched",
		archived: true,
		reader:   &countingProofExporter{},
	}, {
		name: "missing input proof fails",
		reader: &countingProofExporter{
			err: proof.ErrProofNotFound,
		},
		wantErr:   proof.ErrProofNotFound,
		wantCalls: 1,
	}, {
		name: "undecodable input proof is not archived",
		reader: &countingProofExporter{
			blob: []byte{0x01},
		},
		wantCalls: 1,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			archive := &stubProofArchive{
				held: map[wire.OutPoint]bool{
					prevID.OutPoint: tc.archived,
				},
			}
			wallet := &countingProofExporter{
				err: proof.ErrProofNotFound,
			}
			if tc.inWallet {
				wallet = &countingProofExporter{
					blob: []byte{0x02},
				}
			}
			porter := NewChainPorter(&ChainPorterConfig{
				ProofWriter:  archive,
				ProofReader:  tc.reader,
				WalletProofs: wallet,
			})

			err := porter.archiveInputProofs(t.Context(), pkg)
			switch {
			case tc.wantErr != nil:
				require.ErrorIs(t, err, tc.wantErr)

			// The test proofs do not decode, so every proof that
			// reaches verification fails it.
			case tc.wantCalls > 0:
				require.ErrorContains(t, err, "verifying")

			default:
				require.NoError(t, err)
			}
			require.Equal(t, tc.wantCalls, tc.reader.calls)
			require.Equal(t, 1, wallet.calls)
			require.Empty(t, archive.imported)
		})
	}
}
