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
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
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
	newPkg := func(supplied proof.Blob) *sendPackage {
		pkg := &sendPackage{
			VirtualPackets: []*tappsbt.VPacket{{
				Inputs: []*tappsbt.VInput{
					{PrevID: prevID},
					{PrevID: prevID},
				},
			}},
		}
		if supplied != nil {
			pkg.InputProofs = map[asset.PrevID]proof.Blob{
				prevID: supplied,
			}
		}

		return pkg
	}
	notFound := &countingProofExporter{err: proof.ErrProofNotFound}

	testCases := []struct {
		name      string
		inWallet  bool
		archived  bool
		supplied  proof.Blob
		reader    *countingProofExporter
		wantErr   error
		wantCalls int
	}{{
		name:     "wallet input is not archived",
		inWallet: true,
		supplied: []byte{0x01},
		reader:   &countingProofExporter{},
	}, {
		name:     "archived input is not fetched",
		archived: true,
		reader:   &countingProofExporter{},
	}, {
		name:      "missing input proof fails",
		reader:    notFound,
		wantErr:   proof.ErrProofNotFound,
		wantCalls: 1,
	}, {
		name: "undecodable input proof is not archived",
		reader: &countingProofExporter{
			blob: []byte{0x01},
		},
		wantCalls: 1,
	}, {
		name:     "supplied proof replaces archived copy",
		archived: true,
		supplied: []byte{0x01},
		reader:   &countingProofExporter{},
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
			reader := *tc.reader
			porter := NewChainPorter(&ChainPorterConfig{
				ProofWriter:  archive,
				ProofReader:  &reader,
				WalletProofs: wallet,
			})

			err := porter.archiveInputProofs(
				t.Context(), newPkg(tc.supplied),
			)
			wantVerify := tc.wantCalls > 0 ||
				(tc.supplied != nil && !tc.inWallet)
			switch {
			case tc.wantErr != nil:
				require.ErrorIs(t, err, tc.wantErr)

			// The test proofs do not decode, so every proof that
			// reaches verification fails it.
			case wantVerify:
				require.ErrorContains(t, err, "verifying")

			default:
				require.NoError(t, err)
			}
			require.Equal(t, tc.wantCalls, reader.calls)
			require.Equal(t, 1, wallet.calls)
			require.Empty(t, archive.imported)
		})
	}
}

// TestFetchInputProofBlob checks the order in which the sources of an input
// proof are consulted.
func TestFetchInputProofBlob(t *testing.T) {
	t.Parallel()

	prevID := asset.PrevID{
		OutPoint:  test.RandOp(t),
		ID:        asset.RandID(t),
		ScriptKey: asset.ToSerialized(test.RandPubKey(t)),
	}
	locator, err := inputProofLocator(prevID)
	require.NoError(t, err)

	var (
		walletProof   = proof.Blob{0x01}
		archivedProof = proof.Blob{0x02}
		suppliedProof = proof.Blob{0x03}
	)
	testCases := []struct {
		name     string
		inWallet bool
		supplied bool
		want     proof.Blob
	}{{
		name: "archive without a supplied proof",
		want: archivedProof,
	}, {
		name:     "supplied proof over the archive",
		supplied: true,
		want:     suppliedProof,
	}, {
		name:     "wallet proof over a supplied proof",
		inWallet: true,
		supplied: true,
		want:     walletProof,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			wallet := &countingProofExporter{
				err: proof.ErrProofNotFound,
			}
			if tc.inWallet {
				wallet = &countingProofExporter{
					blob: walletProof,
				}
			}
			porter := NewChainPorter(&ChainPorterConfig{
				ProofReader: &countingProofExporter{
					blob: archivedProof,
				},
				WalletProofs: wallet,
			})

			var supplied map[asset.PrevID]proof.Blob
			if tc.supplied {
				supplied = map[asset.PrevID]proof.Blob{
					prevID: suppliedProof,
				}
			}
			blob, err := porter.fetchInputProofBlob(
				t.Context(), locator, prevID, supplied,
			)
			require.NoError(t, err)
			require.Equal(t, tc.want, blob)
		})
	}
}

// TestPreAnchoredParcelInputProofs checks that a parcel accepts supplied
// proofs only for its own inputs.
func TestPreAnchoredParcelInputProofs(t *testing.T) {
	t.Parallel()

	prevID := asset.PrevID{
		OutPoint:  test.RandOp(t),
		ID:        asset.RandID(t),
		ScriptKey: asset.ToSerialized(test.RandPubKey(t)),
	}
	vPkt := &tappsbt.VPacket{
		Inputs:  []*tappsbt.VInput{{PrevID: prevID}},
		Outputs: []*tappsbt.VOutput{{}},
		Version: tappsbt.V1,
	}
	anchorTx := &tapsend.AnchorTransaction{
		FundedPsbt: &tapsend.FundedPsbt{},
		FinalTx:    wire.NewMsgTx(2),
	}
	newParcel := func(id asset.PrevID) *PreAnchoredParcel {
		return NewPreAnchoredParcel(
			[]*tappsbt.VPacket{vPkt}, nil, anchorTx, false, "",
			fn.None[uint32](), WithInputProofs(
				map[asset.PrevID]proof.Blob{id: {0x01}},
			),
		)
	}

	parcel := newParcel(prevID)
	require.NoError(t, parcel.Validate())
	require.Equal(
		t, proof.Blob{0x01}, parcel.pkg().InputProofs[prevID],
	)

	other := prevID
	other.OutPoint = test.RandOp(t)
	require.ErrorContains(
		t, newParcel(other).Validate(), "does not match a transfer "+
			"input",
	)
}
