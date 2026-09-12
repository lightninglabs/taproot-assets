package tapfreighter

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapreorg"
	"github.com/stretchr/testify/require"
)

// stubProofExporter serves one encoded proof file for any locator.
type stubProofExporter struct {
	blob proof.Blob
}

func (s *stubProofExporter) FetchProof(_ context.Context,
	_ proof.Locator) (proof.Blob, error) {

	return s.blob, nil
}

// TestResumedParcelAdoptsAnchoring covers the resume path for a
// transfer written before the anchoring watcher existed: no anchoring
// exists for its anchor transaction, and waiting on its outcome must
// adopt a fresh one — trigger scripts recovered from the inputs'
// proof files — rather than failing terminally on every restart. The
// wait state is driven as the state machine drives it, so the package
// it hands on is asserted too: send-event subscribers read the anchor
// block context off it.
func TestResumedParcelAdoptsAnchoring(t *testing.T) {
	t.Parallel()

	// The input asset's proof file: its tip proof anchors the input
	// at output 1 of its own anchor transaction, carrying the
	// pkScript the adoption must recover.
	inputPkScript := append(
		[]byte{0x51, 0x20}, bytes.Repeat([]byte{0xaa}, 32)...,
	)
	inputAnchorTx := wire.NewMsgTx(2)
	inputAnchorTx.AddTxIn(wire.NewTxIn(&wire.OutPoint{}, nil, nil))
	inputAnchorTx.AddTxOut(&wire.TxOut{Value: 1_000})
	inputAnchorTx.AddTxOut(&wire.TxOut{
		Value:    1_000,
		PkScript: inputPkScript,
	})
	inputBlock := wire.MsgBlock{
		Transactions: []*wire.MsgTx{inputAnchorTx},
	}
	inputProof := proof.RandProof(
		t, asset.RandGenesis(t, asset.Normal), test.RandPubKey(t),
		inputBlock, 0, 1,
	)

	file, err := proof.NewFile(proof.V0, inputProof)
	require.NoError(t, err)
	var fileBuf bytes.Buffer
	require.NoError(t, file.Encode(&fileBuf))

	inputOutPoint := inputProof.OutPoint()
	prevID := asset.PrevID{
		OutPoint: inputOutPoint,
		ID:       inputProof.Asset.ID(),
		ScriptKey: asset.ToSerialized(
			inputProof.Asset.ScriptKey.PubKey,
		),
	}

	// The resumed transfer spends that input.
	anchorTx := wire.NewMsgTx(2)
	anchorTx.AddTxIn(wire.NewTxIn(&inputOutPoint, nil, nil))
	anchorTx.AddTxOut(&wire.TxOut{Value: 900, PkScript: []byte{0x51}})
	anchorTxid := anchorTx.TxHash()

	registrar := tapreorg.NewMockRegistrar()
	porter := NewChainPorter(&ChainPorterConfig{
		AnchoringWatcher:   registrar,
		ProofReader:        &stubProofExporter{blob: fileBuf.Bytes()},
		AnchoringThreshold: 6,
	})

	pkg := &sendPackage{
		SendState: SendStateWaitTxConf,
		OutboundPkg: &OutboundParcel{
			AnchorTx:           anchorTx,
			AnchorTxHeightHint: 100,
			Inputs: []TransferInput{{
				PrevID: prevID,
				Amount: 1,
			}},
		},
	}

	// Without an anchoring, the identity lookup reports the typed
	// miss the wait path branches on.
	ctx := context.Background()
	_, err = porter.findAnchoring(ctx, anchorTxid)
	require.ErrorIs(t, err, ErrNoParcelAnchoring)

	// Drive the wait state. It must adopt an anchoring and then block
	// for the (mock) watcher's outcome, not fail.
	type waitResult struct {
		pkg *sendPackage
		err error
	}
	resultChan := make(chan waitResult, 1)
	go func() {
		updated, err := porter.stateStep(*pkg)
		resultChan <- waitResult{pkg: updated, err: err}
	}()

	// The adoption lands in the registrar with the parcel's
	// essential identity and the proof-recovered trigger.
	var adopted *tapreorg.Anchoring
	require.Eventually(t, func() bool {
		select {
		case result := <-resultChan:
			t.Fatalf("wait resolved before delivery: %v",
				result.err)
		default:
		}

		adopted, err = registrar.LookupByMatchKey(
			ctx, PorterSiteID, anchorTxid.CloneBytes(),
		)
		require.NoError(t, err)

		return adopted != nil
	}, 5*time.Second, 10*time.Millisecond)

	triggers := adopted.Triggers.OutPoints()
	require.Len(t, triggers, 1)
	require.Equal(t, inputOutPoint, triggers[0].OutPoint)
	require.Equal(t, inputPkScript, triggers[0].PkScript)
	require.Equal(t, uint32(100), triggers[0].HeightHint)
	require.Equal(t, uint32(6), adopted.Threshold)

	// The mock watcher witnesses the spend and delivers, the way
	// sensing and delivery would; the resumed parcel's wait then
	// resolves to a positive outcome.
	blockHash := chainhash.Hash{0xcc}
	confirmed, err := registrar.ConfirmSpend(
		anchorTx, blockHash, 700, 0, wire.BlockHeader{Nonce: 1},
		proof.TxMerkleProof{},
	)
	require.NoError(t, err)
	require.Equal(t, 1, confirmed)

	deadline := time.After(5 * time.Second)
	for {
		select {
		case result := <-resultChan:
			require.NoError(t, result.err)
			updated := result.pkg
			require.NotNil(t, updated.ConfWitness)
			require.Equal(
				t, SendStateStorePostAnchorTxConf,
				updated.SendState,
			)
			require.Equal(t, adopted.ID, updated.AnchoringID)

			// The package carries the anchor block context on
			// to the send event published for this state.
			event := newAssetSendEvent(
				SendStateWaitTxConf, *updated,
			)
			require.Equal(
				t, fn.Some(blockHash),
				event.Transfer.AnchorTxBlockHash,
			)
			require.Equal(
				t, uint32(700),
				event.Transfer.AnchorTxBlockHeight,
			)

			// A second resolution finds the adopted anchoring
			// rather than registering another.
			again, err := porter.findAnchoring(ctx, anchorTxid)
			require.NoError(t, err)
			require.Equal(t, adopted.ID, again.ID)

			return

		case <-deadline:
			t.Fatal("resumed parcel wait did not resolve")

		case <-time.After(10 * time.Millisecond):
			// The waiter's nudge channel may not exist yet
			// when the mock delivers, so keep nudging the way
			// repeated deliveries would.
			porter.OnAnchoringDelivered(
				adopted.ID, PorterSiteID, adopted.Phase,
			)
		}
	}
}
