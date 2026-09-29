package tapfreighter

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapnode"
	"github.com/lightninglabs/taproot-assets/tapreorg"
	"github.com/stretchr/testify/require"
)

// stubProofExporter serves one encoded proof file for any locator.
type stubProofExporter struct {
	blob proof.Blob
}

type blockByHeightBridge struct {
	tapnode.ChainBridge

	block *wire.MsgBlock
	err   error
	calls int
}

func (b *blockByHeightBridge) GetBlockByHeight(_ context.Context,
	_ int64) (*wire.MsgBlock, error) {

	b.calls++
	if b.err != nil {
		return nil, b.err
	}

	return b.block, nil
}

// stubExportLog serves a fixed parcel set to the startup adoption pass and
// records the floor it was asked for.
type stubExportLog struct {
	ExportLog

	parcels []*OutboundParcel
	floor   uint32
}

func (s *stubExportLog) ParcelsForAdoption(_ context.Context,
	minBlockHeight uint32) ([]*OutboundParcel, error) {

	s.floor = minBlockHeight
	return s.parcels, nil
}

func (s *stubProofExporter) FetchProof(_ context.Context,
	_ proof.Locator) (proof.Blob, error) {

	return s.blob, nil
}

// TestConfirmedParcelSeed asserts that legacy porter adoption begins from the
// confirmed state already represented on disk, with complete proof-repair
// evidence, and shares one block lookup across parcels at the same height.
func TestConfirmedParcelSeed(t *testing.T) {
	t.Parallel()

	anchorTx := wire.NewMsgTx(2)
	anchorTx.AddTxIn(wire.NewTxIn(&wire.OutPoint{}, nil, nil))
	anchorTx.AddTxOut(wire.NewTxOut(1_000, []byte{0x51}))
	block := &wire.MsgBlock{
		Header: wire.BlockHeader{Version: 1},
		Transactions: []*wire.MsgTx{
			wire.NewMsgTx(2), anchorTx,
		},
	}
	bridge := &blockByHeightBridge{block: block}
	porter := NewChainPorter(&ChainPorterConfig{ChainBridge: bridge})
	blockHash := block.BlockHash()
	parcel := &OutboundParcel{
		AnchorTx:            anchorTx,
		AnchorTxBlockHash:   fn.Some(blockHash),
		AnchorTxBlockHeight: 101,
		AnchorTxHeightHint:  99,
	}

	cache := make(map[uint32]*wire.MsgBlock)
	seed, err := porter.confirmedParcelSeed(
		context.Background(), parcel, cache,
	)
	require.NoError(t, err)
	require.Equal(t, anchorTx.TxHash(), seed.W.TxHash())
	require.Equal(t, blockHash, seed.W.BlockHash())
	require.EqualValues(t, 101, seed.W.Height())
	require.EqualValues(t, 1, seed.W.TxIndex())
	require.NotNil(t, seed.BlockHeader)
	require.NotNil(t, seed.MerkleProof)
	require.Equal(t, 1, bridge.calls)

	_, err = porter.confirmedParcelSeed(
		context.Background(), parcel, cache,
	)
	require.NoError(t, err)
	require.Equal(t, 1, bridge.calls)
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

// TestAdoptLegacyParcelsSeedFallback asserts that legacy porter adoption
// registers a young confirmed transfer even when its recorded
// confirmation cannot be reconstructed from the chain: the anchoring is
// then born unseeded, for the sensor to derive its phase, rather than
// the failure keeping the porter from starting. Registry failures stay
// fatal.
func TestAdoptLegacyParcelsSeedFallback(t *testing.T) {
	t.Parallel()

	// The input asset's proof file, from which adoption recovers the
	// trigger script.
	inputPkScript := append(
		[]byte{0x51, 0x20}, bytes.Repeat([]byte{0xbb}, 32)...,
	)
	inputAnchorTx := wire.NewMsgTx(2)
	inputAnchorTx.AddTxIn(wire.NewTxIn(&wire.OutPoint{}, nil, nil))
	inputAnchorTx.AddTxOut(&wire.TxOut{Value: 1_000})
	inputAnchorTx.AddTxOut(&wire.TxOut{
		Value:    1_000,
		PkScript: inputPkScript,
	})
	inputProof := proof.RandProof(
		t, asset.RandGenesis(t, asset.Normal), test.RandPubKey(t),
		wire.MsgBlock{Transactions: []*wire.MsgTx{inputAnchorTx}},
		0, 1,
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

	// The legacy transfer spends that input and is recorded confirmed
	// at height 101, within the safe depth of the best height.
	anchorTx := wire.NewMsgTx(2)
	anchorTx.AddTxIn(wire.NewTxIn(&inputOutPoint, nil, nil))
	anchorTx.AddTxOut(&wire.TxOut{Value: 900, PkScript: []byte{0x51}})
	anchorTxid := anchorTx.TxHash()
	block := &wire.MsgBlock{
		Header:       wire.BlockHeader{Version: 1},
		Transactions: []*wire.MsgTx{wire.NewMsgTx(2), anchorTx},
	}
	parcel := OutboundParcel{
		AnchorTx:            anchorTx,
		AnchorTxBlockHash:   fn.Some(block.BlockHash()),
		AnchorTxBlockHeight: 101,
		AnchorTxHeightHint:  99,
		Inputs: []TransferInput{{
			PrevID: prevID,
			Amount: 1,
		}},
	}

	// adopt runs the startup pass for one parcel against a fresh
	// porter and returns the anchoring it produced, if any.
	adopt := func(parcel OutboundParcel, bridge *blockByHeightBridge,
		registrar *tapreorg.MockRegistrar) (*tapreorg.Anchoring,
		error) {

		registrar.SetBestHeight(103)
		exportLog := &stubExportLog{
			parcels: []*OutboundParcel{&parcel},
		}
		porter := NewChainPorter(&ChainPorterConfig{
			ExportLog:   exportLog,
			ChainBridge: bridge,
			ProofReader: &stubProofExporter{
				blob: fileBuf.Bytes(),
			},
			AnchoringWatcher:   registrar,
			AnchoringThreshold: 6,
		})
		if err := porter.adoptLegacyParcels(); err != nil {
			return nil, err
		}

		// The database is asked only for the young frontier.
		require.Equal(
			t, tapreorg.ProtectionFloor(103, 6), exportLog.floor,
		)

		return registrar.LookupByMatchKey(
			context.Background(), PorterSiteID,
			anchorTxid.CloneBytes(),
		)
	}

	// unseeded asserts a registration born without the recorded
	// confirmation, carrying the proof-recovered trigger.
	unseeded := func(t *testing.T, parcel OutboundParcel,
		bridge *blockByHeightBridge) {

		adopted, err := adopt(
			parcel, bridge, tapreorg.NewMockRegistrar(),
		)
		require.NoError(t, err)
		require.NotNil(t, adopted)
		require.IsType(t, tapreorg.Unwitnessed{}, adopted.Phase)
		require.Empty(t, adopted.Spends)

		triggers := adopted.Triggers.OutPoints()
		require.Len(t, triggers, 1)
		require.Equal(t, inputOutPoint, triggers[0].OutPoint)
		require.Equal(t, inputPkScript, triggers[0].PkScript)
	}

	t.Run("recorded confirmation seeds", func(t *testing.T) {
		adopted, err := adopt(
			parcel, &blockByHeightBridge{block: block},
			tapreorg.NewMockRegistrar(),
		)
		require.NoError(t, err)
		require.NotNil(t, adopted)
		require.IsType(t, tapreorg.Witnessed{}, adopted.Phase)
		require.Len(t, adopted.Spends, 1)
		require.Equal(t, anchorTxid, adopted.Spends[0].W.TxHash())
	})

	t.Run("block re-orged out", func(t *testing.T) {
		// Another block now sits at the recorded height.
		reorged := &wire.MsgBlock{
			Header: wire.BlockHeader{Version: 1, Nonce: 1},
			Transactions: []*wire.MsgTx{
				wire.NewMsgTx(2), anchorTx,
			},
		}
		unseeded(t, parcel, &blockByHeightBridge{block: reorged})
	})

	t.Run("transaction absent from block", func(t *testing.T) {
		// A transfer recorded without its block hash can only be
		// checked by membership, and the block at its height no
		// longer carries the transaction.
		unhashed := parcel
		unhashed.AnchorTxBlockHash = fn.None[chainhash.Hash]()
		emptied := &wire.MsgBlock{
			Header:       block.Header,
			Transactions: []*wire.MsgTx{wire.NewMsgTx(2)},
		}
		unseeded(t, unhashed, &blockByHeightBridge{block: emptied})
	})

	t.Run("block fetch fails", func(t *testing.T) {
		unseeded(t, parcel, &blockByHeightBridge{
			err: errors.New("backend unavailable"),
		})
	})

	t.Run("registry failure is fatal", func(t *testing.T) {
		registrar := tapreorg.NewMockRegistrar()
		errRegistry := errors.New("registry unavailable")
		registrar.FailNextRegister(errRegistry)

		_, err := adopt(
			parcel, &blockByHeightBridge{block: block}, registrar,
		)
		require.ErrorIs(t, err, errRegistry)
	})
}
