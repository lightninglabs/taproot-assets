package tapgarden

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/tapnode/tapnodemock"
	"github.com/lightninglabs/taproot-assets/tapreorg"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

// mintCall records one persistence call with its full argument list.
type mintCall struct {
	kind        string
	txid        chainhash.Hash
	blockHash   chainhash.Hash
	blockHeight uint32
	txIndex     uint32
	header      wire.BlockHeader
}

// ladderMintLog captures what each handler derived, not merely that it
// was called. The existing recordingMintLog counts calls, which is
// enough to pin act gating but cannot see a stale block context.
type ladderMintLog struct {
	calls []mintCall

	// locators is what the proof-touching bodies report as
	// rewritten or deleted, and so what the site must hand to the
	// mirror.
	locators []proof.Locator
}

func (l *ladderMintLog) ApplyReceiveReconfirm(_ context.Context,
	_ *sqlc.Queries, anchorTxid chainhash.Hash,
	blockHash chainhash.Hash, blockHeight, txIndex uint32,
	header wire.BlockHeader,
	_ proof.TxMerkleProof) ([]proof.Locator, error) {

	l.calls = append(l.calls, mintCall{
		kind:        "reconfirm",
		txid:        anchorTxid,
		blockHash:   blockHash,
		blockHeight: blockHeight,
		txIndex:     txIndex,
		header:      header,
	})

	return l.locators, nil
}

func (l *ladderMintLog) ApplyReceiveUnconfirm(_ context.Context,
	_ *sqlc.Queries, anchorTxid chainhash.Hash) error {

	l.calls = append(l.calls, mintCall{
		kind: "unconfirm",
		txid: anchorTxid,
	})

	return nil
}

func (l *ladderMintLog) ApplyMintAbandonment(_ context.Context,
	_ *sqlc.Queries, genesisTxid chainhash.Hash,
	_ []byte) ([]proof.Locator, error) {

	l.calls = append(l.calls, mintCall{
		kind: "abandon",
		txid: genesisTxid,
	})

	return l.locators, nil
}

func (l *ladderMintLog) kinds() []string {
	out := make([]string, 0, len(l.calls))
	for _, c := range l.calls {
		out = append(out, c.kind)
	}

	return out
}

// mintWitnessAt builds a witness and its matching candidate enrichment
// for the genesis transaction in the given block.
func mintWitnessAt(t *testing.T, tx *wire.MsgTx, nonce uint32,
	height, txIndex uint32) (tapreorg.Witness, tapreorg.CandidateSpend) {

	t.Helper()

	header := &wire.BlockHeader{Version: 2, Nonce: nonce}
	w, err := tapreorg.NewWitness(tx, header.BlockHash(), height, txIndex)
	require.NoError(t, err)

	return w, tapreorg.CandidateSpend{
		Verdict:     tapreorg.VerdictSatisfies,
		W:           w,
		OnChain:     true,
		BlockHeader: header,
		MerkleProof: &proof.TxMerkleProof{},
	}
}

// TestMintSiteReorgLadder drives the mint site through a genesis
// transaction that confirms, is re-organized away, and re-confirms in a
// different block before finally being buried.
//
// TestMintSiteActGating already pins which handler emits, but it does so
// against a single unchanging witness, so it cannot distinguish a site
// that reads its block context from the current phase from one that
// captured it once. That distinction is the whole point of the potency
// tier: a mint whose genesis moved blocks must publish the block it
// actually landed in, because the issuance proof it publishes to the
// universe carries that header and a stale one will not verify.
//
// The emission is asserted against the re-organized block specifically:
// burial happens in block B, so the single act-gated publication must
// follow a re-confirmation carrying B.
func TestMintSiteReorgLadder(t *testing.T) {
	t.Parallel()

	genesisTx := wire.NewMsgTx(2)
	genesisTx.AddTxIn(wire.NewTxIn(&wire.OutPoint{}, nil, nil))
	genesisTx.AddTxOut(wire.NewTxOut(1_000, []byte{0x51}))

	var blob mintBlob
	blob.RawBatchKey[0] = 0x02
	blob.GenesisTxid = genesisTx.TxHash()
	payload := encodeMintBlob(blob)

	witnessA, candidateA := mintWitnessAt(t, genesisTx, 10, 700, 1)
	witnessB, candidateB := mintWitnessAt(t, genesisTx, 11, 706, 5)
	require.NotEqual(t, witnessA.BlockHash(), witnessB.BlockHash())

	loc := mirrorLocator(t, blob.GenesisTxid)
	log := &ladderMintLog{locators: []proof.Locator{loc}}
	site := &mintSite{planter: NewChainPlanter(PlanterConfig{
		GardenKit: GardenKit{MintAnchoringLog: log},
	})}
	ctx := context.Background()
	tx := &recordingRegistryTx{}

	anchoring := &tapreorg.Anchoring{
		ID:      9,
		Site:    MintSiteID,
		Payload: payload,
		Spends:  []tapreorg.CandidateSpend{candidateA},
		Phase:   tapreorg.Witnessed{W: witnessA},
	}

	// Genesis confirms in block A. Nothing is published: the batch is
	// locally confirmed but five blocks short of the act threshold.
	require.NoError(t, site.OnWitnessed(ctx, tx, anchoring))
	require.Empty(t, actGated(tx.effects), "published at the potency tier")

	// Block A is re-organized away.
	anchoring.Phase = tapreorg.Unwitnessed{}
	require.NoError(t, site.OnUnwitnessed(ctx, tx, anchoring))
	require.Empty(t, actGated(tx.effects))

	// Genesis re-confirms in block B, at a new height and index.
	anchoring.Spends = []tapreorg.CandidateSpend{candidateB}
	anchoring.Phase = tapreorg.Witnessed{W: witnessB}
	require.NoError(t, site.OnWitnessed(ctx, tx, anchoring))
	require.Empty(t, actGated(tx.effects))

	// Block B is buried. Now, and only now, the batch's issuance is
	// published — carrying block B.
	anchoring.Phase = tapreorg.Buried{W: witnessB}
	require.NoError(t, site.OnBuried(ctx, tx, anchoring))

	require.Equal(
		t, []string{
			"reconfirm", "unconfirm", "reconfirm", "reconfirm",
		}, log.kinds(),
	)
	published := actGated(tx.effects)
	require.Len(t, published, 1)
	require.Equal(t, MintPublishEffectKind, published[0].Kind)

	// Each confirmation re-stamped the stored proof, and each
	// re-stamp is followed by the mirror's catch-up for it, so the
	// file tree ends up carrying block B too.
	requireMirrorSyncs(
		t, tx.effects, anchoring.ID, loc,
		proof.MirrorSyncRewrite, proof.MirrorSyncRewrite,
		proof.MirrorSyncRewrite,
	)

	// Freshness: the pre-re-org confirmation carried A; everything
	// after it carried B. The burial confirmation in particular must
	// carry B, since it is the one whose proof gets published.
	require.Equal(t, witnessA.BlockHash(), log.calls[0].blockHash)
	require.EqualValues(t, 700, log.calls[0].blockHeight)

	for _, idx := range []int{2, 3} {
		require.Equal(
			t, witnessB.BlockHash(), log.calls[idx].blockHash,
			"call %d carries a stale block hash", idx,
		)
		require.EqualValues(
			t, 706, log.calls[idx].blockHeight,
			"call %d carries a stale height", idx,
		)
		require.EqualValues(
			t, 5, log.calls[idx].txIndex,
			"call %d carries a stale tx index", idx,
		)
		require.Equal(
			t, *candidateB.BlockHeader, log.calls[idx].header,
			"call %d carries a stale header", idx,
		)
	}

	// Every call named the genesis transaction from the payload.
	for i, c := range log.calls {
		require.Equal(t, blob.GenesisTxid, c.txid, "call %d", i)
	}
}

// TestMintAbandonmentStopsCultivator resumes a broadcast batch whose
// anchoring the watcher has abandoned. Abandonment is a handled
// outcome, not a fault: the cultivator winds down on its own, the
// batch reads as sprout-cancelled, subscribers hear it, the planter
// is handed the finished cultivator, and the daemon's error channel
// stays silent.
func TestMintAbandonmentStopsCultivator(t *testing.T) {
	t.Parallel()

	const timeout = 5 * time.Second
	ctx := context.Background()

	// The genesis transaction, in the finalized packet the broadcast
	// step extracts it from. The mock wallet finalizes by stamping an
	// empty signature script; mirror that.
	fundingOp := wire.OutPoint{Hash: chainhash.Hash{0x01}, Index: 0}
	genesisTx := wire.NewMsgTx(2)
	genesisTx.AddTxIn(wire.NewTxIn(&fundingOp, nil, nil))
	genesisTx.AddTxOut(wire.NewTxOut(int64(GenesisAmtSats), []byte{0x51}))
	genesisTxid := genesisTx.TxHash()

	pkt, err := psbt.NewFromUnsignedTx(genesisTx)
	require.NoError(t, err)
	pkt.Inputs[0].FinalScriptSig = []byte{}

	batchPriv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	batch := &MintingBatch{
		HeightHint: 100,
		BatchKey:   keychain.KeyDescriptor{PubKey: batchPriv.PubKey()},
		GenesisPacket: &FundedMintAnchorPsbt{
			FundedPsbt: tapsend.FundedPsbt{Pkt: pkt},
		},
	}
	batch.setState(BatchStateBroadcast)

	// The registry already holds the batch's anchoring, abandoned: a
	// foreign spend of the funding input was buried while the
	// cultivator was away.
	registrar := tapreorg.NewMockRegistrar()
	triggers, err := tapreorg.NewTriggerSet([]tapreorg.TriggerOutPoint{{
		OutPoint:   fundingOp,
		HeightHint: 100,
	}})
	require.NoError(t, err)
	id, err := registrar.Register(ctx, tapreorg.RegistrationSpec{
		Site:      MintSiteID,
		Triggers:  triggers,
		MatchKey:  genesisTxid.CloneBytes(),
		Threshold: 1,
	}, nil)
	require.NoError(t, err)

	foreign := wire.NewMsgTx(2)
	foreign.AddTxIn(wire.NewTxIn(&fundingOp, nil, nil))
	foreign.AddTxOut(wire.NewTxOut(500, []byte{0x51}))
	require.NoError(t, registrar.Abandon(
		id, foreign, chainhash.Hash{0x02}, 101, 1,
	))

	chain := tapnodemock.NewChainBridge()
	errChan := make(chan error, 1)
	completed := make(chan struct{}, 1)

	var (
		eventsMu sync.Mutex
		events   []*AssetMintEvent
	)
	cultivator := NewCultivator(&CultivatorConfig{
		Batch: batch,
		GardenKit: &GardenKit{
			ChainBridge:        chain,
			AnchoringWatcher:   registrar,
			AnchoringThreshold: 1,
		},
		BroadcastCompleteChan: make(chan struct{}, 1),
		BroadcastErrChan:      make(chan error, 1),
		SignalCompletion: func() {
			completed <- struct{}{}
		},
		CancelReqChan: make(chan cancelReq, 1),
		PublishMintEvent: func(event fn.Event) {
			eventsMu.Lock()
			defer eventsMu.Unlock()

			events = append(events, event.(*AssetMintEvent))
		},
		ErrChan:          errChan,
		AnchoringWaiters: tapreorg.NewDeliveryWaiters(),
	})
	require.NoError(t, cultivator.Start())
	t.Cleanup(func() {
		require.NoError(t, cultivator.Stop())
	})

	// Resuming at broadcast re-publishes the genesis transaction.
	select {
	case tx := <-chain.PublishReq:
		require.Equal(t, genesisTxid, tx.TxHash())
	case <-time.After(timeout):
		t.Fatal("genesis transaction not published")
	}

	// The cultivator winds down on its own, having handed itself back
	// to the planter as finished.
	select {
	case <-cultivator.Done():
	case <-time.After(timeout):
		t.Fatal("cultivator did not stop on abandonment")
	}
	select {
	case <-completed:
	default:
		t.Fatal("cultivator did not signal completion")
	}

	// The in-memory batch mirrors the compensation the site applied
	// on disk, and subscribers saw the cancellation as a plain state
	// event.
	require.Equal(t, BatchStateSproutCancelled, batch.State())

	eventsMu.Lock()
	defer eventsMu.Unlock()
	require.NotEmpty(t, events)
	last := events[len(events)-1]
	require.NoError(t, last.Error)
	require.Equal(t, BatchStateSproutCancelled, last.Batch.State())

	// Nothing reached the daemon's critical error channel.
	select {
	case err := <-errChan:
		t.Fatalf("abandonment escalated as critical: %v", err)
	default:
	}
}

// TestMintAnchoringWaitNudged pins the cultivator's wait on its
// anchoring: nothing wakes it but the planter's delivery listener, a
// delivery for another site is not its own, and a delivery that landed
// before the wait began resolves at once.
func TestMintAnchoringWaitNudged(t *testing.T) {
	t.Parallel()

	const timeout = 5 * time.Second
	ctx := context.Background()

	fundingOp := wire.OutPoint{Hash: chainhash.Hash{0x03}, Index: 0}
	genesisTx := wire.NewMsgTx(2)
	genesisTx.AddTxIn(wire.NewTxIn(&fundingOp, nil, nil))
	genesisTx.AddTxOut(wire.NewTxOut(int64(GenesisAmtSats), []byte{0x51}))
	genesisTxid := genesisTx.TxHash()

	batchPriv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	batch := &MintingBatch{
		HeightHint: 100,
		BatchKey:   keychain.KeyDescriptor{PubKey: batchPriv.PubKey()},
	}

	registrar := tapreorg.NewMockRegistrar()
	triggers, err := tapreorg.NewTriggerSet([]tapreorg.TriggerOutPoint{{
		OutPoint:   fundingOp,
		HeightHint: 100,
	}})
	require.NoError(t, err)
	id, err := registrar.Register(ctx, tapreorg.RegistrationSpec{
		Site:      MintSiteID,
		Triggers:  triggers,
		MatchKey:  genesisTxid.CloneBytes(),
		Threshold: 1,
	}, nil)
	require.NoError(t, err)

	chain := tapnodemock.NewChainBridge()
	planter := NewChainPlanter(PlanterConfig{})
	cultivator := NewCultivator(&CultivatorConfig{
		Batch: batch,
		GardenKit: &GardenKit{
			ChainBridge:        chain,
			AnchoringWatcher:   registrar,
			AnchoringThreshold: 1,
		},
		AnchoringWaiters: planter.waiters,
	})

	type result struct {
		outcome *mintAnchoringOutcome
		err     error
	}
	wait := func() <-chan result {
		results := make(chan result, 1)
		go func() {
			outcome, err := cultivator.waitForMintAnchoring(
				ctx, genesisTxid,
			)
			results <- result{outcome: outcome, err: err}
		}()

		return results
	}
	requireBlocked := func(results <-chan result, desc string) {
		t.Helper()

		select {
		case r := <-results:
			t.Fatalf("wait resolved %s: %v", desc, r)
		case <-time.After(200 * time.Millisecond):
		}
	}

	// Nothing is delivered yet: the wait blocks.
	results := wait()
	requireBlocked(results, "before delivery")

	// The watcher witnesses the genesis transaction and delivers.
	// Until the planter's listener hears of it, the wait stays
	// blocked; a delivery for another site is not its own.
	blockHash := chainhash.Hash{0xcc}
	block := &wire.MsgBlock{Transactions: []*wire.MsgTx{genesisTx}}
	chain.SetBlock(blockHash, block)
	confirmed, err := registrar.ConfirmSpend(
		genesisTx, blockHash, 101, 0, wire.BlockHeader{Nonce: 1},
		proof.TxMerkleProof{},
	)
	require.NoError(t, err)
	require.Equal(t, 1, confirmed)

	planter.OnAnchoringDelivered(
		id, tapreorg.SiteID("other"), tapreorg.Witnessed{},
	)
	requireBlocked(results, "on another site's delivery")

	planter.OnAnchoringDelivered(id, MintSiteID, tapreorg.Witnessed{})
	select {
	case r := <-results:
		require.NoError(t, r.err)
		require.NotNil(t, r.outcome.confirmation)
		require.Equal(t, blockHash, *r.outcome.confirmation.BlockHash)
		require.EqualValues(t, 101, r.outcome.confirmation.BlockHeight)
		require.Equal(t, block, r.outcome.confirmation.Block)

	case <-time.After(timeout):
		t.Fatal("wait did not resolve on the listener's nudge")
	}

	// A wait that begins after the delivery reads it from the
	// registry and resolves without a nudge.
	select {
	case r := <-wait():
		require.NoError(t, r.err)
		require.NotNil(t, r.outcome.confirmation)

	case <-time.After(timeout):
		t.Fatal("wait on a delivered anchoring did not resolve")
	}
}

// broadcastBatchStore serves one batch, whatever key is asked for.
type broadcastBatchStore struct {
	BatchStore

	batch *MintingBatch
}

func (s *broadcastBatchStore) FetchMintingBatch(_ context.Context,
	_ *btcec.PublicKey) (*MintingBatch, error) {

	return s.batch, nil
}

// TestMintPublishNotReadyBeforeConfirmation pins the publish handler's
// readiness gate: a batch whose burial was delivered before the
// cultivator confirmed it has no proofs to publish yet, which the
// handler reports as not ready rather than as a failure; a batch that
// can never be published fails outright.
func TestMintPublishNotReadyBeforeConfirmation(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	batchPriv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	batch := &MintingBatch{
		BatchKey: keychain.KeyDescriptor{PubKey: batchPriv.PubKey()},
	}
	batch.setState(BatchStateBroadcast)

	planter := NewChainPlanter(PlanterConfig{
		GardenKit: GardenKit{
			BatchStore: &broadcastBatchStore{batch: batch},
		},
	})

	var rawKey [33]byte
	copy(rawKey[:], batchPriv.PubKey().SerializeCompressed())
	payload := encodeMintBlob(mintBlob{
		RawBatchKey: rawKey,
		GenesisTxid: chainhash.Hash{0x04},
	})

	err = planter.DispatchMintPublish(
		ctx, fn.None[tapreorg.AnchoringID](), payload,
	)
	require.ErrorIs(t, err, tapreorg.ErrEffectNotReady)

	batch.setState(BatchStateSproutCancelled)
	err = planter.DispatchMintPublish(
		ctx, fn.None[tapreorg.AnchoringID](), payload,
	)
	require.Error(t, err)
	require.NotErrorIs(t, err, tapreorg.ErrEffectNotReady)
}
