package tapcustody_test

import (
	"context"
	"database/sql"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapcustody"
	"github.com/lightninglabs/taproot-assets/tapdb"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/tapreorg"
	"github.com/lightninglabs/taproot-assets/tapreorg/chainsim"
	"github.com/lightningnetwork/lnd/clock"
	"github.com/stretchr/testify/require"
)

const receiveIntegrationTimeout = 30 * time.Second

// cascadeReceiveLog records the receive compensations relevant to the
// integration test below. The watcher calls it from its delivery goroutine, so
// its observations are synchronized with the test goroutine.
type cascadeReceiveLog struct {
	mu           sync.Mutex
	abandonments map[chainhash.Hash]int
}

// batchRecordingRegistrar keeps the production registrar behavior while
// making the receive side's batching contract observable.
type batchRecordingRegistrar struct {
	tapreorg.Registrar

	mu         sync.Mutex
	batchSizes []int
}

func (r *batchRecordingRegistrar) RegisterBatch(ctx context.Context,
	specs []tapreorg.RegistrationSpec,
	phase1 tapreorg.BatchPhase1Func) ([]tapreorg.AnchoringID, error) {

	r.mu.Lock()
	r.batchSizes = append(r.batchSizes, len(specs))
	r.mu.Unlock()

	return r.Registrar.RegisterBatch(ctx, specs, phase1)
}

func (r *batchRecordingRegistrar) sizes() []int {
	r.mu.Lock()
	defer r.mu.Unlock()

	return append([]int(nil), r.batchSizes...)
}

func newCascadeReceiveLog() *cascadeReceiveLog {
	return &cascadeReceiveLog{
		abandonments: make(map[chainhash.Hash]int),
	}
}

func (l *cascadeReceiveLog) ApplyReceiveReconfirm(context.Context,
	*sqlc.Queries, proof.VerifiedBlockContext) ([]proof.Locator, error) {

	return nil, nil
}

func (l *cascadeReceiveLog) ApplyReceiveUnconfirm(context.Context,
	*sqlc.Queries, chainhash.Hash) error {

	return nil
}

func (l *cascadeReceiveLog) ApplyReceiveAbandonment(_ context.Context,
	_ *sqlc.Queries, txid chainhash.Hash,
	_ int16) ([]proof.Locator, error) {

	l.mu.Lock()
	defer l.mu.Unlock()

	l.abandonments[txid]++

	return nil, nil
}

func (l *cascadeReceiveLog) StakeReceivedProofs(context.Context,
	tapreorg.RegistryTx,
	...proof.VerifiedAnnotatedProof) ([]proof.Blob, error) {

	return nil, nil
}

func (l *cascadeReceiveLog) StoreReceivedProofs(context.Context,
	...proof.VerifiedAnnotatedProof) ([]proof.Blob, error) {

	return nil, nil
}

func (l *cascadeReceiveLog) HasReceivedProof(context.Context,
	proof.Locator) (bool, error) {

	return false, nil
}

func (l *cascadeReceiveLog) NotifyProofs(...proof.Blob) {}

func (l *cascadeReceiveLog) abandonmentCount(txid chainhash.Hash) int {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.abandonments[txid]
}

// receiveIntegrationScript returns a standard witness program accepted by
// the notifier simulator.
func receiveIntegrationScript(tag byte) []byte {
	script := make([]byte, 34)
	script[0] = txscript.OP_0
	script[1] = txscript.OP_DATA_32
	for idx := 2; idx < len(script); idx++ {
		script[idx] = tag
	}

	return script
}

// receiveIntegrationTx builds one link in the proof's transaction chain.
func receiveIntegrationTx(spends wire.OutPoint, tag byte) *wire.MsgTx {
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(&spends, nil, nil))
	tx.AddTxOut(wire.NewTxOut(1_000, receiveIntegrationScript(tag)))

	return tx
}

// proofBlockContext reads a transaction's simulated chain location and builds
// the corresponding proof context.
func proofBlockContext(t *testing.T, sim *chainsim.Chain,
	tx *wire.MsgTx, height uint32) (wire.BlockHeader,
	proof.TxMerkleProof) {

	t.Helper()

	ctx := context.Background()
	blockHash, err := sim.GetBlockHash(ctx, int64(height))
	require.NoError(t, err)
	block, err := sim.GetBlock(ctx, blockHash)
	require.NoError(t, err)

	txIndex := -1
	for idx := range block.Transactions {
		if block.Transactions[idx].TxHash() == tx.TxHash() {
			txIndex = idx
			break
		}
	}
	require.NotEqual(t, -1, txIndex)

	merkleProof, err := proof.NewTxMerkleProof(
		block.Transactions, txIndex,
	)
	require.NoError(t, err)

	return block.Header, *merkleProof
}

// threeHopReceiveFile builds genesis -> parent -> tip with chain contexts from
// the simulator. The parent and tip are the dependency edge under test.
func threeHopReceiveFile(t *testing.T, sim *chainsim.Chain,
	genesisTx, parentTx, tipTx *wire.MsgTx, genesisHeight,
	parentHeight, tipHeight uint32) *proof.File {

	t.Helper()

	genesisHeader, genesisMerkle := proofBlockContext(
		t, sim, genesisTx, genesisHeight,
	)
	parentHeader, parentMerkle := proofBlockContext(
		t, sim, parentTx, parentHeight,
	)
	tipHeader, tipMerkle := proofBlockContext(
		t, sim, tipTx, tipHeight,
	)

	genesisKey := asset.NewScriptKey(test.RandPubKey(t))
	parentKey := asset.NewScriptKey(test.RandPubKey(t))
	tipKey := asset.NewScriptKey(test.RandPubKey(t))

	genesisProof := proof.Proof{
		BlockHeader:   genesisHeader,
		BlockHeight:   genesisHeight,
		AnchorTx:      *genesisTx,
		TxMerkleProof: genesisMerkle,
		Asset: asset.Asset{
			Version:   asset.V0,
			Amount:    1_000,
			ScriptKey: genesisKey,
			PrevWitnesses: []asset.Witness{
				{PrevID: &asset.PrevID{}},
			},
		},
		InclusionProof: proof.TaprootProof{
			InternalKey: test.RandPubKey(t),
			OutputIndex: 0,
		},
	}

	genesisOut := wire.OutPoint{Hash: genesisTx.TxHash(), Index: 0}
	parentPrevID := asset.PrevID{
		OutPoint: genesisOut,
		ScriptKey: asset.ToSerialized(
			genesisKey.PubKey,
		),
	}
	parentProof := proof.Proof{
		PrevOut:       genesisOut,
		BlockHeader:   parentHeader,
		BlockHeight:   parentHeight,
		AnchorTx:      *parentTx,
		TxMerkleProof: parentMerkle,
		Asset: asset.Asset{
			Version:   asset.V0,
			Amount:    1_000,
			ScriptKey: parentKey,
			PrevWitnesses: []asset.Witness{{
				PrevID:    &parentPrevID,
				TxWitness: wire.TxWitness{{0x01}},
			}},
		},
		InclusionProof: proof.TaprootProof{
			InternalKey: test.RandPubKey(t),
			OutputIndex: 0,
		},
	}

	parentOut := wire.OutPoint{Hash: parentTx.TxHash(), Index: 0}
	tipPrevID := asset.PrevID{
		OutPoint: parentOut,
		ScriptKey: asset.ToSerialized(
			parentKey.PubKey,
		),
	}
	tipProof := proof.Proof{
		PrevOut:       parentOut,
		BlockHeader:   tipHeader,
		BlockHeight:   tipHeight,
		AnchorTx:      *tipTx,
		TxMerkleProof: tipMerkle,
		Asset: asset.Asset{
			Version:   asset.V0,
			Amount:    1_000,
			ScriptKey: tipKey,
			PrevWitnesses: []asset.Witness{{
				PrevID:    &tipPrevID,
				TxWitness: wire.TxWitness{{0x02}},
			}},
		},
		InclusionProof: proof.TaprootProof{
			InternalKey: test.RandPubKey(t),
			OutputIndex: 0,
		},
	}

	file, err := proof.NewFile(
		proof.V0, genesisProof, parentProof, tipProof,
	)
	require.NoError(t, err)

	return file
}

// TestReceiveBatchDependencyForeclosure proves the receive composition across
// its real boundaries: proof-DAG derivation, one watcher batch, the tapdb
// dependency edge, cascade sensing and the tip's receive compensation.
func TestReceiveBatchDependencyForeclosure(t *testing.T) {
	const threshold uint32 = 6

	ctx := context.Background()
	sim := chainsim.New()

	fundingOut := wire.OutPoint{
		Hash:  chainhash.Hash{0x41},
		Index: 0,
	}
	genesisTx := receiveIntegrationTx(fundingOut, 0x11)
	genesisOut := wire.OutPoint{Hash: genesisTx.TxHash(), Index: 0}
	parentTx := receiveIntegrationTx(genesisOut, 0x22)
	parentOut := wire.OutPoint{Hash: parentTx.TxHash(), Index: 0}
	tipTx := receiveIntegrationTx(parentOut, 0x33)

	genesisHeight := sim.MineBlock(genesisTx)
	parentHeight := sim.MineBlock(parentTx)
	tipHeight := sim.MineBlock(tipTx)
	file := threeHopReceiveFile(
		t, sim, genesisTx, parentTx, tipTx, genesisHeight,
		parentHeight, tipHeight,
	)

	db := tapdb.NewTestDB(t)
	executor := tapdb.NewTransactionExecutor(
		db, func(tx *sql.Tx) *sqlc.Queries {
			return db.WithTx(tx)
		},
	)
	store := tapdb.NewReorgRegistryStore(
		executor, clock.NewDefaultClock(),
	)
	errChan := make(chan error, 16)
	watcher := tapreorg.NewWatcher(&tapreorg.WatcherConfig{
		Notifier:               sim,
		Registry:               store,
		DefaultThreshold:       threshold,
		InitialDeliveryBackoff: 10 * time.Millisecond,
		MaxDeliveryBackoff:     40 * time.Millisecond,
		ScanInterval:           20 * time.Millisecond,
		DispatchTimeout:        100 * time.Millisecond,
		ErrChan:                errChan,
	})

	receiveLog := newCascadeReceiveLog()
	registrar := &batchRecordingRegistrar{Registrar: watcher}
	custodian := tapcustody.NewCustodian(&tapcustody.Config{
		AnchoringWatcher:   registrar,
		AnchoringLog:       receiveLog,
		AnchoringThreshold: threshold,
	})
	require.NoError(t, watcher.RegisterSite(custodian.AnchoringSite()))
	require.NoError(t, watcher.Start())
	t.Cleanup(func() {
		require.NoError(t, watcher.Stop())
		select {
		case err := <-errChan:
			require.NoError(t, err)
		default:
		}
	})

	// This is the production receive entry point: it derives all three
	// registrations from the proof DAG and sends them through one
	// RegisterBatch call.
	require.NoError(t, custodian.RegisterReceiveAnchoring(ctx, file, nil))
	require.Equal(t, []int{3}, registrar.sizes())

	parentTxID := parentTx.TxHash()
	parentID, err := watcher.LookupByMatchKey(
		ctx, tapcustody.ReceiveSiteID, parentTxID.CloneBytes(),
	)
	require.NoError(t, err)
	require.NotNil(t, parentID)
	tipTxID := tipTx.TxHash()
	tipID, err := watcher.LookupByMatchKey(
		ctx, tapcustody.ReceiveSiteID, tipTxID.CloneBytes(),
	)
	require.NoError(t, err)
	require.NotNil(t, tipID)

	// The parent's seeded candidate was inserted earlier in the same batch,
	// so the tip's trigger must have resolved to this durable edge.
	edges, err := store.DependencyEdges(ctx, parentID.ID)
	require.NoError(t, err)
	require.Len(t, edges, 1)
	require.Equal(t, tipID.ID, edges[0].Child)
	require.Equal(t, parentID.ID, edges[0].Parent)
	require.Equal(t, parentTxID, edges[0].ParentWitnessTxHash)

	// Replace the parent and remove the tip. Nothing spends the tip's
	// trigger on the surviving chain, so only the dependency foreclosure
	// can make the tip terminal.
	foreignParent := receiveIntegrationTx(genesisOut, 0x44)
	sim.Reorg(2, []*wire.MsgTx{foreignParent}, nil)
	require.Eventually(t, func() bool {
		anchoring, err := store.GetAnchoring(ctx, tipID.ID)
		if err != nil {
			return false
		}

		return tapreorg.PhaseEqual(
			anchoring.Phase, tapreorg.Unwitnessed{},
		) && tapreorg.PhaseEqual(
			anchoring.DeliveredPhase, anchoring.Phase,
		)
	}, receiveIntegrationTimeout, 10*time.Millisecond)

	// Once the replacement reaches act depth, the parent abandons and the
	// in-batch edge carries that foreclosure to the tip's handler.
	sim.MineBlocks(int(threshold))
	require.Eventually(t, func() bool {
		anchoring, err := store.GetAnchoring(ctx, tipID.ID)
		if err != nil {
			return false
		}

		abandoned, ok := anchoring.Phase.(tapreorg.Abandoned)
		if !ok || !tapreorg.PhaseEqual(
			anchoring.DeliveredPhase, anchoring.Phase,
		) {

			return false
		}
		foreclosed, ok := abandoned.Cause.(tapreorg.Foreclosed)
		if !ok || foreclosed.Parent != parentID.ID {
			return false
		}

		return receiveLog.abandonmentCount(tipTxID) == 1
	}, receiveIntegrationTimeout, 10*time.Millisecond)
}
