package tapdb

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/tapfreighter"
	"github.com/lightninglabs/taproot-assets/tapnode"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/tapreorg"
	"github.com/lightninglabs/taproot-assets/tapreorg/chainsim"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/lightninglabs/taproot-assets/vm"
	"github.com/lightningnetwork/lnd/clock"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

// simChainBridge exposes the chain simulator through the chain bridge
// surface the porter and the proof verifier read: blocks by height and hash,
// the tip, header verification, and the verifier's timelock queries.
type simChainBridge struct {
	tapnode.ChainBridge

	sim *chainsim.Chain
}

func (b *simChainBridge) GetBlockByHeight(ctx context.Context,
	height int64) (*wire.MsgBlock, error) {

	hash, err := b.sim.GetBlockHash(ctx, height)
	if err != nil {
		return nil, err
	}

	return b.sim.GetBlock(ctx, hash)
}

func (b *simChainBridge) GetBlockHash(ctx context.Context,
	height int64) (chainhash.Hash, error) {

	return b.sim.GetBlockHash(ctx, height)
}

func (b *simChainBridge) GetBlock(ctx context.Context,
	hash chainhash.Hash) (*wire.MsgBlock, error) {

	return b.sim.GetBlock(ctx, hash)
}

func (b *simChainBridge) CurrentHeight(ctx context.Context) (uint32, error) {
	return b.sim.CurrentHeight(ctx)
}

func (b *simChainBridge) VerifyBlock(ctx context.Context,
	header wire.BlockHeader, height uint32) error {

	hash, err := b.sim.GetBlockHash(ctx, int64(height))
	if err != nil {
		return err
	}
	if header.BlockHash() != hash {
		return fmt.Errorf("block %v is not at height %d",
			header.BlockHash(), height)
	}

	return nil
}

func (b *simChainBridge) GenFileChainLookup(*proof.File) asset.ChainLookup {
	return b
}

func (b *simChainBridge) GenProofChainLookup(
	*proof.Proof) (asset.ChainLookup, error) {

	return b, nil
}

func (b *simChainBridge) TxBlockHeight(_ context.Context,
	txid chainhash.Hash) (uint32, error) {

	height, ok := b.sim.TxHeight(txid)
	if !ok {
		return 0, fmt.Errorf("transaction %v is not confirmed", txid)
	}

	return height, nil
}

func (b *simChainBridge) MeanBlockTimestamp(_ context.Context,
	height uint32) (time.Time, error) {

	return time.Unix(int64(height)*600, 0), nil
}

// errHeldConfirmation is the retryable failure the ordering gate answers a
// held confirmation with.
var errHeldConfirmation = errors.New("confirmation held back by the test")

// orderedPorterLog is the porter's persistence with one confirmation held
// back: re-applying the held transaction fails, and so is retried, until
// released. Deliveries for different anchorings carry no mutual order, so a
// test that depends on one pins it this way.
type orderedPorterLog struct {
	*AssetStore

	held     chainhash.Hash
	released atomic.Bool
}

func (l *orderedPorterLog) ApplyAnchorTxConfirm(ctx context.Context,
	q *sqlc.Queries, conf *tapfreighter.AssetConfirmEvent,
	burns []*tapfreighter.AssetBurn) ([]tapfreighter.OutputIdentifier,
	error) {

	if conf.AnchorTXID == l.held && !l.released.Load() {
		return nil, errHeldConfirmation
	}

	return l.AssetStore.ApplyAnchorTxConfirm(ctx, q, conf, burns)
}

// holding is an asset the wallet holds: where it sits, whose key spends it.
type holding struct {
	assetID   asset.ID
	scriptKey *btcec.PublicKey
	priv      *btcec.PrivateKey
	outPoint  wire.OutPoint
	tx        *wire.MsgTx
	height    uint32
	amount    uint64
}

// keyedSigner signs a virtual transaction with the private key behind the
// descriptor's public key, as the wallet's signer would.
type keyedSigner map[[33]byte]*btcec.PrivateKey

// add registers a key and returns its descriptor.
func (s keyedSigner) add(priv *btcec.PrivateKey) keychain.KeyDescriptor {
	s[[33]byte(priv.PubKey().SerializeCompressed())] = priv

	return test.PubToKeyDesc(priv.PubKey())
}

func (s keyedSigner) SignVirtualTx(signDesc *lndclient.SignDescriptor,
	tx *wire.MsgTx, prevOut *wire.TxOut) (*schnorr.Signature, error) {

	priv, ok := s[[33]byte(signDesc.KeyDesc.PubKey.SerializeCompressed())]
	if !ok {
		return nil, fmt.Errorf("no private key for %x",
			signDesc.KeyDesc.PubKey.SerializeCompressed())
	}

	return asset.SignVirtualTx(priv, signDesc, tx, prevOut)
}

// vmWitnessValidator validates transfer witnesses with the asset VM.
type vmWitnessValidator struct{}

func (vmWitnessValidator) ValidateWitnesses(newAsset *asset.Asset,
	splitAssets []*commitment.SplitAsset,
	prevAssets commitment.InputSet) error {

	return vm.ValidateWitnesses(newAsset, splitAssets, prevAssets)
}

// sendOutput is one output of a send: its amount and the anchor output it
// lands in. Every output goes to a fresh local key.
type sendOutput struct {
	amount      uint64
	anchorIndex uint32
	splitRoot   bool
}

// send is one asset's movement within a transfer: the holdings it spends,
// all of one asset, and the outputs it creates.
type send struct {
	inputs  []holding
	outputs []sendOutput
}

// transferResult is what a transfer leaves the wallet holding: each send's
// outputs in order, and the passives at their new anchor.
type transferResult struct {
	outputs   [][]holding
	passives  []holding
	tx        *wire.MsgTx
	height    uint32
	anchoring tapreorg.AnchoringID
}

// first is the first output of the first send.
func (r transferResult) first() holding {
	return r.outputs[0][0]
}

func (h holding) locator() proof.Locator {
	assetID := h.assetID

	return proof.Locator{
		AssetID:   &assetID,
		ScriptKey: *h.scriptKey,
		OutPoint:  &h.outPoint,
	}
}

// reorgWorkflow is a wallet with the porter wired to a watcher over a
// simulated chain, one transaction per block.
type reorgWorkflow struct {
	sim    *chainsim.Chain
	bridge *simChainBridge

	db          *BaseDB
	assetsStore *AssetStore
	executor    *TransactionExecutor[*sqlc.Queries]
	registry    *ReorgRegistryStore
	watcher     *tapreorg.Watcher
	porter      *tapfreighter.ChainPorter
	porterLog   *orderedPorterLog
	errChan     chan error
	keys        keyedSigner
}

func newReorgWorkflow(t *testing.T, threshold uint32) *reorgWorkflow {
	t.Helper()

	db := NewTestDB(t)
	_, assetsStore := newAssetStoreFromDB(db.BaseDB)
	executor := NewTransactionExecutor(
		db, func(tx *sql.Tx) *sqlc.Queries {
			return db.WithTx(tx)
		},
	)
	registry := NewReorgRegistryStore(
		executor, clock.NewTestClock(time.Unix(1_000_000, 0)),
	)
	sim := chainsim.New()
	bridge := &simChainBridge{sim: sim}

	errChan := make(chan error, 16)
	watcher := tapreorg.NewWatcher(&tapreorg.WatcherConfig{
		Notifier:               sim,
		Registry:               registry,
		DefaultThreshold:       threshold,
		InitialDeliveryBackoff: 10 * time.Millisecond,
		MaxDeliveryBackoff:     40 * time.Millisecond,
		ScanInterval:           20 * time.Millisecond,
		DispatchTimeout:        100 * time.Millisecond,
		ErrChan:                errChan,
	})
	porterLog := &orderedPorterLog{AssetStore: assetsStore}
	porterLog.released.Store(true)
	porter := tapfreighter.NewChainPorter(&tapfreighter.ChainPorterConfig{
		ExportLog:          assetsStore,
		ChainBridge:        bridge,
		ProofReader:        assetsStore,
		AnchoringWatcher:   watcher,
		AnchoringLog:       porterLog,
		AnchoringThreshold: threshold,
	})
	require.NoError(t, watcher.RegisterSite(porter.AnchoringSite()))
	require.NoError(t, watcher.Start())
	t.Cleanup(func() {
		require.NoError(t, watcher.Stop())
		for {
			select {
			case err := <-errChan:
				if !errors.Is(err, errHeldConfirmation) {
					require.NoError(t, err)
				}
			default:
				return
			}
		}
	})

	return &reorgWorkflow{
		sim:         sim,
		bridge:      bridge,
		db:          db.BaseDB,
		assetsStore: assetsStore,
		executor:    executor,
		registry:    registry,
		watcher:     watcher,
		porter:      porter,
		porterLog:   porterLog,
		errChan:     errChan,
		keys:        make(keyedSigner),
	}
}

// anchor mines a transaction in its own block.
func (w *reorgWorkflow) anchor(tx *wire.MsgTx) (*wire.MsgBlock, uint32) {
	height := w.sim.MineBlock(tx)
	block, err := w.bridge.GetBlockByHeight(
		context.Background(), int64(height),
	)
	if err != nil {
		panic(err)
	}

	return block, height
}

// verifierCtx verifies proofs against the simulated chain.
func (w *reorgWorkflow) verifierCtx(ctx context.Context) proof.VerifierCtx {
	return proof.VerifierCtx{
		HeaderVerifier:      tapnode.GenHeaderVerifier(ctx, w.bridge),
		MerkleVerifier:      proof.DefaultMerkleVerifier,
		GroupVerifier:       proof.MockGroupVerifier,
		GroupAnchorVerifier: proof.MockGroupAnchorVerifier,
		ChainLookupGen:      w.bridge,
	}
}

// verify checks a file against the chain and returns its tip snapshot.
func (w *reorgWorkflow) verify(t *testing.T,
	file *proof.File) *proof.AssetSnapshot {

	t.Helper()

	snapshot, err := file.Verify(
		context.Background(), w.verifierCtx(context.Background()),
	)
	require.NoError(t, err)

	return snapshot
}

// storedFile reads a holding's proof file from the database.
func (w *reorgWorkflow) storedFile(t *testing.T, h holding) *proof.File {
	t.Helper()

	blob, err := w.assetsStore.FetchProof(context.Background(), h.locator())
	require.NoError(t, err)
	file, err := blob.AsFile()
	require.NoError(t, err)

	return file
}

// issue issues an asset on the chain and imports it as a holding, the way
// any verified proof enters the wallet.
func (w *reorgWorkflow) issue(t *testing.T) holding {
	t.Helper()

	ctx := context.Background()
	genesisProof, issuerPriv := proof.RandAnchoredGenesisProof(t, w.anchor)
	file := proof.NewEmptyFile(proof.V0)
	require.NoError(t, file.AppendProof(genesisProof))
	snapshot := w.verify(t, file)

	var fileBuf bytes.Buffer
	require.NoError(t, file.Encode(&fileBuf))
	require.NoError(t, w.assetsStore.importAssetFromProof(
		ctx, w.assetsStore.db, &proof.AnnotatedProof{
			Locator: proof.Locator{
				AssetID:   fn.Ptr(snapshot.Asset.ID()),
				ScriptKey: *snapshot.Asset.ScriptKey.PubKey,
				OutPoint:  &snapshot.OutPoint,
			},
			Blob:          fileBuf.Bytes(),
			AssetSnapshot: snapshot,
		},
	))

	return holding{
		assetID:   snapshot.Asset.ID(),
		scriptKey: snapshot.Asset.ScriptKey.PubKey,
		priv:      issuerPriv,
		outPoint:  snapshot.OutPoint,
		tx:        &genesisProof.AnchorTx,
		height:    genesisProof.BlockHeight,
		amount:    snapshot.Asset.Amount,
	}
}

// packetInput describes a holding as a virtual input: its asset with the
// signing key attached, and the anchor output it sits in.
func (w *reorgWorkflow) packetInput(t *testing.T,
	h holding) (*tappsbt.VInput, *asset.Asset) {

	t.Helper()

	tip, err := w.storedFile(t, h).LastProof()
	require.NoError(t, err)
	keyDesc := w.keys.add(h.priv)
	inputAsset := tip.Asset.Copy()
	inputAsset.ScriptKey = asset.NewScriptKeyBip86(keyDesc)
	anchorOut := tip.AnchorTx.TxOut[tip.InclusionProof.OutputIndex]
	bip32, trBip32 := tappsbt.Bip32DerivationFromKeyDesc(
		keyDesc, address.RegressionNetTap.HDCoinType,
	)

	vIn := &tappsbt.VInput{
		PrevID: asset.PrevID{
			OutPoint:  h.outPoint,
			ID:        h.assetID,
			ScriptKey: asset.ToSerialized(h.scriptKey),
		},
		Anchor: tappsbt.Anchor{
			Value:       btcutil.Amount(anchorOut.Value),
			PkScript:    anchorOut.PkScript,
			SigHashType: txscript.SigHashDefault,
			InternalKey: tip.InclusionProof.InternalKey,
		},
		Proof: tip,
	}
	vIn.SighashType = txscript.SigHashDefault
	vIn.Bip32Derivation = []*psbt.Bip32Derivation{bip32}
	vIn.TaprootBip32Derivation = []*psbt.TaprootBip32Derivation{trBip32}

	return vIn, inputAsset
}

// transfer moves assets the way the porter does, short of the wallet: the
// virtual packets are built, signed and anchored with the porter's own
// primitives, the parcel is registered before its anchor transaction is
// mined, and the watcher's delivery of the confirmation writes the
// transfer's proofs. Passives are holdings sharing an input's anchor output
// without being spent; they are re-anchored alongside, as the wallet would.
func (w *reorgWorkflow) transfer(t *testing.T, sends []send,
	passives []holding) transferResult {

	t.Helper()

	ctx := context.Background()
	params := &address.RegressionNetTap
	validator := vmWitnessValidator{}

	// One internal key per anchor output, shared by every packet that
	// anchors there.
	anchorKeys := make(map[uint32]keychain.KeyDescriptor)
	anchorKey := func(index uint32) keychain.KeyDescriptor {
		desc, ok := anchorKeys[index]
		if !ok {
			desc = test.PubToKeyDesc(test.RandPrivKey().PubKey())
			anchorKeys[index] = desc
		}

		return desc
	}

	var (
		active   []*tappsbt.VPacket
		outPrivs [][]*btcec.PrivateKey
	)
	for _, s := range sends {
		pkt := &tappsbt.VPacket{
			ChainParams: params,
			Version:     tappsbt.V1,
		}
		for _, in := range s.inputs {
			vIn, inputAsset := w.packetInput(t, in)
			pkt.Inputs = append(pkt.Inputs, vIn)
			pkt.SetInputAsset(len(pkt.Inputs)-1, inputAsset)
		}

		version := pkt.Inputs[0].Asset().Version
		var privs []*btcec.PrivateKey
		for _, out := range s.outputs {
			priv := test.RandPrivKey()
			privs = append(privs, priv)
			vOut := &tappsbt.VOutput{
				Amount:            out.amount,
				AssetVersion:      version,
				Interactive:       true,
				AnchorOutputIndex: out.anchorIndex,
				ScriptKey: asset.NewScriptKeyBip86(
					w.keys.add(priv),
				),
			}
			if out.splitRoot {
				vOut.Type = tappsbt.TypeSplitRoot
			}
			vOut.SetAnchorInternalKey(
				anchorKey(out.anchorIndex), params.HDCoinType,
			)
			pkt.Outputs = append(pkt.Outputs, vOut)
		}

		require.NoError(t, tapsend.PrepareOutputAssets(ctx, pkt))
		require.NoError(t, tapsend.SignVirtualTransaction(
			pkt, w.keys, validator,
		))
		active = append(active, pkt)
		outPrivs = append(outPrivs, privs)
	}

	// Passives ride in the split root's output when there is one, and
	// otherwise in the first output, as the wallet chooses.
	passiveIndex := sends[0].outputs[0].anchorIndex
	for _, s := range sends {
		for _, out := range s.outputs {
			if out.splitRoot {
				passiveIndex = out.anchorIndex
			}
		}
	}
	var passivePkts []*tappsbt.VPacket
	for _, p := range passives {
		vIn, inputAsset := w.packetInput(t, p)
		outputAsset := inputAsset.CopySpendTemplate()
		outputAsset.PrevWitnesses = []asset.Witness{{
			PrevID: &vIn.PrevID,
		}}
		vOut := &tappsbt.VOutput{
			Amount:            outputAsset.Amount,
			AssetVersion:      outputAsset.Version,
			Interactive:       true,
			AnchorOutputIndex: passiveIndex,
			ScriptKey:         outputAsset.ScriptKey,
			Asset:             outputAsset,
		}
		vOut.SetAnchorInternalKey(
			anchorKey(passiveIndex), params.HDCoinType,
		)
		pkt := &tappsbt.VPacket{
			Inputs:      []*tappsbt.VInput{vIn},
			Outputs:     []*tappsbt.VOutput{vOut},
			ChainParams: params,
			Version:     tappsbt.V1,
		}
		pkt.SetInputAsset(0, inputAsset)
		require.NoError(t, tapsend.SignVirtualTransaction(
			pkt, w.keys, validator,
		))
		passivePkts = append(passivePkts, pkt)
	}

	// The anchor transaction commits every packet; its inputs are the
	// anchor outputs the packets spend.
	all := append(append([]*tappsbt.VPacket{}, active...), passivePkts...)
	outputCommitments, err := tapsend.CreateOutputCommitments(all)
	require.NoError(t, err)
	sendPacket, err := tapsend.CreateAnchorTx(all)
	require.NoError(t, err)
	for _, pkt := range all {
		for _, vIn := range pkt.Inputs {
			if tapsend.HasInput(
				sendPacket.UnsignedTx, vIn.PrevID.OutPoint,
			) {

				continue
			}

			input := psbt.PInput{
				WitnessUtxo: &wire.TxOut{
					Value:    int64(vIn.Anchor.Value),
					PkScript: vIn.Anchor.PkScript,
				},
				SighashType: vIn.Anchor.SigHashType,
				TaprootInternalKey: schnorr.SerializePubKey(
					vIn.Anchor.InternalKey,
				),
			}
			sendPacket.Inputs = append(sendPacket.Inputs, input)
			sendPacket.UnsignedTx.TxIn = append(
				sendPacket.UnsignedTx.TxIn, &wire.TxIn{
					PreviousOutPoint: vIn.PrevID.OutPoint,
				},
			)
		}
	}
	for _, pkt := range all {
		require.NoError(t, tapsend.UpdateTaprootOutputKeys(
			sendPacket, pkt, outputCommitments,
		))
	}
	finalTx := sendPacket.UnsignedTx
	for _, pkt := range all {
		for outIdx := range pkt.Outputs {
			suffix, err := tapsend.CreateProofSuffix(
				finalTx, sendPacket.Outputs, pkt,
				outputCommitments, outIdx, all,
			)
			require.NoError(t, err)
			pkt.Outputs[outIdx].ProofSuffix = suffix
		}
	}
	anchorTx := &tapsend.AnchorTransaction{
		FundedPsbt: &tapsend.FundedPsbt{
			Pkt:               sendPacket,
			ChangeOutputIndex: -1,
		},
		FinalTx: finalTx,
	}
	parcel, err := tapfreighter.ConvertToTransfer(
		w.sim.BestHeight(), active, anchorTx, passivePkts, nil,
		func(asset.ScriptKey) (bool, error) { return true, nil },
		"", false,
	)
	require.NoError(t, err)

	// Registered before it is mined, as the porter registers before it
	// broadcasts. The watcher senses the confirmation, and its delivery
	// writes the transfer's proofs.
	id, err := w.porter.RegisterParcel(ctx, parcel)
	require.NoError(t, err)
	height := w.sim.MineBlock(finalTx)
	require.Eventually(t, func() bool {
		return w.witnessedAt(id, height)
	}, 30*time.Second, 10*time.Millisecond)

	result := transferResult{
		tx:        finalTx,
		height:    height,
		anchoring: id,
	}
	for sIdx, s := range sends {
		var outs []holding
		for oIdx, out := range s.outputs {
			vOut := active[sIdx].Outputs[oIdx]
			outs = append(outs, holding{
				assetID:   s.inputs[0].assetID,
				scriptKey: vOut.ScriptKey.PubKey,
				priv:      outPrivs[sIdx][oIdx],
				outPoint: wire.OutPoint{
					Hash:  finalTx.TxHash(),
					Index: out.anchorIndex,
				},
				tx:     finalTx,
				height: height,
				amount: out.amount,
			})
		}
		result.outputs = append(result.outputs, outs)
	}
	for _, p := range passives {
		p.outPoint = wire.OutPoint{
			Hash:  finalTx.TxHash(),
			Index: passiveIndex,
		}
		p.tx = finalTx
		p.height = height
		result.passives = append(result.passives, p)
	}

	return result
}

// sendAll moves a holding whole to a fresh key.
func (w *reorgWorkflow) sendAll(t *testing.T, h holding) transferResult {
	t.Helper()

	return w.transfer(t, []send{{
		inputs:  []holding{h},
		outputs: []sendOutput{{amount: h.amount}},
	}}, nil)
}

// tip is the last proof of a holding's stored file.
func (w *reorgWorkflow) tip(t *testing.T, h holding) *proof.Proof {
	t.Helper()

	tip, err := w.storedFile(t, h).LastProof()
	require.NoError(t, err)

	return tip
}

// moveOneBlockLater re-orgs the transactions, oldest first, into the blocks
// one later than they confirmed in. The chain gains one block on top.
func (w *reorgWorkflow) moveOneBlockLater(t *testing.T,
	oldest transferResult, later ...transferResult) {

	t.Helper()

	depth := int(w.sim.BestHeight() - oldest.height + 1)
	replacement := [][]*wire.MsgTx{nil, {oldest.tx}}
	for _, r := range later {
		replacement = append(replacement, []*wire.MsgTx{r.tx})
	}
	w.sim.Reorg(depth, replacement...)
	w.sim.MineBlocks(1)
}

// awaitMoved waits until a transfer is witnessed one block later than it
// first confirmed, and delivered as such.
func (w *reorgWorkflow) awaitMoved(t *testing.T, r transferResult) {
	t.Helper()

	require.Eventually(t, func() bool {
		return w.witnessedAt(r.anchoring, r.height+1)
	}, 30*time.Second, 10*time.Millisecond)
}

// requireCurrent asserts every proof in a file, at any depth, carries the
// header of the block now at its height. The label names the file.
func (w *reorgWorkflow) requireCurrent(t *testing.T, label string,
	file *proof.File) {

	t.Helper()

	ctx := context.Background()
	for idx := 0; idx < file.NumProofs(); idx++ {
		p, err := file.ProofAt(uint32(idx))
		require.NoError(t, err)
		for inputIdx := range p.AdditionalInputs {
			w.requireCurrent(
				t, fmt.Sprintf("%s input %d", label, inputIdx),
				&p.AdditionalInputs[inputIdx],
			)
		}

		hash, err := w.sim.GetBlockHash(ctx, int64(p.BlockHeight))
		require.NoError(t, err)
		require.Equal(t, hash, p.BlockHeader.BlockHash(),
			"%s: transaction %v at height %d carries a stale "+
				"header", label, p.AnchorTx.TxHash(),
			p.BlockHeight)
	}
}

// witnessedAt reports whether an anchoring is witnessed at the height and
// delivered as such.
func (w *reorgWorkflow) witnessedAt(id tapreorg.AnchoringID,
	height uint32) bool {

	anchoring, err := w.registry.GetAnchoring(context.Background(), id)
	if err != nil {
		return false
	}
	witnessed, ok := anchoring.Phase.(tapreorg.Witnessed)

	return ok && witnessed.W.Height() == height && tapreorg.PhaseEqual(
		anchoring.DeliveredPhase, anchoring.Phase,
	)
}

// TestPorterReorgRepairsHeldHistory is the ordinary workflow the watcher
// exists for: two young outgoing transfers in a chain, a re-org that moves
// them both, and afterwards every stored proof describing the chain as it is
// now — verifiable, and fit to build the next transfer on. Deliveries for
// different anchorings carry no mutual order, so the test pins the harder
// one: the later transfer's confirmation is re-applied before the earlier
// one's, and the earlier one's repair must still reach the later file.
func TestPorterReorgRepairsHeldHistory(t *testing.T) {
	t.Parallel()

	const threshold = 6
	ctx := context.Background()
	w := newReorgWorkflow(t, threshold)

	genesis := w.issue(t)
	first := w.sendAll(t, genesis)
	second := w.sendAll(t, first.first())

	// The re-org moves both transfers one block later. The earlier
	// transfer's confirmation is held back until the later one has been
	// re-applied.
	w.porterLog.held = first.tx.TxHash()
	w.porterLog.released.Store(false)
	w.moveOneBlockLater(t, first, second)
	w.awaitMoved(t, second)
	w.porterLog.released.Store(true)
	w.awaitMoved(t, first)

	// Every stored proof describes the chain as it is now, at every
	// depth: the files the moved transfers own, and then the later file
	// whose history holds the earlier transfer.
	rows, err := w.db.FetchAssetProofs(ctx)
	require.NoError(t, err)
	require.Len(t, rows, 3)
	w.requireCurrent(t, "genesis file", w.storedFile(t, genesis))
	w.requireCurrent(t, "first transfer's file", w.storedFile(
		t, first.first(),
	))
	w.requireCurrent(t, "second transfer's file", w.storedFile(
		t, second.first(),
	))

	// The holding verifies against the chain and can be built on.
	held := second.first()
	file := w.storedFile(t, held)
	w.verify(t, file)
	proof.AppendRandTransfer(t, file, held.priv, w.anchor)
	w.verify(t, file)

	// The repair changed nothing about what the wallet holds.
	assets, err := w.assetsStore.FetchAllAssets(ctx, false, false, nil)
	require.NoError(t, err)
	require.Len(t, assets, 1)
	require.True(t, assets[0].ScriptKey.PubKey.IsEqual(held.scriptKey))
}

// TestPorterReorgRepairsNestedHistory is the workflow the proof DAG exists
// for: a holding split in two and the parts merged again, so the merged
// file carries one part's history nested inside its tip. A re-org moves the
// split and the merge, the split's confirmation is held back until the
// merge has been re-applied, and the split's repair must still reach its
// occurrence inside the nested file.
func TestPorterReorgRepairsNestedHistory(t *testing.T) {
	t.Parallel()

	const threshold = 6
	ctx := context.Background()
	w := newReorgWorkflow(t, threshold)

	genesis := w.issue(t)
	split := w.transfer(t, []send{{
		inputs: []holding{genesis},
		outputs: []sendOutput{
			{amount: 60, anchorIndex: 0, splitRoot: true},
			{amount: 40, anchorIndex: 1},
		},
	}}, nil)
	change, part := split.outputs[0][0], split.outputs[0][1]
	merge := w.transfer(t, []send{{
		inputs:  []holding{change, part},
		outputs: []sendOutput{{amount: 100}},
	}}, nil)
	merged := merge.first()

	// The merged file nests the other part's history at its tip.
	require.Len(t, w.tip(t, merged).AdditionalInputs, 1)

	w.porterLog.held = split.tx.TxHash()
	w.porterLog.released.Store(false)
	w.moveOneBlockLater(t, split, merge)
	w.awaitMoved(t, merge)
	w.porterLog.released.Store(true)
	w.awaitMoved(t, split)

	// Every stored file is current at every depth, the nested history
	// included.
	w.requireCurrent(t, "genesis file", w.storedFile(t, genesis))
	w.requireCurrent(t, "change file", w.storedFile(t, change))
	w.requireCurrent(t, "part file", w.storedFile(t, part))
	w.requireCurrent(t, "merged file", w.storedFile(t, merged))

	// The merged holding verifies against the chain and can be built on.
	file := w.storedFile(t, merged)
	w.verify(t, file)
	proof.AppendRandTransfer(t, file, merged.priv, w.anchor)
	w.verify(t, file)

	assets, err := w.assetsStore.FetchAllAssets(ctx, false, false, nil)
	require.NoError(t, err)
	require.Len(t, assets, 1)
	require.True(t, assets[0].ScriptKey.PubKey.IsEqual(merged.scriptKey))
}

// TestPorterReorgRepairsPassiveHolding is the workflow of a holding that
// moves without being sent: two assets share an anchor output, one is sent
// on, and the other is re-anchored alongside as a passive, its file gaining
// a transition of its own in the send. A re-org moves both the joining and
// the send, the joining's confirmation is held back until the send has been
// re-applied, and the passive's file must end current at every depth.
func TestPorterReorgRepairsPassiveHolding(t *testing.T) {
	t.Parallel()

	const threshold = 6
	ctx := context.Background()
	w := newReorgWorkflow(t, threshold)

	first, second := w.issue(t), w.issue(t)
	joined := w.transfer(t, []send{
		{
			inputs:  []holding{first},
			outputs: []sendOutput{{amount: first.amount}},
		},
		{
			inputs:  []holding{second},
			outputs: []sendOutput{{amount: second.amount}},
		},
	}, nil)
	active, passive := joined.outputs[0][0], joined.outputs[1][0]
	moved := w.transfer(t, []send{{
		inputs:  []holding{active},
		outputs: []sendOutput{{amount: active.amount}},
	}}, []holding{passive})
	sent, ridden := moved.first(), moved.passives[0]

	// The passive's file gained a transition anchored in the send, under
	// the key it already had.
	riddenTip := w.tip(t, ridden)
	require.Equal(t, moved.tx.TxHash(), riddenTip.AnchorTx.TxHash())
	require.True(t, riddenTip.Asset.ScriptKey.PubKey.IsEqual(
		passive.scriptKey,
	))

	w.porterLog.held = joined.tx.TxHash()
	w.porterLog.released.Store(false)
	w.moveOneBlockLater(t, joined, moved)
	w.awaitMoved(t, moved)
	w.porterLog.released.Store(true)
	w.awaitMoved(t, joined)

	w.requireCurrent(t, "first genesis file", w.storedFile(t, first))
	w.requireCurrent(t, "second genesis file", w.storedFile(t, second))
	w.requireCurrent(t, "active's joined file", w.storedFile(t, active))
	w.requireCurrent(t, "sent file", w.storedFile(t, sent))
	w.requireCurrent(t, "passive's file", w.storedFile(t, ridden))

	// Both holdings verify against the chain, and the passive can be
	// spent from where it now sits.
	w.verify(t, w.storedFile(t, sent))
	file := w.storedFile(t, ridden)
	w.verify(t, file)
	proof.AppendRandTransfer(t, file, ridden.priv, w.anchor)
	w.verify(t, file)

	assets, err := w.assetsStore.FetchAllAssets(ctx, false, false, nil)
	require.NoError(t, err)
	require.Len(t, assets, 2)
}
