package tapcustody

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapreorg"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// singleProofGenesisFile returns a single-proof file whose tip has no
// prior asset outpoint — the shape of a genesis-shaped receive.
func singleProofGenesisFile(t *testing.T,
	anchorTx *wire.MsgTx) *proof.File {

	t.Helper()

	scriptKey := asset.NewScriptKey(test.RandPubKey(t))
	p := proof.Proof{
		PrevOut: wire.OutPoint{}, // No prior outpoint: genesis.
		BlockHeader: wire.BlockHeader{
			Version:    1,
			MerkleRoot: chainhash.Hash{0xaa, 0xbb},
		},
		BlockHeight:   700,
		AnchorTx:      *anchorTx,
		TxMerkleProof: proof.TxMerkleProof{},
		Asset: asset.Asset{
			Version:   asset.V0,
			Amount:    1_000,
			ScriptKey: scriptKey,
			PrevWitnesses: []asset.Witness{
				{PrevID: &asset.PrevID{}},
			},
		},
		InclusionProof: proof.TaprootProof{
			InternalKey: test.RandPubKey(t),
			OutputIndex: 0,
		},
	}
	file, err := proof.NewFile(proof.V0, p)
	require.NoError(t, err)

	return file
}

// TestRegisterReceiveAnchoringGenesisShape asserts that a single-proof
// genesis file — no derivable asset-bearing trigger — takes the seed
// path: the anchor tx is recorded as the anchoring's candidate spend
// directly, without a trigger set to watch.
func TestRegisterReceiveAnchoringGenesisShape(t *testing.T) {
	t.Parallel()

	registrar := tapreorg.NewMockRegistrar()
	c := &Custodian{
		cfg: &Config{
			AnchoringWatcher:   registrar,
			AnchoringThreshold: 6,
		},
	}

	fundingOp := wire.OutPoint{Hash: chainhash.Hash{0x11}, Index: 0}
	anchorTx := wire.NewMsgTx(2)
	anchorTx.AddTxIn(wire.NewTxIn(&fundingOp, nil, nil))
	anchorTx.AddTxOut(wire.NewTxOut(1_000, []byte{0x51, 0xaa}))

	file := singleProofGenesisFile(t, anchorTx)
	require.NoError(t, c.RegisterReceiveAnchoring(
		context.Background(), file, nil,
	))

	anchorings, err := registrar.AllAnchorings(
		context.Background(), ReceiveSiteID,
	)
	require.NoError(t, err)
	require.Len(t, anchorings, 1)

	a := anchorings[0]

	// A genesis-shape registration passes an empty trigger set —
	// the seed candidate is what's watched.
	require.Zero(t, a.Triggers.Len())

	// The seed is durably recorded and the mock's phase reflects
	// the immediate Witnessed state (production's watcher would
	// reach the same phase through the conf subscription on the
	// candidate).
	require.Len(t, a.Spends, 1)
	require.Equal(t, anchorTx.TxHash(), a.Spends[0].W.TxHash())
	require.True(t, a.Spends[0].OnChain)
	require.NotNil(t, a.Spends[0].BlockHeader)
	require.NotNil(t, a.Spends[0].MerkleProof)
	require.IsType(t, tapreorg.Witnessed{}, a.Phase)
}

// TestRegisterReceiveAnchoringGenesisShapeIdempotent asserts the
// genesis-shape path is idempotent per anchor transaction: a
// second registration for the same file does not create a duplicate
// anchoring, matching the multi-proof path's contract.
func TestRegisterReceiveAnchoringGenesisShapeIdempotent(t *testing.T) {
	t.Parallel()

	registrar := tapreorg.NewMockRegistrar()
	c := &Custodian{
		cfg: &Config{
			AnchoringWatcher:   registrar,
			AnchoringThreshold: 6,
		},
	}

	fundingOp := wire.OutPoint{Hash: chainhash.Hash{0x22}, Index: 0}
	anchorTx := wire.NewMsgTx(2)
	anchorTx.AddTxIn(wire.NewTxIn(&fundingOp, nil, nil))
	anchorTx.AddTxOut(wire.NewTxOut(1_000, []byte{0x51, 0xbb}))

	file := singleProofGenesisFile(t, anchorTx)
	ctx := context.Background()
	require.NoError(t, c.RegisterReceiveAnchoring(ctx, file, nil))
	require.NoError(t, c.RegisterReceiveAnchoring(ctx, file, nil))

	anchorings, err := registrar.AllAnchorings(ctx, ReceiveSiteID)
	require.NoError(t, err)
	require.Len(t, anchorings, 1)
}

// TestReceiveTriggerPointsGenesisShape pins the current signal from
// receiveTriggerPoints for genesis-shaped files: it returns
// ErrNoTriggers, which RegisterReceiveAnchoring routes onto the seed
// path.
func TestReceiveTriggerPointsGenesisShape(t *testing.T) {
	t.Parallel()

	anchorTx := wire.NewMsgTx(2)
	anchorTx.AddTxIn(wire.NewTxIn(&wire.OutPoint{}, nil, nil))
	anchorTx.AddTxOut(wire.NewTxOut(1_000, []byte{0x51, 0xcc}))

	file := singleProofGenesisFile(t, anchorTx)
	tip, err := file.ProofAt(0)
	require.NoError(t, err)

	_, err = receiveTriggerPoints(file, tip)
	require.ErrorIs(t, err, ErrNoTriggers)
}

// TestTipSeedCandidateFromFile asserts the seed candidate built
// from a genesis-shaped file's tip is fully enriched: witness located,
// block header and merkle proof carried, satisfying verdict.
func TestTipSeedCandidateFromFile(t *testing.T) {
	t.Parallel()

	anchorTx := wire.NewMsgTx(2)
	anchorTx.AddTxIn(wire.NewTxIn(&wire.OutPoint{}, nil, nil))
	anchorTx.AddTxOut(wire.NewTxOut(1_000, []byte{0x51, 0xdd}))

	file := singleProofGenesisFile(t, anchorTx)
	tip, err := file.ProofAt(0)
	require.NoError(t, err)

	seed, err := tipSeedCandidate(tip)
	require.NoError(t, err)

	require.Equal(t, anchorTx.TxHash(), seed.W.TxHash())
	require.Equal(t, tip.BlockHeight, seed.W.Height())
	require.True(t, seed.OnChain)
	require.Equal(t, tapreorg.VerdictSatisfies, seed.Verdict)
	require.False(t, seed.ActCertified)
	require.NotNil(t, seed.BlockHeader)
	require.NotNil(t, seed.MerkleProof)

	// The tip's own tx round-trips through the witness.
	var recovered bytes.Buffer
	require.NoError(t, seed.W.Tx().Serialize(&recovered))
	var original bytes.Buffer
	require.NoError(t, anchorTx.Serialize(&original))
	require.Equal(t, original.Bytes(), recovered.Bytes())
}

// TestRegisterReceiveAnchoringSeedsTip asserts that a file with
// derivable triggers registers on both: the trigger set the sensor
// watches for foreign spenders, and the tip's own confirmation as the
// seed the anchoring is born delivered on. A second registration for
// the same anchor tx (another output of the same send) attaches to
// that anchoring, whose delivered phase is the seed's Witnessed.
func TestRegisterReceiveAnchoringSeedsTip(t *testing.T) {
	t.Parallel()

	registrar := tapreorg.NewMockRegistrar()
	c := &Custodian{
		cfg: &Config{
			AnchoringWatcher:   registrar,
			AnchoringThreshold: 6,
		},
	}

	inputTx := wire.NewMsgTx(2)
	inputTx.AddTxIn(wire.NewTxIn(&wire.OutPoint{}, nil, nil))
	inputTx.AddTxOut(wire.NewTxOut(1_000, test.RandBytes(34)))
	inputTx.TxOut[0].PkScript[0], inputTx.TxOut[0].PkScript[1] = 0x51, 0x20

	anchorTx := wire.NewMsgTx(2)
	anchorTx.AddTxIn(wire.NewTxIn(&wire.OutPoint{
		Hash: inputTx.TxHash(), Index: 0,
	}, nil, nil))
	anchorTx.AddTxOut(wire.NewTxOut(1_000, []byte{0x51, 0xaa}))

	file := trimmedTransferFile(t, anchorTx, inputTx)
	tip, err := file.ProofAt(0)
	require.NoError(t, err)
	require.NotZero(t, tip.BlockHeight)

	ctx := context.Background()
	require.NoError(t, c.RegisterReceiveAnchoring(ctx, file, nil))
	require.NoError(t, c.RegisterReceiveAnchoring(ctx, file, nil))

	anchorings, err := registrar.AllAnchorings(ctx, ReceiveSiteID)
	require.NoError(t, err)
	require.Len(t, anchorings, 1)

	anchoring := anchorings[0]
	require.Equal(t, 1, anchoring.Triggers.Len())
	require.Len(t, anchoring.Spends, 1)
	require.Equal(t, anchorTx.TxHash(), anchoring.Spends[0].W.TxHash())
	require.Equal(t, tip.BlockHeight, anchoring.Spends[0].W.Height())
	require.False(t, anchoring.Spends[0].ActCertified)
	require.IsType(t, tapreorg.Witnessed{}, anchoring.Phase)
	require.IsType(t, tapreorg.Witnessed{}, anchoring.DeliveredPhase)
}

// TestRegisterReceiveAnchoringUnwatchable asserts that a genesis-shape
// file with no block context returns ErrUnwatchable: callers see the
// outcome legibly rather than mistaking a warning-log-and-nil for
// successful registration.
func TestRegisterReceiveAnchoringUnwatchable(t *testing.T) {
	t.Parallel()

	registrar := tapreorg.NewMockRegistrar()
	c := &Custodian{
		cfg: &Config{
			AnchoringWatcher:   registrar,
			AnchoringThreshold: 6,
		},
	}

	fundingOp := wire.OutPoint{Hash: chainhash.Hash{0x33}, Index: 0}
	anchorTx := wire.NewMsgTx(2)
	anchorTx.AddTxIn(wire.NewTxIn(&fundingOp, nil, nil))
	anchorTx.AddTxOut(wire.NewTxOut(1_000, []byte{0x51, 0xee}))

	// singleProofGenesisFile sets BlockHeight to 700; force the stub
	// case by rebuilding a proof file with height 0.
	scriptKey := asset.NewScriptKey(test.RandPubKey(t))
	p := proof.Proof{
		PrevOut:       wire.OutPoint{},
		BlockHeader:   wire.BlockHeader{Version: 1},
		BlockHeight:   0,
		AnchorTx:      *anchorTx,
		TxMerkleProof: proof.TxMerkleProof{},
		Asset: asset.Asset{
			Version:   asset.V0,
			Amount:    1_000,
			ScriptKey: scriptKey,
			PrevWitnesses: []asset.Witness{
				{PrevID: &asset.PrevID{}},
			},
		},
		InclusionProof: proof.TaprootProof{
			InternalKey: test.RandPubKey(t),
			OutputIndex: 0,
		},
	}
	file, err := proof.NewFile(proof.V0, p)
	require.NoError(t, err)

	err = c.RegisterReceiveAnchoring(context.Background(), file, nil)
	require.ErrorIs(t, err, ErrUnwatchable)

	// Nothing was registered.
	anchorings, err := registrar.AllAnchorings(
		context.Background(), ReceiveSiteID,
	)
	require.NoError(t, err)
	require.Empty(t, anchorings)
}

// TestReceiveBlobRoundTrip asserts that every receive blob survives
// the encode/decode round trip, and that the encoding is canonical:
// the decoded value re-encodes to identical bytes.
func TestReceiveBlobRoundTrip(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(rt *rapid.T) {
		var txid chainhash.Hash
		copy(txid[:], rapid.SliceOfN(rapid.Byte(), 32, 32).Draw(
			rt, "txid",
		))

		encoded := encodeReceiveBlob(txid)
		decoded, err := decodeReceiveBlob(encoded)
		require.NoError(rt, err)
		require.Equal(rt, txid, decoded)

		require.Equal(rt, encoded, encodeReceiveBlob(decoded))
	})
}

// TestReceiveBlobDecodeRejects asserts the decoder rejects unknown
// versions and payloads of the wrong length.
func TestReceiveBlobDecodeRejects(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(rt *rapid.T) {
		data := rapid.SliceOfN(rapid.Byte(), 0, 64).Draw(rt, "data")

		version := rapid.Uint16().Draw(rt, "version")
		_, err := decodeReceiveBlob(tapreorg.VersionedBlob{
			Version: version,
			Data:    data,
		})

		switch {
		case version != receiveBlobVersion:
			require.ErrorContains(rt, err, "unknown receive "+
				"blob version")

		case len(data) != 32:
			require.ErrorContains(rt, err, "receive blob has")

		default:
			require.NoError(rt, err)
		}
	})
}

// TestReceiveTriggerPointsSharedOutpoint asserts that inputs sharing
// one chain outpoint — several asset leaves under a single UTXO,
// merged in one transition — contribute a single trigger point:
// triggers are chain-level, and a duplicate would fail registration.
func TestReceiveTriggerPointsSharedOutpoint(t *testing.T) {
	t.Parallel()

	makeProofAt := func(anchorTx *wire.MsgTx,
		outputIndex uint32) proof.Proof {

		return proof.Proof{
			PrevOut: wire.OutPoint{Hash: chainhash.Hash{0x01}},
			BlockHeader: wire.BlockHeader{
				Version:    1,
				MerkleRoot: chainhash.Hash{0xaa},
			},
			BlockHeight: 700,
			AnchorTx:    *anchorTx,
			Asset: asset.Asset{
				Version: asset.V0,
				Amount:  1_000,
				ScriptKey: asset.NewScriptKey(
					test.RandPubKey(t),
				),
				PrevWitnesses: []asset.Witness{
					{PrevID: &asset.PrevID{}},
				},
			},
			InclusionProof: proof.TaprootProof{
				InternalKey: test.RandPubKey(t),
				OutputIndex: outputIndex,
			},
		}
	}

	prevTx := wire.NewMsgTx(2)
	prevTx.AddTxIn(wire.NewTxIn(&wire.OutPoint{}, nil, nil))
	prevTx.AddTxOut(wire.NewTxOut(1_000, []byte{0x51, 0xaa}))

	otherTx := wire.NewMsgTx(2)
	otherTx.AddTxIn(wire.NewTxIn(&wire.OutPoint{Index: 7}, nil, nil))
	otherTx.AddTxOut(wire.NewTxOut(1_000, []byte{0x51, 0xbb}))

	tipTx := wire.NewMsgTx(2)
	tipTx.AddTxIn(wire.NewTxIn(&wire.OutPoint{
		Hash: prevTx.TxHash(),
	}, nil, nil))
	tipTx.AddTxIn(wire.NewTxIn(&wire.OutPoint{
		Hash: otherTx.TxHash(),
	}, nil, nil))
	tipTx.AddTxOut(wire.NewTxOut(900, []byte{0x51, 0xcc}))

	prevProof := makeProofAt(prevTx, 0)
	tipProof := makeProofAt(tipTx, 0)
	tipProof.PrevOut = wire.OutPoint{Hash: prevTx.TxHash(), Index: 0}

	// One additional input at the same outpoint as the tip's
	// primary previous outpoint, one at a distinct outpoint.
	sameFile, err := proof.NewFile(proof.V0, makeProofAt(prevTx, 0))
	require.NoError(t, err)
	otherFile, err := proof.NewFile(proof.V0, makeProofAt(otherTx, 0))
	require.NoError(t, err)
	tipProof.AdditionalInputs = []proof.File{*sameFile, *otherFile}

	file, err := proof.NewFile(proof.V0, prevProof, tipProof)
	require.NoError(t, err)

	points, err := receiveTriggerPoints(file, &tipProof)
	require.NoError(t, err)
	require.Len(t, points, 2)
	require.Equal(t, tipProof.PrevOut, points[0].OutPoint)
	require.Equal(t, wire.OutPoint{
		Hash:  otherTx.TxHash(),
		Index: 0,
	}, points[1].OutPoint)

	// The deduped set registers cleanly.
	_, err = tapreorg.NewTriggerSet(points)
	require.NoError(t, err)
}

// TestReceiveTriggerPointsAnchorInputsOnly pins the trigger set to
// the anchor transaction's own inputs: an additional-input file whose
// outpoint the tip transaction never spends contributes no trigger,
// so a sender cannot make a verified file refusable by attaching one.
func TestReceiveTriggerPointsAnchorInputsOnly(t *testing.T) {
	t.Parallel()

	makeProofAt := func(anchorTx *wire.MsgTx,
		outputIndex uint32) proof.Proof {

		return proof.Proof{
			PrevOut: wire.OutPoint{Hash: chainhash.Hash{0x01}},
			BlockHeader: wire.BlockHeader{
				Version:    1,
				MerkleRoot: chainhash.Hash{0xaa},
			},
			BlockHeight: 700,
			AnchorTx:    *anchorTx,
			Asset: asset.Asset{
				Version: asset.V0,
				Amount:  1_000,
				ScriptKey: asset.NewScriptKey(
					test.RandPubKey(t),
				),
				PrevWitnesses: []asset.Witness{
					{PrevID: &asset.PrevID{}},
				},
			},
			InclusionProof: proof.TaprootProof{
				InternalKey: test.RandPubKey(t),
				OutputIndex: outputIndex,
			},
		}
	}

	prevTx := wire.NewMsgTx(2)
	prevTx.AddTxIn(wire.NewTxIn(&wire.OutPoint{}, nil, nil))
	prevTx.AddTxOut(wire.NewTxOut(1_000, []byte{0x51, 0xaa}))

	// A spurious input file: a genuine proof for an outpoint the
	// tip transaction does not spend.
	strayTx := wire.NewMsgTx(2)
	strayTx.AddTxIn(wire.NewTxIn(&wire.OutPoint{Index: 9}, nil, nil))
	strayTx.AddTxOut(wire.NewTxOut(1_000, []byte{0x51, 0xee}))

	tipTx := wire.NewMsgTx(2)
	tipTx.AddTxIn(wire.NewTxIn(&wire.OutPoint{
		Hash: prevTx.TxHash(),
	}, nil, nil))
	tipTx.AddTxOut(wire.NewTxOut(900, []byte{0x51, 0xcc}))

	prevProof := makeProofAt(prevTx, 0)
	tipProof := makeProofAt(tipTx, 0)
	tipProof.PrevOut = wire.OutPoint{Hash: prevTx.TxHash(), Index: 0}

	strayFile, err := proof.NewFile(proof.V0, makeProofAt(strayTx, 0))
	require.NoError(t, err)
	tipProof.AdditionalInputs = []proof.File{*strayFile}

	file, err := proof.NewFile(proof.V0, prevProof, tipProof)
	require.NoError(t, err)

	points, err := receiveTriggerPoints(file, &tipProof)
	require.NoError(t, err)
	require.Len(t, points, 1)
	require.Equal(t, tipProof.PrevOut, points[0].OutPoint)

	// The registration the file derives carries exactly that
	// trigger, and its seed spends it: nothing for the registry's
	// whole-set rule to refuse.
	spec, err := receiveRegistrationSpec(file, 3)
	require.NoError(t, err)
	require.Equal(t, 1, spec.Triggers.Len())
	require.NotNil(t, spec.SeedCandidate)
	require.True(t, spec.Phase1OnAttach)
}

// phasedRegistrar answers every lookup with an anchoring in a fixed
// phase, standing in for a watcher that has already decided.
type phasedRegistrar struct {
	tapreorg.Registrar
	phase tapreorg.Phase
}

func (r *phasedRegistrar) LookupByMatchKey(_ context.Context,
	site tapreorg.SiteID, matchKey []byte) (*tapreorg.Anchoring, error) {

	return &tapreorg.Anchoring{
		ID:       1,
		Site:     site,
		MatchKey: matchKey,
		Phase:    r.phase,
	}, nil
}

// TestRefuseAbandonedReceive pins the source-side guard against
// re-importing a compensated receive: a file whose tip anchor
// transaction the receive site has abandoned is refused with
// ErrAnchoringAbandoned, while an unwatched, unknown or live receive
// passes.
func TestRefuseAbandonedReceive(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	fundingOp := wire.OutPoint{Hash: chainhash.Hash{0x33}, Index: 0}
	anchorTx := wire.NewMsgTx(2)
	anchorTx.AddTxIn(wire.NewTxIn(&fundingOp, nil, nil))
	anchorTx.AddTxOut(wire.NewTxOut(1_000, []byte{0x51, 0xcc}))
	file := singleProofGenesisFile(t, anchorTx)

	// No watcher: nothing to consult.
	require.NoError(t, RefuseAbandonedReceive(ctx, nil, file))

	// A watcher that has never seen the transaction.
	registrar := tapreorg.NewMockRegistrar()
	require.NoError(t, RefuseAbandonedReceive(ctx, registrar, file))

	// A live anchoring for it.
	c := &Custodian{cfg: &Config{
		AnchoringWatcher:   registrar,
		AnchoringThreshold: 6,
	}}
	require.NoError(t, c.RegisterReceiveAnchoring(ctx, file, nil))
	require.NoError(t, RefuseAbandonedReceive(ctx, registrar, file))

	// An abandoned one.
	abandoned := &phasedRegistrar{
		Registrar: registrar,
		phase:     tapreorg.Abandoned{},
	}
	err := RefuseAbandonedReceive(ctx, abandoned, file)
	require.ErrorIs(t, err, ErrAnchoringAbandoned)
}

// TestCustodianRefusesAbandonedImport drives the guard through the
// custodian's archive assertion, the path a proof re-delivered by the
// local universe takes: the proof of an abandoned receive is refused
// and the archive stays without it, while the same proof imports once
// the anchoring is live.
func TestCustodianRefusesAbandonedImport(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	fundingOp := wire.OutPoint{Hash: chainhash.Hash{0x44}, Index: 0}
	anchorTx := wire.NewMsgTx(2)
	anchorTx.AddTxIn(wire.NewTxIn(&fundingOp, nil, nil))
	anchorTx.AddTxOut(wire.NewTxOut(1_000, []byte{0x51, 0xdd}))
	file := singleProofGenesisFile(t, anchorTx)
	tip, err := file.LastProof()
	require.NoError(t, err)

	var blob bytes.Buffer
	require.NoError(t, file.Encode(&blob))
	annotated := &proof.AnnotatedProof{
		Locator: proof.Locator{
			AssetID:   fn.Ptr(tip.Asset.ID()),
			ScriptKey: *tip.Asset.ScriptKey.PubKey,
			OutPoint:  fn.Ptr(tip.OutPoint()),
		},
		Blob: blob.Bytes(),
	}

	archive, err := proof.NewFileArchiver(t.TempDir())
	require.NoError(t, err)
	mock := tapreorg.NewMockRegistrar()
	mock.RunPhase1(&tapreorg.MockRegistryTx{})
	registrar := &phasedRegistrar{
		Registrar: mock,
		phase:     tapreorg.Abandoned{},
	}
	c := NewCustodian(&Config{
		ProofArchive:     archive,
		AnchoringWatcher: registrar,
		AnchoringLog:     &archiveStakingLog{archive: archive},
		ProofVerifier:    stubVerifier{},
	})

	err = c.assertProofInLocalArchive(annotated)
	require.ErrorIs(t, err, ErrAnchoringAbandoned)
	has, err := archive.HasProof(ctx, annotated.Locator)
	require.NoError(t, err)
	require.False(t, has)

	// Once the watcher holds the receive as live, the stake imports
	// the proof in the registration's phase-1 write.
	registrar.phase = tapreorg.Witnessed{}
	require.NoError(t, c.assertProofInLocalArchive(annotated))
	has, err = archive.HasProof(ctx, annotated.Locator)
	require.NoError(t, err)
	require.True(t, has)
}

// stubVerifier accepts any decodable file, answering with its tip:
// the receive site's tests build synthetic proofs no chain can
// verify.
type stubVerifier struct{}

func (stubVerifier) Verify(_ context.Context, r io.Reader,
	_ proof.VerifierCtx, _ ...proof.VerifyOption) (*proof.AssetSnapshot,
	error) {

	f := &proof.File{}
	if err := f.Decode(r); err != nil {
		return nil, err
	}
	tip, err := f.LastProof()
	if err != nil {
		return nil, err
	}

	return &proof.AssetSnapshot{
		Asset:           &tip.Asset,
		OutPoint:        tip.OutPoint(),
		OutputIndex:     tip.InclusionProof.OutputIndex,
		AnchorBlockHash: tip.BlockHeader.BlockHash(),
		AnchorTx:        &tip.AnchorTx,
	}, nil
}

// archiveStakingLog stakes received proofs into a proof archive,
// standing in for the asset store's transaction-scoped import.
type archiveStakingLog struct {
	ReceiveAnchoringLog

	archive proof.Archiver
}

func (l *archiveStakingLog) StakeReceivedProofs(ctx context.Context,
	_ tapreorg.RegistryTx,
	proofs ...proof.VerifiedAnnotatedProof) ([]proof.Blob, error) {

	var imported []proof.Blob
	for _, verified := range proofs {
		p := verified.AnnotatedProof()
		has, err := l.archive.HasProof(ctx, p.Locator)
		if err != nil {
			return nil, err
		}
		if has {
			continue
		}
		err = l.archive.ImportProofs(
			ctx, proof.VerifierCtx{}, false, p,
		)
		if err != nil {
			return nil, err
		}
		imported = append(imported, p.Blob)
	}

	return imported, nil
}

func (l *archiveStakingLog) NotifyProofs(_ ...proof.Blob) {}

func (l *archiveStakingLog) HasReceivedProof(ctx context.Context,
	locator proof.Locator) (bool, error) {

	return l.archive.HasProof(ctx, locator)
}

// TestReceiveSiteEvaluateCandidate pins the receive site's verdict:
// exactly the received proof's anchor transaction satisfies the
// anchoring, any other spender of its inputs is foreign, and a match
// blob the site cannot decode is an error rather than a verdict. A
// transaction spending only part of the trigger set never reaches the
// predicate — the watcher judges it foreign by the whole-set rule — so
// it is not a case here.
func TestReceiveSiteEvaluateCandidate(t *testing.T) {
	t.Parallel()

	inputOp := test.RandOp(t)
	anchorTx := wire.NewMsgTx(2)
	anchorTx.AddTxIn(wire.NewTxIn(&inputOp, nil, nil))
	anchorTx.AddTxOut(wire.NewTxOut(1_000, []byte{0x51}))

	// A rival spends the same input to a different output.
	rivalTx := anchorTx.Copy()
	rivalTx.TxOut[0].Value++

	match := encodeReceiveBlob(anchorTx.TxHash())

	tests := []struct {
		name    string
		match   tapreorg.VersionedBlob
		spender *wire.MsgTx
		want    tapreorg.Verdict
		wantErr bool
	}{{
		name:    "received anchor transaction satisfies",
		match:   match,
		spender: anchorTx,
		want:    tapreorg.VerdictSatisfies,
	}, {
		name:    "other spender of the inputs is foreign",
		match:   match,
		spender: rivalTx,
		want:    tapreorg.VerdictForeign,
	}, {
		name: "undecodable match is an error",
		match: tapreorg.VersionedBlob{
			Version: receiveBlobVersion,
			Data:    []byte{0x01},
		},
		spender: anchorTx,
		wantErr: true,
	}}

	site := &receiveSite{}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			verdict, err := site.EvaluateCandidate(
				tc.match, tc.spender,
			)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, verdict)
		})
	}
}
