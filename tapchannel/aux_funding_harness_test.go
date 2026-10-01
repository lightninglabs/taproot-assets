package tapchannel

import (
	"bytes"
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	cmsg "github.com/lightninglabs/taproot-assets/tapchannelmsg"
	"github.com/lightninglabs/taproot-assets/tapscript"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/stretchr/testify/require"
)

// keySpendWitness signs a BIP86 key spend of the given virtual transaction
// input.
func keySpendWitness(t *testing.T, privKey *btcec.PrivateKey,
	virtualTx *wire.MsgTx, input, newAsset *asset.Asset,
	idx uint32) wire.TxWitness {

	t.Helper()

	virtualTxCopy := asset.VirtualTxWithInput(
		virtualTx, newAsset.LockTime, newAsset.RelativeLockTime, idx,
		nil,
	)
	sigHash, err := tapscript.InputKeySpendSigHash(
		virtualTxCopy, input, newAsset, idx, txscript.SigHashDefault,
	)
	require.NoError(t, err)

	taprootPrivKey := txscript.TweakTaprootPrivKey(*privKey, nil)
	sig, err := schnorr.Sign(taprootPrivKey, sigHash)
	require.NoError(t, err)

	return wire.TxWitness{sig.Serialize()}
}

// signOwnershipWitness creates the challenge witness of an input ownership
// proof, mirroring what the initiator's wallet produces during funding.
func signOwnershipWitness(t *testing.T, ownedAsset *asset.Asset,
	key *btcec.PrivateKey) wire.TxWitness {

	t.Helper()

	owned := ownedAsset.Copy()
	prevID, proofAsset := proof.CreateOwnershipProofAsset(
		owned, fn.None[[32]byte](),
	)
	inputs := commitment.InputSet{prevID: owned}
	virtualTx, _, err := tapscript.VirtualTx(proofAsset, inputs)
	require.NoError(t, err)

	return keySpendWitness(t, key, virtualTx, owned, proofAsset, 0)
}

// harnessInput describes one funding input of the harness.
type harnessInput struct {
	prevID     asset.PrevID
	inputFile  *proof.File
	provenance *proof.File
	ownership  *proof.Proof
}

// fundingHarness is a fully valid, cryptographically verifiable funding flow
// fixture: for every asset, an ownership proof of a verifiable genesis leaf
// carries a production shaped challenge witness and doubles as the
// single-proof input file, and a funding proof suffix spends the input into
// the shared funding commitment at the funding output index.
type fundingHarness struct {
	fundingState  *pendingAssetFunding
	outputs       []*cmsg.AssetOutput
	inputs        []harnessInput
	fundingTx     *wire.MsgTx
	fundingParams proof.BaseProofParams
	channel       lnwallet.AuxChanState
}

// newFundingHarness builds the fixture for the given number of assets. The
// lock time is applied to the first funding output asset. If
// omitLastAnchorInput is set, the funding transaction does not spend the
// last asset's input outpoint.
func newFundingHarness(t *testing.T, numAssets int, lockTime uint64,
	omitLastAnchorInput bool) *fundingHarness {

	t.Helper()

	return newFundingHarnessWithFeatures(
		t, numAssets, lockTime, omitLastAnchorInput, STXOFeatures{},
	)
}

// newFundingHarnessWithFeatures builds the fixture as newFundingHarness does,
// with the funding commitment carrying the alt leaves of the given STXO
// features, and the funding proofs carrying the proofs for them.
func newFundingHarnessWithFeatures(t *testing.T, numAssets int,
	lockTime uint64, omitLastAnchorInput bool,
	stxoFeatures STXOFeatures) *fundingHarness {

	t.Helper()

	const amt = uint64(100)

	fundingState := &pendingAssetFunding{
		inputProofFiles: make(map[asset.PrevID]*proof.File),
	}

	type stagedAsset struct {
		genesisProof proof.Proof
		fundingAsset *asset.Asset
		prevID       asset.PrevID
	}

	inputs := make([]harnessInput, numAssets)
	staged := make([]*stagedAsset, numAssets)
	for i := range staged {
		amtCopy := amt
		genesisProof, senderKey := proof.RandGenesisProofWithKey(
			t, asset.Normal, &amtCopy, nil, true, nil, nil, nil,
			nil, asset.V0,
		)

		prevID := asset.PrevID{
			OutPoint: genesisProof.OutPoint(),
			ID:       genesisProof.Asset.ID(),
			ScriptKey: asset.ToSerialized(
				genesisProof.Asset.ScriptKey.PubKey,
			),
		}

		provenance, err := proof.NewFile(proof.V0, genesisProof)
		require.NoError(t, err)

		// The ownership proof is the leaf's proof plus a challenge
		// witness, exactly like the initiator sends it. Stored as a
		// single-proof file, it becomes the input proof file the
		// funding suffix is verified against.
		ownership := genesisProof
		ownership.ChallengeWitness = signOwnershipWitness(
			t, &genesisProof.Asset, senderKey,
		)
		inputFile, err := proof.NewFile(proof.V0, ownership)
		require.NoError(t, err)

		// The funding output asset spends the full input into a
		// fresh funding script key.
		fundingKey := test.RandPrivKey()
		fundingAsset := genesisProof.Asset.Copy()
		fundingAsset.ScriptKey = asset.NewScriptKeyBip86(
			test.PubToKeyDesc(fundingKey.PubKey()),
		)
		if i == 0 {
			fundingAsset.LockTime = lockTime
		}
		fundingAsset.PrevWitnesses = []asset.Witness{{
			PrevID: &prevID,
		}}

		vTxInputs := commitment.InputSet{
			prevID: &genesisProof.Asset,
		}
		virtualTx, _, err := tapscript.VirtualTx(
			fundingAsset, vTxInputs,
		)
		require.NoError(t, err)
		fundingAsset.PrevWitnesses[0].TxWitness = keySpendWitness(
			t, senderKey, virtualTx, &genesisProof.Asset,
			fundingAsset, 0,
		)

		err = fundingState.addToFundingCommitment(
			fundingAsset.Copy(), stxoFeatures,
		)
		require.NoError(t, err)

		staged[i] = &stagedAsset{
			genesisProof: genesisProof,
			fundingAsset: fundingAsset,
			prevID:       prevID,
		}
		inputs[i] = harnessInput{
			prevID:     prevID,
			inputFile:  inputFile,
			provenance: provenance,
			ownership:  &ownership,
		}
		fundingState.inputProofFiles[prevID] = inputFile
	}

	// Build the funding transaction spending every input into the single
	// funding output that commits to all funding assets.
	fundingCommitment := fundingState.fundingAssetCommitment
	internalKey := test.RandPubKey(t)
	tapscriptRoot := fundingCommitment.TapscriptRoot(nil)
	taprootKey := txscript.ComputeTaprootOutputKey(
		internalKey, tapscriptRoot[:],
	)

	fundingTx := &wire.MsgTx{
		Version: 2,
		TxOut: []*wire.TxOut{{
			PkScript: test.ComputeTaprootScript(t, taprootKey),
			Value:    100_000,
		}},
	}
	for i, sa := range staged {
		if omitLastAnchorInput && i == len(staged)-1 {
			continue
		}

		fundingTx.TxIn = append(fundingTx.TxIn, &wire.TxIn{
			PreviousOutPoint: sa.prevID.OutPoint,
		})
	}

	merkleTree := blockchain.BuildMerkleTreeStore(
		[]*btcutil.Tx{btcutil.NewTx(fundingTx)}, false,
	)
	merkleRoot := merkleTree[len(merkleTree)-1]
	genesisHash := staged[0].genesisProof.BlockHeader.BlockHash()
	blockHeader := wire.NewBlockHeader(0, &genesisHash, merkleRoot, 0, 0)
	fundingBlock := &wire.MsgBlock{
		Header:       *blockHeader,
		Transactions: []*wire.MsgTx{fundingTx},
	}
	fundingParams := proof.BaseProofParams{
		Block:       fundingBlock,
		BlockHeight: 2,
		Tx:          fundingTx,
		TxIndex:     0,
	}

	// Create the funding proof suffixes for every asset. Without STXO
	// proofs, the proofs are of version 0.
	proofOpts := stxoFeatures.ProofOpts()
	if stxoFeatures.STXO {
		proofOpts = append(
			proofOpts, proof.WithVersion(proof.TransitionV1),
		)
	}

	outputs := make([]*cmsg.AssetOutput, numAssets)
	for i, sa := range staged {
		baseParams := proof.BaseProofParams{
			Block:            fundingBlock,
			BlockHeight:      2,
			Tx:               fundingTx,
			TxIndex:          0,
			OutputIndex:      int(FundingOutputIndex),
			InternalKey:      internalKey,
			TaprootAssetRoot: fundingCommitment,
		}
		suffix, err := proof.CreateTransitionProof(
			sa.prevID.OutPoint, &proof.TransitionParams{
				BaseProofParams: baseParams,
				NewAsset:        sa.fundingAsset,
			}, proofOpts...,
		)
		require.NoError(t, err)

		outputs[i] = cmsg.NewAssetOutput(
			sa.fundingAsset.ID(), sa.fundingAsset.Amount, *suffix,
		)
	}

	channel := lnwallet.AuxChanState{
		FundingOutpoint: wire.OutPoint{
			Hash:  fundingTx.TxHash(),
			Index: FundingOutputIndex,
		},
		ShortChannelID: lnwire.ShortChannelID{BlockHeight: 2},
		TapscriptRoot:  lfn.Some(tapscriptRoot),
	}

	return &fundingHarness{
		fundingState:  fundingState,
		outputs:       outputs,
		inputs:        inputs,
		fundingTx:     fundingTx,
		fundingParams: fundingParams,
		channel:       channel,
	}
}

// deliverInputProofFile stores a proof file in the mock courier under the
// funding input's exact locator.
func deliverInputProofFile(t *testing.T, courier *proof.MockProofCourier,
	input harnessInput, proofFile *proof.File) {

	t.Helper()

	var proofBytes bytes.Buffer
	require.NoError(t, proofFile.Encode(&proofBytes))

	scriptKey, err := input.prevID.ScriptKey.ToPubKey()
	require.NoError(t, err)

	err = courier.DeliverProof(
		context.Background(), proof.Recipient{}, &proof.AnnotatedProof{
			Locator: proof.Locator{
				AssetID:   &input.prevID.ID,
				ScriptKey: *scriptKey,
				OutPoint:  &input.prevID.OutPoint,
			},
			Blob:          proof.Blob(proofBytes.Bytes()),
			AssetSnapshot: &proof.AssetSnapshot{},
		}, nil,
	)
	require.NoError(t, err)
}

// TestVerifyFundingInputProvenance verifies that channel activation requires
// a complete and valid history for each funding input. The ownership proof
// accepted during negotiation is deliberately insufficient at this boundary.
func TestVerifyFundingInputProvenance(t *testing.T) {
	t.Parallel()

	newDependencies := func() (*proof.MockProofCourier,
		*proof.MockProofCourierDispatcher, *url.URL) {

		courier := proof.NewMockProofCourier()
		dispatcher := &proof.MockProofCourierDispatcher{
			Courier: courier,
		}
		courierAddr := &url.URL{Scheme: string(proof.MockCourierType)}

		return courier, dispatcher, courierAddr
	}

	t.Run("complete provenance", func(t *testing.T) {
		h := newFundingHarness(t, 2, 0, false)
		courier, dispatcher, courierAddr := newDependencies()
		for _, input := range h.inputs {
			deliverInputProofFile(
				t, courier, input, input.provenance,
			)
		}

		_, err := verifyFundingInputProvenance(
			context.Background(), h.outputs, courierAddr,
			dispatcher, proof.MockVerifierCtx,
		)
		require.NoError(t, err)
	})

	t.Run("unavailable provenance", func(t *testing.T) {
		h := newFundingHarness(t, 1, 0, false)
		_, dispatcher, courierAddr := newDependencies()

		_, err := verifyFundingInputProvenance(
			context.Background(), h.outputs, courierAddr,
			dispatcher, proof.MockVerifierCtx,
		)
		require.ErrorIs(t, err, proof.ErrProofNotFound)
	})

	t.Run("ownership proof is not provenance", func(t *testing.T) {
		h := newFundingHarness(t, 1, 0, false)
		courier, dispatcher, courierAddr := newDependencies()
		deliverInputProofFile(
			t, courier, h.inputs[0], h.inputs[0].inputFile,
		)

		_, err := verifyFundingInputProvenance(
			context.Background(), h.outputs, courierAddr,
			dispatcher, proof.MockVerifierCtx,
		)
		require.ErrorContains(t, err, "ownership challenge")
	})

	t.Run("history does not start at genesis", func(t *testing.T) {
		h := newFundingHarness(t, 1, 0, false)
		courier, dispatcher, courierAddr := newDependencies()

		firstProof, err := h.inputs[0].provenance.ProofAt(0)
		require.NoError(t, err)
		firstProof.Asset.PrevWitnesses = []asset.Witness{{
			PrevID: &asset.PrevID{
				OutPoint: test.RandOp(t),
				ID:       firstProof.Asset.ID(),
				ScriptKey: asset.ToSerialized(
					firstProof.Asset.ScriptKey.PubKey,
				),
			},
		}}
		truncatedFile, err := proof.NewFile(proof.V0, *firstProof)
		require.NoError(t, err)
		deliverInputProofFile(t, courier, h.inputs[0], truncatedFile)

		_, err = verifyFundingInputProvenance(
			context.Background(), h.outputs, courierAddr,
			dispatcher, proof.MockVerifierCtx,
		)
		require.ErrorContains(t, err, "does not start at genesis")
	})

	t.Run("invalid cryptographic history", func(t *testing.T) {
		h := newFundingHarness(t, 1, 0, false)
		courier, dispatcher, courierAddr := newDependencies()

		firstProof, err := h.inputs[0].provenance.ProofAt(0)
		require.NoError(t, err)
		firstProof.Asset.Amount++
		invalidFile, err := proof.NewFile(proof.V0, *firstProof)
		require.NoError(t, err)
		deliverInputProofFile(t, courier, h.inputs[0], invalidFile)

		_, err = verifyFundingInputProvenance(
			context.Background(), h.outputs, courierAddr,
			dispatcher, proof.MockVerifierCtx,
		)
		require.ErrorContains(t, err, "is invalid")
	})
}

// TestValidateProvenanceFileRejectsNestedTruncation verifies that additional
// input histories cannot introduce a non-genesis trust root.
func TestValidateProvenanceFileRejectsNestedTruncation(t *testing.T) {
	t.Parallel()

	h := newFundingHarness(t, 1, 0, false)
	genesisProof, err := h.inputs[0].provenance.ProofAt(0)
	require.NoError(t, err)

	truncatedProof := *genesisProof
	truncatedProof.Asset.PrevWitnesses = []asset.Witness{{
		PrevID: &asset.PrevID{
			OutPoint: test.RandOp(t),
			ID:       truncatedProof.Asset.ID(),
			ScriptKey: asset.ToSerialized(
				truncatedProof.Asset.ScriptKey.PubKey,
			),
		},
	}}
	truncatedFile, err := proof.NewFile(proof.V0, truncatedProof)
	require.NoError(t, err)

	genesisProof.AdditionalInputs = []proof.File{*truncatedFile}
	proofFile, err := proof.NewFile(proof.V0, *genesisProof)
	require.NoError(t, err)

	err = validateProvenanceFile(context.Background(), proofFile)
	require.ErrorContains(t, err, "additional input 0")
	require.ErrorContains(t, err, "does not start at genesis")
}

// TestValidateProvenanceFileCancellation verifies that provenance preflight
// stops once its operation context is canceled.
func TestValidateProvenanceFileCancellation(t *testing.T) {
	t.Parallel()

	h := newFundingHarness(t, 1, 0, false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := validateProvenanceFile(ctx, h.inputs[0].provenance)
	require.ErrorIs(t, err, context.Canceled)
}

// TestContextWithProgressDeadline verifies that proof progress renews the idle
// deadline without extending the operation's hard upper bound.
func TestContextWithProgressDeadline(t *testing.T) {
	t.Parallel()

	t.Run("idle deadline", func(t *testing.T) {
		ctx, _, cancel := contextWithProgressDeadline(
			context.Background(), 50*time.Millisecond, time.Second,
		)
		defer cancel()

		select {
		case <-ctx.Done():
			require.ErrorIs(
				t, context.Cause(ctx), errFundingProvenanceIdle,
			)
		case <-time.After(time.Second):
			t.Fatal("idle deadline did not cancel the context")
		}
	})

	t.Run("progress renews idle deadline", func(t *testing.T) {
		ctx, progress, cancel := contextWithProgressDeadline(
			context.Background(), 500*time.Millisecond,
			5*time.Second,
		)
		defer cancel()

		// Together the steps outlast one idle interval, while each
		// stays well within it.
		for range 6 {
			time.Sleep(100 * time.Millisecond)
			progress()
			require.NoError(t, ctx.Err())
		}
	})

	t.Run("hard deadline", func(t *testing.T) {
		ctx, progress, cancel := contextWithProgressDeadline(
			context.Background(), time.Second, 100*time.Millisecond,
		)
		defer cancel()

		progressTicker := time.NewTicker(20 * time.Millisecond)
		defer progressTicker.Stop()
		for {
			select {
			case <-progressTicker.C:
				progress()

			case <-ctx.Done():
				require.ErrorIs(
					t, context.Cause(ctx),
					context.DeadlineExceeded,
				)

				return
			}
		}
	})
}

// TestFundingInputOwnershipProof drives the receive-time input check
// through its full cryptographic path: the ownership proof's challenge
// witness must prove control of the claimed leaf.
func TestFundingInputOwnershipProof(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	t.Run("valid ownership proof", func(t *testing.T) {
		h := newFundingHarness(t, 1, 0, false)
		input := h.inputs[0]

		// The ownership proof must verify through the challenge
		// witness path, like in processFundingMsg.
		_, err := input.ownership.Verify(
			ctx, nil, proof.MockChainLookup, proof.MockVerifierCtx,
		)
		require.NoError(t, err)
	})

	t.Run("wrong challenge witness", func(t *testing.T) {
		h := newFundingHarness(t, 2, 0, false)

		// The witness of one input proves nothing about the leaf of
		// the other.
		tampered := *h.inputs[0].ownership
		tampered.ChallengeWitness =
			h.inputs[1].ownership.ChallengeWitness

		_, err := tampered.Verify(
			ctx, nil, proof.MockChainLookup, proof.MockVerifierCtx,
		)
		require.Error(t, err)
	})
}

// TestValidateFundingProofsSuccess drives validateFundingProofs through the
// complete successful path (suffix verification, root comparison, membership
// and exact coverage), then mutates one property per subtest.
func TestValidateFundingProofsSuccess(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	t.Run("valid single asset funding", func(t *testing.T) {
		h := newFundingHarness(t, 1, 0, false)

		err := validateFundingProofs(
			ctx, proof.MockVerifierCtx, h.fundingState, h.outputs,
		)
		require.NoError(t, err)
	})

	t.Run("valid multi asset funding", func(t *testing.T) {
		h := newFundingHarness(t, 2, 0, false)

		err := validateFundingProofs(
			ctx, proof.MockVerifierCtx, h.fundingState, h.outputs,
		)
		require.NoError(t, err)
	})

	t.Run("commitment root mismatch", func(t *testing.T) {
		h := newFundingHarness(t, 1, 0, false)

		// The responder expects a funding commitment that contains an
		// additional asset, so the suffix commits to the wrong root.
		err := h.fundingState.addToFundingCommitment(
			asset.RandAsset(t, asset.Normal), STXOFeatures{},
		)
		require.NoError(t, err)

		err = validateFundingProofs(
			ctx, proof.MockVerifierCtx, h.fundingState, h.outputs,
		)
		require.ErrorContains(t, err, "unexpected asset root")
	})

	t.Run("missing asset coverage", func(t *testing.T) {
		h := newFundingHarness(t, 2, 0, false)

		// Only one of the two committed assets has a funding proof.
		err := validateFundingProofs(
			ctx, proof.MockVerifierCtx, h.fundingState,
			h.outputs[:1],
		)
		require.ErrorContains(t, err, "expected 2")
	})

	t.Run("different anchor transactions", func(t *testing.T) {
		h := newFundingHarness(t, 2, 0, false)

		h.outputs[1].Proof.Val.AnchorTx.LockTime = 1

		err := validateFundingProofs(
			ctx, proof.MockVerifierCtx, h.fundingState, h.outputs,
		)
		require.ErrorContains(t, err, "has anchor transaction")
	})

	t.Run("reused input across outputs", func(t *testing.T) {
		h := newFundingHarness(t, 2, 0, false)

		witnesses := h.outputs[1].Proof.Val.Asset.PrevWitnesses
		witnesses[0].PrevID = &h.inputs[0].prevID

		err := validateFundingProofs(
			ctx, proof.MockVerifierCtx, h.fundingState, h.outputs,
		)
		require.ErrorContains(t, err, "reuses input")
	})

	t.Run("missing additional anchor input", func(t *testing.T) {
		h := newFundingHarness(t, 2, 0, true)

		err := validateFundingProofs(
			ctx, proof.MockVerifierCtx, h.fundingState, h.outputs,
		)
		require.ErrorContains(t, err, "does not spend input")
	})

	t.Run("swapped input proof files", func(t *testing.T) {
		h := newFundingHarness(t, 2, 0, false)

		// Swap the two input proof files: their leaves no longer
		// match the inputs they are keyed under.
		files := h.fundingState.inputProofFiles
		files[h.inputs[0].prevID] = h.inputs[1].inputFile
		files[h.inputs[1].prevID] = h.inputs[0].inputFile

		err := validateFundingProofs(
			ctx, proof.MockVerifierCtx, h.fundingState,
			h.outputs,
		)
		require.ErrorContains(t, err, "input proof mismatch")
	})

	t.Run("time locked funding output", func(t *testing.T) {
		h := newFundingHarness(t, 1, 500, false)

		// Funding outputs never legitimately carry a time lock, and
		// no lock can be evaluated before the funding transaction
		// confirms, so the structural pass rejects them outright.
		err := validateFundingProofs(
			ctx, proof.MockVerifierCtx, h.fundingState, h.outputs,
		)
		require.ErrorContains(t, err, "carries a time lock")
	})
}

// TestValidateConfirmedFundingProofs exercises the confirmed-funding
// validation performed in ChannelReady against the real funding transaction.
func TestValidateConfirmedFundingProofs(t *testing.T) {
	t.Parallel()

	t.Run("honest funding flow", func(t *testing.T) {
		h := newFundingHarness(t, 2, 0, false)

		err := validateConfirmedFundingProofs(
			h.channel, h.outputs, h.fundingParams,
		)
		require.NoError(t, err)
	})

	t.Run("doppelganger funding transaction", func(t *testing.T) {
		h := newFundingHarness(t, 1, 0, false)

		// The confirmed transaction differs from the one the peer's
		// suffixes anchor to, even though it has the same commitment
		// output.
		doppelTx := h.fundingTx.Copy()
		doppelTx.TxIn = append(doppelTx.TxIn, &wire.TxIn{
			PreviousOutPoint: test.RandOp(t),
		})
		h.fundingParams.Tx = doppelTx
		h.channel.FundingOutpoint.Hash = doppelTx.TxHash()

		err := validateConfirmedFundingProofs(
			h.channel, h.outputs, h.fundingParams,
		)
		require.ErrorContains(t, err, "anchors to")
	})

	t.Run("funding transaction omits claimed input", func(t *testing.T) {
		h := newFundingHarness(t, 2, 0, true)

		err := validateConfirmedFundingProofs(
			h.channel, h.outputs, h.fundingParams,
		)
		require.ErrorContains(t, err, "does not spend input")
	})

	t.Run("tapscript root mismatch", func(t *testing.T) {
		h := newFundingHarness(t, 1, 0, false)

		h.channel.TapscriptRoot = lfn.Some(test.RandHash())

		err := validateConfirmedFundingProofs(
			h.channel, h.outputs, h.fundingParams,
		)
		require.ErrorContains(
			t, err, "do not reproduce the channel tapscript root",
		)
	})
}
