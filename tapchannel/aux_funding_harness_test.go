package tapchannel

import (
	"context"
	"testing"

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
	prevID    asset.PrevID
	inputFile *proof.File
	ownership *proof.Proof
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
			fundingAsset.Copy(), false,
		)
		require.NoError(t, err)

		staged[i] = &stagedAsset{
			genesisProof: genesisProof,
			fundingAsset: fundingAsset,
			prevID:       prevID,
		}
		inputs[i] = harnessInput{
			prevID:    prevID,
			inputFile: inputFile,
			ownership: &ownership,
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

	// Create the funding proof suffixes for every asset.
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
			}, proof.WithVersion(proof.TransitionV0),
			proof.WithNoSTXOProofs(),
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
			asset.RandAsset(t, asset.Normal), false,
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
