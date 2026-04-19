package tapchannel

import (
	"bytes"
	"context"
	"crypto/sha256"
	"net/url"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapnode"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/stretchr/testify/require"
)

// importProofChainBridge returns the block containing the funding transaction.
// The embedded interface supplies the methods importOutputProofs doesn't use.
type importProofChainBridge struct {
	tapnode.ChainBridge

	block *wire.MsgBlock
}

func (b *importProofChainBridge) GetBlockByHeight(context.Context,
	int64) (*wire.MsgBlock, error) {

	return b.block, nil
}

// recordingProofCourier records the locators requested from its underlying
// courier.
type recordingProofCourier struct {
	proof.Courier

	received []proof.Locator
}

func (c *recordingProofCourier) ReceiveProof(ctx context.Context,
	recipient proof.Recipient,
	locator proof.Locator) (*proof.AnnotatedProof, error) {

	c.received = append(c.received, locator)
	return c.Courier.ReceiveProof(ctx, recipient, locator)
}

// fetchInputTestProof returns an output proof with one structurally valid
// input reference. Tests can mutate it to exercise preflight validation.
func fetchInputTestProof(t *testing.T) (proof.Proof, asset.PrevID) {
	t.Helper()

	outputProof := randFundingProof(t)
	prevID := asset.PrevID{
		OutPoint: test.RandOp(t),
		ID:       outputProof.Asset.ID(),
		ScriptKey: asset.ToSerialized(
			outputProof.Asset.ScriptKey.PubKey,
		),
	}
	outputProof.Asset.PrevWitnesses = []asset.Witness{{PrevID: &prevID}}
	outputProof.PrevOut = prevID.OutPoint
	outputProof.AdditionalInputs = nil
	outputProof.AnchorTx.TxIn = []*wire.TxIn{{
		PreviousOutPoint: prevID.OutPoint,
	}}

	return outputProof, prevID
}

// TestImportOutputProofsMerge is an assembly-level test that ensures a funding
// output merging multiple inputs fetches and embeds every input proof. The
// single-asset multi-input itest covers verification and cooperative close.
func TestImportOutputProofsMerge(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	genesis := asset.RandGenesis(t, asset.Normal)

	inputTx := wire.NewMsgTx(2)
	inputTx.AddTxIn(&wire.TxIn{})
	inputTx.AddTxOut(&wire.TxOut{Value: 1_000})
	inputTx.AddTxOut(&wire.TxOut{Value: 1_000})
	inputBlock := wire.MsgBlock{
		Transactions: []*wire.MsgTx{inputTx},
	}

	inputProofs := []proof.Proof{
		proof.RandProof(
			t, genesis, test.RandPubKey(t), inputBlock, 0, 0,
		),
		proof.RandProof(
			t, genesis, test.RandPubKey(t), inputBlock, 0, 1,
		),
	}
	prevIDs := make([]asset.PrevID, len(inputProofs))
	inputProofs[1].Asset.GroupKey = inputProofs[0].Asset.GroupKey
	for idx := range inputProofs {
		prevIDs[idx] = asset.PrevID{
			OutPoint: inputProofs[idx].OutPoint(),
			ID:       inputProofs[idx].Asset.ID(),
			ScriptKey: asset.ToSerialized(
				inputProofs[idx].Asset.ScriptKey.PubKey,
			),
		}
	}

	mergedAsset := inputProofs[0].Asset.Copy()
	mergedAsset.Amount = inputProofs[0].Asset.Amount +
		inputProofs[1].Asset.Amount
	mergedAsset.ScriptKey = asset.NewScriptKey(test.RandPubKey(t))
	mergedAsset.PrevWitnesses = []asset.Witness{
		{PrevID: &prevIDs[0]},
		{PrevID: &prevIDs[1]},
	}

	outputProof := randFundingProof(t)
	outputProof.Asset = *mergedAsset
	outputProof.PrevOut = prevIDs[0].OutPoint
	outputProof.ChallengeWitness = nil
	outputProof.AnchorTx.TxIn = []*wire.TxIn{
		{PreviousOutPoint: prevIDs[0].OutPoint},
		{PreviousOutPoint: prevIDs[1].OutPoint},
	}

	fundingBlock := &wire.MsgBlock{
		Header:       outputProof.BlockHeader,
		Transactions: []*wire.MsgTx{&outputProof.AnchorTx},
	}
	chainBridge := &importProofChainBridge{block: fundingBlock}

	courier := proof.NewMockProofCourier()
	for idx := range inputProofs {
		inputFile, err := proof.NewFile(proof.V0, inputProofs[idx])
		require.NoError(t, err)

		var inputFileBuf bytes.Buffer
		require.NoError(t, inputFile.Encode(&inputFileBuf))

		scriptKey := inputProofs[idx].Asset.ScriptKey.PubKey
		err = courier.DeliverProof(
			ctx, proof.Recipient{}, &proof.AnnotatedProof{
				Locator: proof.Locator{
					AssetID:   &prevIDs[idx].ID,
					ScriptKey: *scriptKey,
					OutPoint:  &prevIDs[idx].OutPoint,
				},
				Blob:          inputFileBuf.Bytes(),
				AssetSnapshot: &proof.AssetSnapshot{},
			}, nil,
		)
		require.NoError(t, err)
	}

	archive := proof.NewMockProofArchive()
	recordingCourier := &recordingProofCourier{Courier: courier}
	dispatch := &proof.MockProofCourierDispatcher{
		Courier: recordingCourier,
	}
	err := importOutputProofs(
		ctx, lnwire.ShortChannelID{}, []*proof.Proof{&outputProof},
		&url.URL{}, dispatch, chainBridge, proof.MockVerifierCtx,
		archive,
	)
	require.NoError(t, err)
	require.Len(t, recordingCourier.received, len(inputProofs))
	for _, locator := range recordingCourier.received {
		require.NotNil(t, locator.GroupKey)
		require.True(
			t, locator.GroupKey.IsEqual(
				&mergedAsset.GroupKey.GroupPubKey,
			),
		)
	}

	outputOutPoint := outputProof.OutPoint()
	importedBlob, err := archive.FetchProof(ctx, proof.Locator{
		AssetID:   &prevIDs[0].ID,
		ScriptKey: *mergedAsset.ScriptKey.PubKey,
		OutPoint:  &outputOutPoint,
	})
	require.NoError(t, err)

	var importedFile proof.File
	require.NoError(t, importedFile.Decode(bytes.NewReader(importedBlob)))
	require.Equal(t, 2, importedFile.NumProofs())

	lineageInput, err := importedFile.ProofAt(0)
	require.NoError(t, err)
	require.Equal(t, prevIDs[0].OutPoint, lineageInput.OutPoint())
	require.Equal(
		t, prevIDs[0].ScriptKey,
		asset.ToSerialized(lineageInput.Asset.ScriptKey.PubKey),
	)

	importedOutput, err := importedFile.LastProof()
	require.NoError(t, err)
	require.Len(t, importedOutput.AdditionalInputs, 1)

	additionalInput, err := importedOutput.AdditionalInputs[0].LastProof()
	require.NoError(t, err)
	require.Equal(t, prevIDs[1].OutPoint, additionalInput.OutPoint())
	require.Equal(
		t, prevIDs[1].ScriptKey,
		asset.ToSerialized(additionalInput.Asset.ScriptKey.PubKey),
	)
}

// TestFetchInputProofFilesRejectsMalformed ensures malformed persisted funding
// proofs fail before any courier is created.
func TestFetchInputProofFilesRejectsMalformed(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		mutate    func(*proof.Proof, asset.PrevID)
		expectErr string
	}{
		{
			name: "peer supplied additional inputs",
			mutate: func(p *proof.Proof, _ asset.PrevID) {
				p.AdditionalInputs = []proof.File{{}}
			},
			expectErr: "carries additional inputs",
		},
		{
			name: "missing witnesses",
			mutate: func(p *proof.Proof, _ asset.PrevID) {
				p.Asset.PrevWitnesses = nil
			},
			expectErr: "missing previous witnesses",
		},
		{
			name: "too many witnesses",
			mutate: func(p *proof.Proof, prevID asset.PrevID) {
				numInputs := maxFundingInputProofs + 1
				p.Asset.PrevWitnesses = make(
					[]asset.Witness, numInputs,
				)
				for idx := range p.Asset.PrevWitnesses {
					witness := &p.Asset.PrevWitnesses[idx]
					witness.PrevID = &prevID
				}
			},
			expectErr: "too many funding input witnesses",
		},
		{
			name: "nil previous ID",
			mutate: func(p *proof.Proof, _ asset.PrevID) {
				p.Asset.PrevWitnesses = []asset.Witness{{}}
			},
			expectErr: "has no previous ID",
		},
		{
			name: "duplicate input",
			mutate: func(p *proof.Proof, prevID asset.PrevID) {
				p.Asset.PrevWitnesses = []asset.Witness{
					{PrevID: &prevID}, {PrevID: &prevID},
				}
			},
			expectErr: "duplicate funding input",
		},
		{
			name: "primary outpoint mismatch",
			mutate: func(p *proof.Proof, _ asset.PrevID) {
				p.PrevOut = test.RandOp(t)
			},
			expectErr: "does not match primary input",
		},
		{
			name: "unspent anchor input",
			mutate: func(p *proof.Proof, _ asset.PrevID) {
				p.AnchorTx.TxIn = nil
			},
			expectErr: "does not spend input",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			outputProof, prevID := fetchInputTestProof(t)
			testCase.mutate(&outputProof, prevID)

			_, err := fetchInputProofFiles(
				context.Background(), &outputProof,
				&url.URL{}, nil,
			)
			require.ErrorContains(t, err, testCase.expectErr)
		})
	}
}

// TestFetchInputProofFilesRejectsMismatchedProof ensures a courier cannot
// satisfy a locator with a proof file whose tip identifies another input.
func TestFetchInputProofFilesRejectsMismatchedProof(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	outputProof, prevID := fetchInputTestProof(t)

	wrongProof := randFundingProof(t)
	wrongFile, err := proof.NewFile(proof.V0, wrongProof)
	require.NoError(t, err)

	var wrongFileBuf bytes.Buffer
	require.NoError(t, wrongFile.Encode(&wrongFileBuf))

	courier := proof.NewMockProofCourier()
	err = courier.DeliverProof(
		ctx, proof.Recipient{}, &proof.AnnotatedProof{
			Locator: proof.Locator{
				AssetID:   &prevID.ID,
				ScriptKey: *outputProof.Asset.ScriptKey.PubKey,
				OutPoint:  &prevID.OutPoint,
			},
			Blob:          wrongFileBuf.Bytes(),
			AssetSnapshot: &proof.AssetSnapshot{},
		}, nil,
	)
	require.NoError(t, err)

	dispatch := &proof.MockProofCourierDispatcher{Courier: courier}
	_, err = fetchInputProofFiles(
		ctx, &outputProof, &url.URL{}, dispatch,
	)
	require.ErrorContains(t, err, "input proof mismatch")
}

// TestAuxSweeperStop ensures that stopping the sweeper closes its quit
// channel, which is what aborts any in-flight funding proof import.
func TestAuxSweeperStop(t *testing.T) {
	t.Parallel()

	sweeper := NewAuxSweeper(&AuxSweeperCfg{})
	require.NoError(t, sweeper.Start())
	require.NoError(t, sweeper.Stop())

	select {
	case <-sweeper.quit:
	default:
		t.Fatal("quit channel still open after Stop")
	}

	// A second stop must be a no-op instead of a double close.
	require.NoError(t, sweeper.Stop())
}

// TestRevocationSweepDescSignVerify tests that the revocation sweep descriptor
// functions produce taproot output keys consistent with the signing key derived
// from the same base material. For each revocation type (offered, accepted,
// second-level), it performs a full sign+verify round-trip using the same
// routines used in production to create the scripts and derive the keys.
func TestRevocationSweepDescSignVerify(t *testing.T) {
	t.Parallel()

	// Generate base key material. In production, revokeBasePriv is our
	// revocation base point secret, and commitSecret is the per-commitment
	// secret revealed when the remote party broadcasts a revoked
	// commitment.
	revokeBasePriv, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	commitSecret, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	// Generate HTLC keys and delay key for the commitment keyring.
	localHtlcPriv, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	remoteHtlcPriv, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	toLocalPriv, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	// Derive the revocation public key using the standard LND routine.
	// This key becomes the internal key of all HTLC taproot outputs.
	revocationKey := input.DeriveRevocationPubkey(
		revokeBasePriv.PubKey(), commitSecret.PubKey(),
	)

	keyRing := &lnwallet.CommitmentKeyRing{
		RevocationKey: revocationKey,
		LocalHtlcKey:  localHtlcPriv.PubKey(),
		RemoteHtlcKey: remoteHtlcPriv.PubKey(),
		ToLocalKey:    toLocalPriv.PubKey(),
	}

	payHash := sha256.Sum256([]byte("test preimage"))
	htlcIndex := input.HtlcIndex(42)
	csvDelay := uint32(144)
	htlcExpiry := uint32(800_000)

	// Derive the signing private key that the LND signer computes when
	// processing a breach sweep:
	// 1. DeriveRevocationPrivKey (DoubleTweak) — recovers the revocation
	//    private key from our base secret and the revealed commit secret.
	// 2. TweakPrivKey with HTLC index (SingleTweak) — applies the
	//    asset-level HTLC index tweak.
	revocationPriv := input.DeriveRevocationPrivKey(
		revokeBasePriv, commitSecret,
	)

	tweakScalar := ScriptKeyTweakFromHtlcIndex(htlcIndex)
	var singleTweak [32]byte
	tweakScalar.PutBytesUnchecked(singleTweak[:])
	signingPriv := input.TweakPrivKey(revocationPriv, singleTweak[:])

	// Verify that the private key tweak path is consistent with the public
	// key tweak path. This confirms that TweakPrivKey + SingleTweak on the
	// private side produces the same result as TweakPubKeyWithTweak on the
	// public side.
	derivedInternalKey := input.TweakPubKeyWithTweak(
		revocationKey, singleTweak[:],
	)
	require.Equal(
		t, derivedInternalKey.SerializeCompressed(),
		signingPriv.PubKey().SerializeCompressed(),
		"private key tweak path should match public key tweak path",
	)

	testCases := []struct {
		name          string
		getSweepDescs func() lfn.Result[tapscriptSweepDescs]
	}{
		{
			name: "offered HTLC revocation",
			getSweepDescs: func() lfn.Result[tapscriptSweepDescs] {
				return htlcOfferedRevokeSweepDesc(
					keyRing, payHash[:], htlcExpiry,
					htlcIndex,
				)
			},
		},
		{
			name: "accepted HTLC revocation",
			getSweepDescs: func() lfn.Result[tapscriptSweepDescs] {
				return htlcAcceptedRevokeSweepDesc(
					keyRing, payHash[:], htlcIndex,
				)
			},
		},
		{
			name: "second-level HTLC revocation",
			getSweepDescs: func() lfn.Result[tapscriptSweepDescs] {
				return htlcSecondLevelRevokeSweepDesc(
					keyRing, csvDelay, htlcIndex,
					lfn.None[txscript.TapLeaf](),
				)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Get the sweep descriptor.
			descs := tc.getSweepDescs().UnwrapOrFail(t)
			desc := descs.firstLevel

			// Revocation sweeps use keyspend (no control block).
			require.Empty(t, desc.ctrlBlockBytes,
				"revocation sweep should use keyspend")

			// Verify the descriptor's internal key matches what
			// we derived from applying both tweaks to the base
			// keys on the public key side.
			tree := desc.scriptTree.Tree()
			require.Equal(
				t,
				derivedInternalKey.SerializeCompressed(),
				tree.InternalKey.SerializeCompressed(),
				"descriptor internal key should match "+
					"derived key",
			)

			// Apply the taproot tweak for keyspend signing.
			// This mirrors what RawTxInTaprootSignature does
			// internally.
			tapTweak := desc.scriptTree.TapTweak()
			taprootPriv := txscript.TweakTaprootPrivKey(
				*signingPriv, tapTweak,
			)

			// Sign a test message.
			testMsg := sha256.Sum256([]byte(tc.name))
			sig, err := schnorr.Sign(taprootPriv, testMsg[:])
			require.NoError(t, err)

			// Verify the signature against the taproot output
			// key from the descriptor. This is the key that the
			// UTXO is locked to on-chain.
			require.True(
				t, sig.Verify(testMsg[:], tree.TaprootKey),
				"signature should verify against taproot "+
					"output key",
			)
		})
	}
}