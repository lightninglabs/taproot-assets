package tapchannel

import (
	"bytes"
	"context"
	"net/url"
	"testing"

	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapnode"
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
