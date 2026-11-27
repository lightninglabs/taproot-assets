package tapchannel

import (
	"bytes"
	"context"
	"crypto/rand"
	"net/url"
	"sync"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	cmsg "github.com/lightninglabs/taproot-assets/tapchannelmsg"
	"github.com/lightninglabs/taproot-assets/tapfreighter"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/tapscript"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/lightninglabs/taproot-assets/vm"
	"github.com/lightningnetwork/lnd/channeldb"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/stretchr/testify/require"
)

// importProofChainBridge returns the block containing the funding transaction.
// The embedded interface supplies the methods importOutputProofs doesn't use.
type importProofChainBridge struct {
	tapgarden.ChainBridge

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

	mu       sync.Mutex
	received []proof.Locator
}

func (c *recordingProofCourier) ReceiveProof(ctx context.Context,
	recipient proof.Recipient,
	locator proof.Locator) (*proof.AnnotatedProof, error) {

	c.mu.Lock()
	c.received = append(c.received, locator)
	c.mu.Unlock()

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

// TestImportOutputProofsUsesConfirmedFundingTx ensures the fallback import
// validates funding inputs against the transaction identified by the short
// channel ID, not the peer-supplied transaction stored in the proof suffix.
func TestImportOutputProofsUsesConfirmedFundingTx(t *testing.T) {
	t.Parallel()

	outputProof, _ := fetchInputTestProof(t)
	confirmedTx := wire.NewMsgTx(2)
	confirmedTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: test.RandOp(t),
	})
	confirmedTx.AddTxOut(&wire.TxOut{Value: 1_000})
	chainBridge := &importProofChainBridge{
		block: &wire.MsgBlock{
			Transactions: []*wire.MsgTx{confirmedTx},
		},
	}
	recordingCourier := &recordingProofCourier{
		Courier: proof.NewMockProofCourier(),
	}
	dispatch := &proof.MockProofCourierDispatcher{
		Courier: recordingCourier,
	}

	err := importOutputProofs(
		context.Background(), lnwire.ShortChannelID{},
		[]*proof.Proof{&outputProof}, &url.URL{}, dispatch,
		chainBridge, proof.MockVerifierCtx, proof.NewMockProofArchive(),
	)
	require.ErrorContains(t, err, "does not spend input")
	require.Empty(t, recordingCourier.received)
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

// TestFetchInputProofFilesRejectsGroupMismatch ensures an untrusted courier
// cannot satisfy an input request with a history from another group namespace.
func TestFetchInputProofFilesRejectsGroupMismatch(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		mutate func(*proof.Proof, *proof.Proof)
	}{
		{
			name: "different group key",
			mutate: func(_ *proof.Proof, inputProof *proof.Proof) {
				otherProof := randFundingProof(t)
				inputProof.Asset.GroupKey =
					otherProof.Asset.GroupKey
			},
		},
		{
			name: "grouped request with ungrouped history",
			mutate: func(_ *proof.Proof, inputProof *proof.Proof) {
				inputProof.Asset.GroupKey = nil
			},
		},
		{
			name: "ungrouped request with grouped history",
			mutate: func(outputProof, _ *proof.Proof) {
				outputProof.Asset.GroupKey = nil
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			inputProof := randFundingProof(t)
			outputProof := randFundingProof(t)
			outputProof.Asset.GroupKey = inputProof.Asset.GroupKey

			prevID := asset.PrevID{
				OutPoint: inputProof.OutPoint(),
				ID:       inputProof.Asset.ID(),
				ScriptKey: asset.ToSerialized(
					inputProof.Asset.ScriptKey.PubKey,
				),
			}
			outputProof.Asset.PrevWitnesses = []asset.Witness{{
				PrevID: &prevID,
			}}
			outputProof.PrevOut = prevID.OutPoint
			outputProof.AdditionalInputs = nil
			outputProof.AnchorTx.TxIn = []*wire.TxIn{{
				PreviousOutPoint: prevID.OutPoint,
			}}

			testCase.mutate(&outputProof, &inputProof)

			inputFile, err := proof.NewFile(proof.V0, inputProof)
			require.NoError(t, err)
			var inputFileBuf bytes.Buffer
			require.NoError(t, inputFile.Encode(&inputFileBuf))

			inputScriptKey := inputProof.Asset.ScriptKey.PubKey
			courier := proof.NewMockProofCourier()
			err = courier.DeliverProof(
				context.Background(), proof.Recipient{},
				&proof.AnnotatedProof{
					Locator: proof.Locator{
						AssetID:   &prevID.ID,
						ScriptKey: *inputScriptKey,
						OutPoint:  &prevID.OutPoint,
					},
					Blob:          inputFileBuf.Bytes(),
					AssetSnapshot: &proof.AssetSnapshot{},
				}, nil,
			)
			require.NoError(t, err)

			dispatch := &proof.MockProofCourierDispatcher{
				Courier: courier,
			}
			_, err = fetchInputProofFiles(
				context.Background(), &outputProof, &url.URL{},
				dispatch,
			)
			require.ErrorContains(
				t, err, "input proof group mismatch",
			)
		})
	}
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

// scriptKeyStore is an address book store that accepts script key imports
// and nothing else, which is all the resolution path asks of it.
type scriptKeyStore struct {
	address.Storage
}

func (s *scriptKeyStore) InsertScriptKey(context.Context, asset.ScriptKey,
	asset.ScriptKeyType) error {

	return nil
}

// recordingPorter records shipment requests. It knows no prior parcels, so
// every commitment transaction it is asked about gets imported.
type recordingPorter struct {
	tapfreighter.Porter

	shipped []tapfreighter.Parcel
}

func (p *recordingPorter) QueryParcels(context.Context,
	fn.Option[chainhash.Hash], bool) ([]*tapfreighter.OutboundParcel,
	error) {

	return nil, nil
}

func (p *recordingPorter) RequestShipment(
	parcel tapfreighter.Parcel) (*tapfreighter.OutboundParcel, error) {

	p.shipped = append(p.shipped, parcel)
	return nil, nil
}

// oneSidedChannel is an asset channel whose whole balance sits on one side:
// a single funding asset and a single commitment output carrying all of it.
// The funding input proof is served by the mock courier, so the sweeper's
// commitment import can run against it.
type oneSidedChannel struct {
	fundingProof proof.Proof
	fundingBlock wire.MsgBlock
	assetOutput  *cmsg.AssetOutput
	courier      *proof.MockProofCourier
}

func newOneSidedChannel(t *testing.T) *oneSidedChannel {
	t.Helper()

	ctx := context.Background()
	genesis := asset.RandGenesis(t, asset.Normal)

	// The funding input is a genesis output the courier can serve.
	inputTx := wire.NewMsgTx(2)
	inputTx.AddTxIn(&wire.TxIn{})
	inputTx.AddTxOut(&wire.TxOut{Value: 1_000})
	inputBlock := wire.MsgBlock{Transactions: []*wire.MsgTx{inputTx}}
	inputProof := proof.RandProof(
		t, genesis, test.RandPubKey(t), inputBlock, 0, 0,
	)
	prevID := asset.PrevID{
		OutPoint: inputProof.OutPoint(),
		ID:       inputProof.Asset.ID(),
		ScriptKey: asset.ToSerialized(
			inputProof.Asset.ScriptKey.PubKey,
		),
	}

	// The funding output spends that input in full. Funding assets never
	// carry time locks.
	fundingTx := wire.NewMsgTx(2)
	fundingTx.AddTxIn(&wire.TxIn{PreviousOutPoint: prevID.OutPoint})
	fundingTx.AddTxOut(&wire.TxOut{Value: 1_000})
	fundingBlock := wire.MsgBlock{Transactions: []*wire.MsgTx{fundingTx}}
	fundingProof := proof.RandProof(
		t, genesis, test.RandPubKey(t), fundingBlock, 0,
		FundingOutputIndex,
	)
	fundingProof.Asset.GroupKey = inputProof.Asset.GroupKey
	fundingProof.Asset.LockTime = 0
	fundingProof.Asset.RelativeLockTime = 0
	fundingProof.Asset.PrevWitnesses = []asset.Witness{{PrevID: &prevID}}
	fundingProof.PrevOut = prevID.OutPoint
	fundingProof.AdditionalInputs = nil

	// The commitment proof must speak of the asset as it now stands.
	fundingCommitment, err := commitment.FromAssets(
		nil, &fundingProof.Asset,
	)
	require.NoError(t, err)
	_, fundingCommitmentProof, err := fundingCommitment.Proof(
		fundingProof.Asset.TapCommitmentKey(),
		fundingProof.Asset.AssetCommitmentKey(),
	)
	require.NoError(t, err)
	fundingProof.InclusionProof.CommitmentProof.Proof =
		*fundingCommitmentProof

	inputFile, err := proof.NewFile(proof.V0, inputProof)
	require.NoError(t, err)
	var inputFileBuf bytes.Buffer
	require.NoError(t, inputFile.Encode(&inputFileBuf))

	courier := proof.NewMockProofCourier()
	err = courier.DeliverProof(
		ctx, proof.Recipient{}, &proof.AnnotatedProof{
			Locator: proof.Locator{
				AssetID:   &prevID.ID,
				ScriptKey: *inputProof.Asset.ScriptKey.PubKey,
				OutPoint:  &prevID.OutPoint,
			},
			Blob:          inputFileBuf.Bytes(),
			AssetSnapshot: &proof.AssetSnapshot{},
		}, nil,
	)
	require.NoError(t, err)

	// The commitment output moves the whole funding balance to a fresh
	// script key.
	outputProof := fundingProof
	outputProof.Asset = *fundingProof.Asset.Copy()
	outputProof.Asset.ScriptKey = asset.NewScriptKey(test.RandPubKey(t))

	return &oneSidedChannel{
		fundingProof: fundingProof,
		fundingBlock: fundingBlock,
		assetOutput: cmsg.NewAssetOutput(
			outputProof.Asset.ID(), outputProof.Asset.Amount,
			outputProof,
		),
		courier: courier,
	}
}

// TestResolveContractNoAssetOutputs ensures that resolving an output that
// carries no assets yields an empty resolution rather than an error, so lnd
// sweeps the plain BTC output and the force close completes. That is a
// commitment output whose side of the channel holds no assets, or a
// sat-only HTLC, which has no entry in the commitment's HTLC asset maps.
// The commitment transaction must still be imported and handed to the
// porter, so its transfer is recorded.
func TestResolveContractNoAssetOutputs(t *testing.T) {
	t.Parallel()

	// Each case places the whole asset balance on the side opposite to
	// the output being resolved. The HTLC cases resolve an HTLC index the
	// commitment knows no assets for.
	testCases := []struct {
		name        string
		witnessType input.WitnessType
		closeType   lnwallet.CloseType
		assetsLocal bool
		htlc        bool
	}{{
		name:        "local commit spend",
		witnessType: input.TaprootLocalCommitSpend,
		closeType:   lnwallet.LocalForceClose,
	}, {
		name:        "remote commit spend",
		witnessType: input.TaprootRemoteCommitSpend,
		closeType:   lnwallet.RemoteForceClose,
		assetsLocal: true,
	}, {
		name:        "commitment revoke",
		witnessType: input.TaprootCommitmentRevoke,
		closeType:   lnwallet.Breach,
	}, {
		name:        "remote htlc timeout",
		witnessType: input.TaprootHtlcOfferedRemoteTimeout,
		closeType:   lnwallet.RemoteForceClose,
		assetsLocal: true,
		htlc:        true,
	}, {
		name:        "local htlc timeout",
		witnessType: input.TaprootHtlcLocalOfferedTimeout,
		closeType:   lnwallet.LocalForceClose,
		htlc:        true,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			channel := newOneSidedChannel(t)
			assets := []*cmsg.AssetOutput{channel.assetOutput}
			var localAssets, remoteAssets []*cmsg.AssetOutput
			if tc.assetsLocal {
				localAssets = assets
			} else {
				remoteAssets = assets
			}
			commit := cmsg.NewCommitment(
				localAssets, remoteAssets, nil, nil,
				lnwallet.CommitAuxLeaves{}, false, false,
				false,
			)
			fundingProof := channel.fundingProof
			funding := cmsg.NewOpenChannel(
				[]*cmsg.AssetOutput{cmsg.NewAssetOutput(
					fundingProof.Asset.ID(),
					fundingProof.Asset.Amount, fundingProof,
				)}, 0, nil,
			)

			// The commitment transaction carries the asset output
			// first and the BTC-only to-local output second.
			keyRing := test.RandCommitmentKeyRing(t)
			const csvDelay = 144
			toLocalTree, err := input.NewLocalCommitScriptTree(
				csvDelay, keyRing.ToLocalKey,
				keyRing.RevocationKey, input.NoneTapLeaf(),
			)
			require.NoError(t, err)
			toLocalScript, err := txscript.PayToTaprootScript(
				toLocalTree.TaprootKey,
			)
			require.NoError(t, err)

			commitTx := wire.NewMsgTx(2)
			commitTx.AddTxIn(&wire.TxIn{
				PreviousOutPoint: fundingProof.OutPoint(),
			})
			commitTx.AddTxOut(&wire.TxOut{
				Value: 1_000,
				PkScript: test.ComputeTaprootScript(
					t, test.RandPubKey(t),
				),
			})
			commitTx.AddTxOut(&wire.TxOut{
				Value:    90_000,
				PkScript: toLocalScript,
			})

			porter := &recordingPorter{}
			sweeper := NewAuxSweeper(&AuxSweeperCfg{
				AddrBook: address.NewBook(address.BookConfig{
					Store: &scriptKeyStore{},
				}),
				ChainParams:        address.RegressionNetTap,
				TxSender:           porter,
				DefaultCourierAddr: &url.URL{},
				ProofFetcher: &proof.MockProofCourierDispatcher{
					Courier: channel.courier,
				},
				ProofArchive:   proof.NewMockProofArchive(),
				HeaderVerifier: proof.MockHeaderVerifier,
				GroupVerifier:  proof.MockGroupVerifier,
				ChainBridge: &importProofChainBridge{
					block: &channel.fundingBlock,
				},
			})

			req := lnwallet.ResolutionReq{
				ChanPoint:           fundingProof.OutPoint(),
				CommitBlob:          lfn.Some(commit.Bytes()),
				FundingBlob:         lfn.Some(funding.Bytes()),
				Type:                tc.witnessType,
				CloseType:           tc.closeType,
				CommitTx:            commitTx,
				CommitTxBlockHeight: 100,
				KeyRing:             &keyRing,
				CsvDelay:            csvDelay,
			}
			if tc.htlc {
				req.HtlcID = lfn.Some(input.HtlcIndex(7))
				req.PayHash = lfn.Some([32]byte{1})
				req.CltvDelay = lfn.Some[uint32](500)
			}

			res := sweeper.resolveContract(req)
			require.NoError(t, res.Err())
			require.True(t, res.OkToSome().IsNone())

			// The commitment transaction was still handed to the
			// porter, anchored at its confirmation height.
			require.Len(t, porter.shipped, 1)
			shipped := porter.shipped[0]
			parcel, ok := shipped.(*tapfreighter.PreAnchoredParcel)
			require.True(t, ok)
			require.Equal(
				t, fn.Some[uint32](100), parcel.HeightHint(),
			)
		})
	}
}

// TestImportCommitTxBtcOnlyHtlc is a regression test for
// https://github.com/lightninglabs/taproot-assets/issues/2393. A remote
// force close with a plain BTC-only HTLC in flight could not be imported:
// the exclusion proofs generated for the commitment only covered the
// balance and anchor outputs, so the plain HTLC output failed proof
// verification and the channel stayed in waiting close. The fix stashes
// the HTLC descriptors that lnd reports when it fetches the aux leaves of
// the commitment, and derives exclusion proofs for those outputs as well.
func TestImportCommitTxBtcOnlyHtlc(t *testing.T) {
	t.Parallel()

	keyRing := test.RandCommitmentKeyRing(t)
	const csvDelay = 144

	// The anchor outputs of the commitment transaction.
	localAnchorTree, err := input.NewAnchorScriptTree(keyRing.ToLocalKey)
	require.NoError(t, err)
	localAnchorScript, err := txscript.PayToTaprootScript(
		localAnchorTree.TaprootKey,
	)
	require.NoError(t, err)

	remoteAnchorTree, err := input.NewAnchorScriptTree(
		keyRing.ToRemoteKey,
	)
	require.NoError(t, err)
	remoteAnchorScript, err := txscript.PayToTaprootScript(
		remoteAnchorTree.TaprootKey,
	)
	require.NoError(t, err)

	// The BTC-only HTLC output is a plain HTLC output that commits to no
	// assets, built exactly as it is when the commitment is created.
	var rHash [32]byte
	_, _ = rand.Read(rHash[:])
	const htlcTimeout = 800
	htlcTree, err := lnwallet.GenTaprootHtlcScript(
		false, lntypes.Remote, htlcTimeout, rHash, &keyRing,
		lfn.None[txscript.TapLeaf](),
	)
	require.NoError(t, err)
	htlcScript, err := txscript.PayToTaprootScript(htlcTree.TaprootKey)
	require.NoError(t, err)

	// The to-remote output carries the channel's assets.
	toRemoteTree, err := input.NewRemoteCommitScriptTree(
		keyRing.ToRemoteKey, input.NoneTapLeaf(),
	)
	require.NoError(t, err)

	transferAsset := asset.RandAsset(t, asset.Normal)
	transferAsset.PrevWitnesses[0].PrevID = &asset.PrevID{
		ID:        transferAsset.ID(),
		ScriptKey: asset.ToSerialized(transferAsset.ScriptKey.PubKey),
	}

	// buildCommitTx assembles the force-close commitment: the two
	// anchors, optionally the plain HTLC output at index 2, and the
	// asset carrying to-remote output last.
	buildCommitTx := func(withHtlc bool) *wire.MsgTx {
		assetCommitment, err := commitment.FromAssets(
			nil, transferAsset,
		)
		require.NoError(t, err)
		toRemoteScript, err := tapscript.PayToAddrScript(
			*toRemoteTree.InternalKey, nil, *assetCommitment,
		)
		require.NoError(t, err)

		commitTx := wire.NewMsgTx(2)
		commitTx.AddTxIn(&wire.TxIn{})
		commitTx.AddTxOut(&wire.TxOut{
			Value:    330,
			PkScript: localAnchorScript,
		})
		commitTx.AddTxOut(&wire.TxOut{
			Value:    330,
			PkScript: remoteAnchorScript,
		})
		if withHtlc {
			commitTx.AddTxOut(&wire.TxOut{
				Value:    5_000,
				PkScript: htlcScript,
			})
		}
		commitTx.AddTxOut(&wire.TxOut{
			Value:    90_000,
			PkScript: toRemoteScript,
		})

		return commitTx
	}

	// importCommitTxProof runs the exact sequence importCommitTx runs to
	// import a force-close commitment: derive the no-asset allocations,
	// then create the output commitments and the proof suffix with
	// exclusion proofs for those allocations.
	importCommitTxProof := func(commitTx *wire.MsgTx,
		stash *CommitHtlcStash) (*proof.Proof, []*tapsend.Allocation) {

		internalKey := toRemoteTree.InternalKey
		assetIdx := uint32(len(commitTx.TxOut) - 1)
		vPkt := &tappsbt.VPacket{
			Inputs: []*tappsbt.VInput{{
				PrevID: asset.PrevID{
					ID: transferAsset.ID(),
				},
			}},
			Outputs: []*tappsbt.VOutput{{
				Amount:       transferAsset.Amount,
				AssetVersion: transferAsset.Version,
				Type:         tappsbt.TypeSimple,
				Interactive:  true,
				Asset:        transferAsset,
				ScriptKey:    transferAsset.ScriptKey,

				AnchorOutputIndex:       assetIdx,
				AnchorOutputInternalKey: internalKey,
			}},
			ChainParams: &address.RegressionNetTap,
		}
		vPkt.SetInputAsset(0, transferAsset)

		req := lnwallet.ResolutionReq{
			CommitTx: commitTx,
			KeyRing:  &keyRing,
			CsvDelay: csvDelay,
		}
		vPackets := []*tappsbt.VPacket{vPkt}

		allocations, err := commitOutputAllocations(
			req, vPackets, stash,
		).Unpack()
		require.NoError(t, err)

		outCommitments, err := tapsend.CreateOutputCommitments(
			vPackets, tapsend.WithNoSTXOProofs(),
		)
		require.NoError(t, err)

		proofSuffix, err := tapsend.CreateProofSuffixCustom(
			commitTx, vPkt, outCommitments, 0, vPackets,
			tapsend.NonAssetExclusionProofs(allocations),
			proof.WithNoSTXOProofs(),
		)
		require.NoError(t, err)

		return proofSuffix, allocations
	}

	verify := func(proofSuffix *proof.Proof) error {
		_, err := proofSuffix.Verify(
			context.Background(), &proof.AssetSnapshot{
				Asset: transferAsset,
			}, proof.MockChainLookup, proof.MockVerifierCtx,
		)

		return err
	}

	commitTx := buildCommitTx(true)

	// Without the HTLC descriptors, the plain HTLC output at index 2
	// gets no exclusion proof, and the porter's pre-broadcast
	// verification rejects the commitment import exactly as reported in
	// the issue.
	t.Run("missing htlc data fails verification", func(t *testing.T) {
		proofSuffix, allocations := importCommitTxProof(
			commitTx, NewCommitHtlcStash(10),
		)

		covered := make(map[uint32]bool)
		for _, alloc := range allocations {
			covered[alloc.OutputIndex] = true
		}
		require.False(t, covered[2])

		err := verify(proofSuffix)
		require.ErrorIs(t, err, proof.ErrInvalidCommitmentProof)
		require.ErrorContains(t, err, "missing exclusion proofs")
	})

	// With the HTLC descriptors stashed, as the aux leaf store does when
	// lnd fetches the leaves of the commitment, the import produces a
	// full set of exclusion proofs and verification only fails on the
	// unsigned transfer witness, which is the last check.
	t.Run("stashed htlc data verifies", func(t *testing.T) {
		stash := NewCommitHtlcStash(10)
		StashCommitHtlcs(stash, channeldb.ChannelCommitment{
			CommitTx: commitTx,
			Htlcs: []channeldb.HTLC{{
				RHash:         rHash,
				RefundTimeout: htlcTimeout,
				Incoming:      false,
				HtlcIndex:     7,
			}},
		}, lntypes.Remote)

		proofSuffix, allocations := importCommitTxProof(
			commitTx, stash,
		)

		covered := make(map[uint32]bool)
		for _, alloc := range allocations {
			covered[alloc.OutputIndex] = true
		}
		require.True(t, covered[0])
		require.True(t, covered[1])
		require.True(t, covered[2])
		require.False(t, covered[3])

		err := verify(proofSuffix)
		require.ErrorIs(t, err, vm.Error{
			Kind: vm.ErrInvalidTransferWitness,
			Inner: txscript.Error{
				ErrorCode: txscript.ErrTaprootSigInvalid,
			},
		})
	})

	// A commitment without HTLC outputs verifies the same way, so the
	// plain HTLC exclusion proof is the only piece that was missing.
	t.Run("no htlc output verifies", func(t *testing.T) {
		proofSuffix, _ := importCommitTxProof(
			buildCommitTx(false), NewCommitHtlcStash(10),
		)

		err := verify(proofSuffix)
		require.ErrorIs(t, err, vm.Error{
			Kind: vm.ErrInvalidTransferWitness,
			Inner: txscript.Error{
				ErrorCode: txscript.ErrTaprootSigInvalid,
			},
		})
	})
}

// TestCommitHtlcStash tests the basic store, fetch, and eviction behavior
// of the commitment HTLC stash.
func TestCommitHtlcStash(t *testing.T) {
	t.Parallel()

	stash := NewCommitHtlcStash(2)

	tx1 := wire.NewMsgTx(2)
	tx1.AddTxIn(&wire.TxIn{})
	tx2 := wire.NewMsgTx(2)
	tx2.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Index: 1}})
	tx3 := wire.NewMsgTx(2)
	tx3.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Index: 2}})

	htlcs := []channeldb.HTLC{{
		RHash:         [32]byte{1},
		RefundTimeout: 500,
		Incoming:      true,
		HtlcIndex:     3,
	}}

	// A nil stash is a no-op and safe to use.
	StashCommitHtlcs(nil, channeldb.ChannelCommitment{
		CommitTx: tx1, Htlcs: htlcs,
	}, lntypes.Remote)

	StashCommitHtlcs(stash, channeldb.ChannelCommitment{
		CommitTx: tx1, Htlcs: htlcs,
	}, lntypes.Remote)

	whoseCommit, fetched, ok := stash.Fetch(tx1.TxHash())
	require.True(t, ok)
	require.Equal(t, lntypes.Remote, whoseCommit)
	require.Len(t, fetched, 1)
	require.Equal(t, [32]byte{1}, fetched[0].RHash)
	require.EqualValues(t, 500, fetched[0].Timeout)
	require.True(t, fetched[0].Incoming)
	require.EqualValues(t, 3, fetched[0].Index)

	// Fetching an unknown commitment reports no entry.
	_, _, ok = stash.Fetch(tx2.TxHash())
	require.False(t, ok)

	// The oldest entry is evicted once the stash exceeds its capacity.
	StashCommitHtlcs(stash, channeldb.ChannelCommitment{
		CommitTx: tx2,
	}, lntypes.Local)
	StashCommitHtlcs(stash, channeldb.ChannelCommitment{
		CommitTx: tx3,
	}, lntypes.Local)

	_, _, ok = stash.Fetch(tx1.TxHash())
	require.False(t, ok)
	_, _, ok = stash.Fetch(tx2.TxHash())
	require.True(t, ok)
	_, _, ok = stash.Fetch(tx3.TxHash())
	require.True(t, ok)

	// A commitment without a transaction is not recorded.
	StashCommitHtlcs(stash, channeldb.ChannelCommitment{}, lntypes.Local)
	_, _, ok = stash.Fetch(tx2.TxHash())
	require.True(t, ok)
}

// TestImportCommitTxHtlcVariants tests that plain HTLC outputs get proper
// exclusion proofs on commitment import for all HTLC directions and
// commitment owners, and for commitments with multiple plain HTLCs.
func TestImportCommitTxHtlcVariants(t *testing.T) {
	t.Parallel()

	keyRing := test.RandCommitmentKeyRing(t)
	const csvDelay = 144

	localAnchorTree, err := input.NewAnchorScriptTree(keyRing.ToLocalKey)
	require.NoError(t, err)
	localAnchorScript, err := txscript.PayToTaprootScript(
		localAnchorTree.TaprootKey,
	)
	require.NoError(t, err)

	remoteAnchorTree, err := input.NewAnchorScriptTree(
		keyRing.ToRemoteKey,
	)
	require.NoError(t, err)
	remoteAnchorScript, err := txscript.PayToTaprootScript(
		remoteAnchorTree.TaprootKey,
	)
	require.NoError(t, err)

	toRemoteTree, err := input.NewRemoteCommitScriptTree(
		keyRing.ToRemoteKey, input.NoneTapLeaf(),
	)
	require.NoError(t, err)

	transferAsset := asset.RandAsset(t, asset.Normal)
	transferAsset.PrevWitnesses[0].PrevID = &asset.PrevID{
		ID:        transferAsset.ID(),
		ScriptKey: asset.ToSerialized(transferAsset.ScriptKey.PubKey),
	}

	// buildAndVerify builds a commitment with the two anchors first, one
	// output per given HTLC descriptor, and the asset output last. It
	// then runs the importCommitTx proof creation with the stashed HTLC
	// descriptors and verifies the resulting proof. Verification must
	// pass all proof checks and only fail on the unsigned transfer
	// witness, which is the last check.
	buildAndVerify := func(t *testing.T, whoseCommit lntypes.ChannelParty,
		htlcs []HtlcDescriptor) {

		assetCommitment, err := commitment.FromAssets(
			nil, transferAsset,
		)
		require.NoError(t, err)
		toRemoteScript, err := tapscript.PayToAddrScript(
			*toRemoteTree.InternalKey, nil, *assetCommitment,
		)
		require.NoError(t, err)

		commitTx := wire.NewMsgTx(2)
		commitTx.AddTxIn(&wire.TxIn{})
		commitTx.AddTxOut(&wire.TxOut{
			Value:    330,
			PkScript: localAnchorScript,
		})
		commitTx.AddTxOut(&wire.TxOut{
			Value:    330,
			PkScript: remoteAnchorScript,
		})

		dbHtlcs := make([]channeldb.HTLC, 0, len(htlcs))
		for idx, htlc := range htlcs {
			htlcTree, err := lnwallet.GenTaprootHtlcScript(
				htlc.Incoming, whoseCommit, htlc.Timeout,
				htlc.RHash, &keyRing,
				lfn.None[txscript.TapLeaf](),
			)
			require.NoError(t, err)
			htlcScript, err := txscript.PayToTaprootScript(
				htlcTree.TaprootKey,
			)
			require.NoError(t, err)

			commitTx.AddTxOut(&wire.TxOut{
				Value:    5_000,
				PkScript: htlcScript,
			})
			dbHtlcs = append(dbHtlcs, channeldb.HTLC{
				RHash:         htlc.RHash,
				RefundTimeout: htlc.Timeout,
				Incoming:      htlc.Incoming,
				HtlcIndex:     uint64(idx),
			})
		}
		commitTx.AddTxOut(&wire.TxOut{
			Value:    90_000,
			PkScript: toRemoteScript,
		})

		internalKey := toRemoteTree.InternalKey
		assetIdx := uint32(len(commitTx.TxOut) - 1)
		vPkt := &tappsbt.VPacket{
			Inputs: []*tappsbt.VInput{{
				PrevID: asset.PrevID{
					ID: transferAsset.ID(),
				},
			}},
			Outputs: []*tappsbt.VOutput{{
				Amount:       transferAsset.Amount,
				AssetVersion: transferAsset.Version,
				Type:         tappsbt.TypeSimple,
				Interactive:  true,
				Asset:        transferAsset,
				ScriptKey:    transferAsset.ScriptKey,

				AnchorOutputIndex:       assetIdx,
				AnchorOutputInternalKey: internalKey,
			}},
			ChainParams: &address.RegressionNetTap,
		}
		vPkt.SetInputAsset(0, transferAsset)

		stash := NewCommitHtlcStash(10)
		StashCommitHtlcs(stash, channeldb.ChannelCommitment{
			CommitTx: commitTx,
			Htlcs:    dbHtlcs,
		}, whoseCommit)

		req := lnwallet.ResolutionReq{
			CommitTx: commitTx,
			KeyRing:  &keyRing,
			CsvDelay: csvDelay,
		}
		vPackets := []*tappsbt.VPacket{vPkt}

		allocations, err := commitOutputAllocations(
			req, vPackets, stash,
		).Unpack()
		require.NoError(t, err)

		outCommitments, err := tapsend.CreateOutputCommitments(
			vPackets, tapsend.WithNoSTXOProofs(),
		)
		require.NoError(t, err)

		proofSuffix, err := tapsend.CreateProofSuffixCustom(
			commitTx, vPkt, outCommitments, 0, vPackets,
			tapsend.NonAssetExclusionProofs(allocations),
			proof.WithNoSTXOProofs(),
		)
		require.NoError(t, err)

		_, err = proofSuffix.Verify(
			context.Background(), &proof.AssetSnapshot{
				Asset: transferAsset,
			}, proof.MockChainLookup, proof.MockVerifierCtx,
		)
		require.ErrorIs(t, err, vm.Error{
			Kind: vm.ErrInvalidTransferWitness,
			Inner: txscript.Error{
				ErrorCode: txscript.ErrTaprootSigInvalid,
			},
		})
	}

	randHash := func() (h [32]byte) {
		_, _ = rand.Read(h[:])

		return h
	}
	dupHash := randHash()

	testCases := []struct {
		name        string
		whoseCommit lntypes.ChannelParty
		htlcs       []HtlcDescriptor
	}{{
		name:        "outgoing htlc on remote commitment",
		whoseCommit: lntypes.Remote,
		htlcs: []HtlcDescriptor{{
			RHash: randHash(), Timeout: 800,
		}},
	}, {
		name:        "incoming htlc on remote commitment",
		whoseCommit: lntypes.Remote,
		htlcs: []HtlcDescriptor{{
			RHash: randHash(), Timeout: 800, Incoming: true,
		}},
	}, {
		name:        "outgoing htlc on local commitment",
		whoseCommit: lntypes.Local,
		htlcs: []HtlcDescriptor{{
			RHash: randHash(), Timeout: 800,
		}},
	}, {
		name:        "incoming htlc on local commitment",
		whoseCommit: lntypes.Local,
		htlcs: []HtlcDescriptor{{
			RHash: randHash(), Timeout: 800, Incoming: true,
		}},
	}, {
		name:        "two htlcs in both directions",
		whoseCommit: lntypes.Remote,
		htlcs: []HtlcDescriptor{
			{RHash: randHash(), Timeout: 800},
			{RHash: randHash(), Timeout: 900, Incoming: true},
		},
	}, {
		// Two plain HTLCs with the same payment hash and timeout in
		// the same direction (e.g. MPP shards) produce identical
		// outputs on the commitment. Each must still get its own
		// exclusion proof.
		name:        "duplicate htlcs same payment hash",
		whoseCommit: lntypes.Remote,
		htlcs: []HtlcDescriptor{
			{RHash: dupHash, Timeout: 800},
			{RHash: dupHash, Timeout: 800},
		},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			buildAndVerify(t, tc.whoseCommit, tc.htlcs)
		})
	}
}
