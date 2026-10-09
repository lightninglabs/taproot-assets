package tapchannel

import (
	"bytes"
	"context"
	"net/url"
	"sync"
	"testing"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	cmsg "github.com/lightninglabs/taproot-assets/tapchannelmsg"
	"github.com/lightninglabs/taproot-assets/tapfreighter"
	"github.com/lightninglabs/taproot-assets/tapnode"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/tapsend"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/sweep"
	"github.com/stretchr/testify/require"
)

// importProofChainBridge returns the block containing the funding transaction.
// The embedded interface supplies the methods importOutputProofs doesn't use.
type importProofChainBridge struct {
	tapnode.ChainBridge

	block *wire.MsgBlock
}

type archiveReceiveStaker struct {
	archive proof.Archiver
}

func (s *archiveReceiveStaker) StakeReceive(ctx context.Context,
	p *proof.AnnotatedProof) error {

	return s.archive.ImportProofs(ctx, proof.MockVerifierCtx, false, p)
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
		&url.URL{}, dispatch, chainBridge, archive,
		&archiveReceiveStaker{archive: archive},
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
		chainBridge, proof.NewMockProofArchive(),
		&archiveReceiveStaker{archive: proof.NewMockProofArchive()},
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
			proofArchive := proof.NewMockProofArchive()
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
				ProofArchive: proofArchive,
				AnchoringRegistrar: &archiveReceiveStaker{
					archive: proofArchive,
				},
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

// p2trScript returns a P2TR pkScript for a fresh random key.
func p2trScript(t *testing.T) []byte {
	t.Helper()

	pkScript, err := txscript.PayToTaprootScript(test.RandPubKey(t))
	require.NoError(t, err)

	return pkScript
}

// TestReanchorDirectSweeps asserts that direct sweep packets are pointed at
// the actual position of the asset output within the sweep transaction, which
// is located by pkScript rather than assumed to be the first output.
func TestReanchorDirectSweeps(t *testing.T) {
	t.Parallel()

	iKeyDesc, _ := test.RandKeyDesc(t)

	requiredScript := p2trScript(t)
	anchorScript := p2trScript(t)

	// The sweep transaction places a required output before the asset
	// output.
	sweepTx := wire.NewMsgTx(2)
	sweepTx.AddTxOut(&wire.TxOut{PkScript: requiredScript, Value: 1_000})
	sweepTx.AddTxOut(&wire.TxOut{PkScript: anchorScript, Value: 1_000})

	extraTxOut := sweep.SweepOutput{
		TxOut: wire.TxOut{
			PkScript: anchorScript,
			Value:    1_000,
		},
		InternalKey: lfn.Some(iKeyDesc),
	}

	directPkts := []*tappsbt.VPacket{{
		Outputs: []*tappsbt.VOutput{{}},
	}}

	err := reanchorDirectSweeps(directPkts, sweepTx, extraTxOut, 0)
	require.NoError(t, err)

	vOut := directPkts[0].Outputs[0]
	require.EqualValues(t, 1, vOut.AnchorOutputIndex)
	require.Equal(t, iKeyDesc.PubKey, vOut.AnchorOutputInternalKey)

	// An extra output whose pkScript doesn't appear in the transaction
	// must be rejected.
	missingTxOut := extraTxOut
	missingTxOut.TxOut.PkScript = p2trScript(t)
	err = reanchorDirectSweeps(directPkts, sweepTx, missingTxOut, 0)
	require.ErrorContains(t, err, "unable to find asset sweep output")

	// An extra output without an internal key must be rejected.
	noKeyTxOut := extraTxOut
	noKeyTxOut.InternalKey = lfn.None[keychain.KeyDescriptor]()
	err = reanchorDirectSweeps(directPkts, sweepTx, noKeyTxOut, 0)
	require.ErrorContains(t, err, "internal key not populated")
}

// TestSweepExclusionProofGen asserts that exclusion proofs are derived from
// the outputs of the actual sweep transaction: a BIP-86 proof for the change
// output wherever (and only if) it exists, nothing for non-P2TR outputs, and
// an error for foreign P2TR outputs that can't be proven.
func TestSweepExclusionProofGen(t *testing.T) {
	t.Parallel()

	changeKeyDesc, _ := test.RandKeyDesc(t)
	changeScript, err := txscript.PayToTaprootScript(changeKeyDesc.PubKey)
	require.NoError(t, err)

	changeAddr := lnwallet.AddrWithKey{
		DeliveryAddress: lnwire.DeliveryAddress(changeScript),
		InternalKey:     lfn.Some(changeKeyDesc),
	}
	noKeyChangeAddr := lnwallet.AddrWithKey{
		DeliveryAddress: lnwire.DeliveryAddress(changeScript),
		InternalKey:     lfn.None[keychain.KeyDescriptor](),
	}

	assetScript := p2trScript(t)
	requiredScript := p2trScript(t)
	foreignScript := p2trScript(t)
	p2wpkhScript := append(
		[]byte{0x00, 0x14}, bytes.Repeat([]byte{0x01}, 20)...,
	)

	testCases := []struct {
		name string

		outputs [][]byte

		// anchorOutputs is the set of output indexes that carry an
		// asset commitment.
		anchorOutputs map[uint32]bool

		changeAddr lnwallet.AddrWithKey

		// expectedProofs is the set of output indexes we expect a
		// BIP-86 exclusion proof for.
		expectedProofs []uint32

		expectedErr string
	}{{
		name:           "asset plus change",
		outputs:        [][]byte{assetScript, changeScript},
		anchorOutputs:  map[uint32]bool{0: true},
		changeAddr:     changeAddr,
		expectedProofs: []uint32{1},
	}, {
		name: "required outputs precede asset and change",
		outputs: [][]byte{
			requiredScript, requiredScript, assetScript,
			changeScript,
		},
		anchorOutputs:  map[uint32]bool{0: true, 1: true, 2: true},
		changeAddr:     changeAddr,
		expectedProofs: []uint32{3},
	}, {
		name:           "dust change omitted",
		outputs:        [][]byte{assetScript},
		anchorOutputs:  map[uint32]bool{0: true},
		changeAddr:     changeAddr,
		expectedProofs: nil,
	}, {
		name:           "non-P2TR output skipped",
		outputs:        [][]byte{assetScript, p2wpkhScript},
		anchorOutputs:  map[uint32]bool{0: true},
		changeAddr:     changeAddr,
		expectedProofs: nil,
	}, {
		name:          "foreign P2TR output rejected",
		outputs:       [][]byte{assetScript, foreignScript},
		anchorOutputs: map[uint32]bool{0: true},
		changeAddr:    changeAddr,
		expectedErr:   "unknown P2TR output",
	}, {
		name:          "change internal key missing",
		outputs:       [][]byte{assetScript, changeScript},
		anchorOutputs: map[uint32]bool{0: true},
		changeAddr:    noKeyChangeAddr,
		expectedErr:   "change internal key not populated",
	}}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			sweepTx := wire.NewMsgTx(2)
			for _, pkScript := range testCase.outputs {
				sweepTx.AddTxOut(&wire.TxOut{
					PkScript: pkScript,
					Value:    1_000,
				})
			}

			gen := sweepExclusionProofGen(
				sweepTx, testCase.changeAddr,
			)

			target := &proof.BaseProofParams{}
			err := gen(target, func(idx uint32) bool {
				return testCase.anchorOutputs[idx]
			})

			if testCase.expectedErr != "" {
				require.ErrorContains(
					t, err, testCase.expectedErr,
				)

				return
			}
			require.NoError(t, err)

			var proofIndexes []uint32
			for _, eProof := range target.ExclusionProofs {
				proofIndexes = append(
					proofIndexes, eProof.OutputIndex,
				)

				require.Equal(
					t, changeKeyDesc.PubKey,
					eProof.InternalKey,
				)
				require.NotNil(t, eProof.TapscriptProof)
				require.True(t, eProof.TapscriptProof.Bip86)
			}

			require.Equal(
				t, testCase.expectedProofs, proofIndexes,
			)
		})
	}
}

// heightChainBridge reports a fixed best height. The embedded interface
// supplies the methods registerAndBroadcastSweep doesn't use.
type heightChainBridge struct {
	tapnode.ChainBridge
}

func (heightChainBridge) CurrentHeight(context.Context) (uint32, error) {
	return 100, nil
}

// TestRegisterAndBroadcastSweepLayout asserts that when lnd places a required
// output ahead of the asset output, the direct sweep packet is anchored to the
// asset output's actual position, and its proof verifies against the final
// sweep transaction.
func TestRegisterAndBroadcastSweepLayout(t *testing.T) {
	t.Parallel()

	params := &address.RegressionNetTap

	// The direct sweep packet is provisionally anchored at index 0 and
	// carries no anchor internal key, as createSweepVpackets leaves it.
	sweepAsset := asset.RandAsset(t, asset.Normal)
	prevID := asset.PrevID{
		OutPoint:  test.RandOp(t),
		ID:        sweepAsset.ID(),
		ScriptKey: asset.ToSerialized(sweepAsset.ScriptKey.PubKey),
	}
	sweepAsset.PrevWitnesses = []asset.Witness{{PrevID: &prevID}}

	vPkt := &tappsbt.VPacket{
		Inputs: []*tappsbt.VInput{{
			PrevID: prevID,
			Anchor: tappsbt.Anchor{
				InternalKey: test.RandPubKey(t),
			},
		}},
		Outputs: []*tappsbt.VOutput{{
			Amount:       sweepAsset.Amount,
			AssetVersion: sweepAsset.Version,
			Type:         tappsbt.TypeSimple,
			Interactive:  true,
			Asset:        sweepAsset,
			ScriptKey:    sweepAsset.ScriptKey,
		}},
		ChainParams: params,
		Version:     tappsbt.V1,
	}
	vPkt.SetInputAsset(0, sweepAsset.Copy())

	var blob bytes.Buffer
	res := cmsg.NewContractResolution(
		[]*tappsbt.VPacket{vPkt}, nil,
		lfn.None[cmsg.TapscriptSigDesc](), true, true,
	)
	require.NoError(t, res.Encode(&blob))

	assetInput := input.MakeBaseInput(
		&prevID.OutPoint, input.TaprootLocalCommitSpend,
		&input.SignDescriptor{}, 0, nil,
		input.WithResolutionBlob(lfn.Some(blob.Bytes())),
	)

	// The asset output commits to the sweep packet, with the alt leaves of
	// an output we alone create, under a fresh internal key, as
	// DeriveSweepAddr derives it.
	iKeyDesc, _ := test.RandKeyDesc(t)
	commitSet := vPktsWithInput{
		vPkts:        []*tappsbt.VPacket{vPkt.Copy()},
		stxoFeatures: sweepOutputSTXOFeatures,
	}
	require.NoError(t, addAltLeaves([]vPktsWithInput{commitSet}))
	commitments, err := tapsend.CreateOutputCommitments(
		commitSet.vPkts, tapsend.WithNoSTXOProofs(),
	)
	require.NoError(t, err)
	assetScript, _, _, err := tapsend.AnchorOutputScript(
		iKeyDesc.PubKey, nil, commitments[0],
	)
	require.NoError(t, err)

	// A pre-signed second level HTLC input of a non-taproot channel
	// commits to a P2WSH required output.
	requiredTxOut := &wire.TxOut{
		PkScript: append([]byte{0x00, 0x20}, test.RandBytes(32)...),
		Value:    1_000,
	}
	htlcTx := wire.NewMsgTx(2)
	htlcTx.AddTxIn(&wire.TxIn{PreviousOutPoint: test.RandOp(t)})
	htlcTx.AddTxOut(requiredTxOut)
	requiredInput := input.MakeHtlcSecondLevelTimeoutAnchorInput(
		htlcTx, &input.SignDetails{}, 0,
	)

	changeKeyDesc, _ := test.RandKeyDesc(t)
	changeScript, err := txscript.PayToTaprootScript(
		txscript.ComputeTaprootKeyNoScript(changeKeyDesc.PubKey),
	)
	require.NoError(t, err)

	// lnd places the required output first, then the asset output, then
	// the change output.
	sweepTx := wire.NewMsgTx(2)
	sweepTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: requiredInput.OutPoint(),
	})
	sweepTx.AddTxIn(&wire.TxIn{PreviousOutPoint: prevID.OutPoint})
	sweepTx.AddTxOut(requiredTxOut)
	sweepTx.AddTxOut(&wire.TxOut{
		PkScript: assetScript,
		Value:    int64(tapsend.DummyAmtSats),
	})
	sweepTx.AddTxOut(&wire.TxOut{PkScript: changeScript, Value: 10_000})

	req := &sweep.BumpRequest{
		Inputs: []input.Input{&requiredInput, &assetInput},
		DeliveryAddress: lnwallet.AddrWithKey{
			DeliveryAddress: changeScript,
			InternalKey:     lfn.Some(changeKeyDesc),
		},
		ExtraTxOut: lfn.Some(sweep.SweepOutput{
			TxOut:       *sweepTx.TxOut[1],
			IsExtra:     true,
			InternalKey: lfn.Some(iKeyDesc),
		}),
	}
	outpointToTxIndex := map[wire.OutPoint]int{
		requiredInput.OutPoint(): 0,
	}

	porter := &recordingPorter{}
	sweeper := NewAuxSweeper(&AuxSweeperCfg{
		ChainParams: *params,
		TxSender:    porter,
		ChainBridge: heightChainBridge{},
	})

	err = sweeper.registerAndBroadcastSweep(
		req, sweepTx, 1_000, outpointToTxIndex,
	)
	require.NoError(t, err)

	require.Len(t, porter.shipped, 1)
	parcel, ok := porter.shipped[0].(*tapfreighter.PreAnchoredParcel)
	require.True(t, ok)

	vPkts := parcel.VirtualPackets()
	require.Len(t, vPkts, 1)
	require.Len(t, vPkts[0].Outputs, 1)
	vOut := vPkts[0].Outputs[0]

	// The packet is anchored to the asset output under its internal key.
	require.EqualValues(t, 1, vOut.AnchorOutputIndex)
	require.Equal(t, iKeyDesc.PubKey, vOut.AnchorOutputInternalKey)

	// Its proof includes the asset in the asset output and proves
	// exclusion for the change output, the only other P2TR output.
	suffix := vOut.ProofSuffix
	require.NotNil(t, suffix)
	require.EqualValues(t, 1, suffix.InclusionProof.OutputIndex)
	require.Len(t, suffix.ExclusionProofs, 1)
	require.EqualValues(t, 2, suffix.ExclusionProofs[0].OutputIndex)

	_, err = suffix.VerifyProofs()
	require.NoError(t, err)
}
