package tapchannel

import (
	"context"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	cmsg "github.com/lightninglabs/taproot-assets/tapchannelmsg"
	mboxrpc "github.com/lightninglabs/taproot-assets/taprpc/authmailboxrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	"github.com/lightningnetwork/lnd/funding"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/msgmux"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// TestExpectedFundingAssetKeys ensures the set of assets that funding proofs
// must cover excludes alt leaves, which are committed alongside the funding
// assets but have no funding proof of their own.
func TestExpectedFundingAssetKeys(t *testing.T) {
	t.Parallel()

	fundingAsset := asset.RandAsset(t, asset.Normal)
	fundingCommitment, err := commitment.FromAssets(
		fn.Ptr(commitment.TapCommitmentV2), fundingAsset,
	)
	require.NoError(t, err)

	altLeaf := asset.RandAltLeaf(t)
	err = fundingCommitment.MergeAltLeaves(
		[]asset.AltLeaf[asset.Asset]{altLeaf},
	)
	require.NoError(t, err)

	assetKeys := expectedFundingAssetKeys(fundingCommitment)
	require.Len(t, assetKeys, 1)
	require.Contains(t, assetKeys, newFundingAssetKey(fundingAsset))
}

// TestExpectedFundingAssetKeysUngrouped ensures that two ungrouped assets
// with different asset IDs but the same script key map to distinct keys. The
// asset commitment key of an ungrouped asset hashes only the script key, so
// without the tap commitment key namespacing the two assets would collide.
func TestExpectedFundingAssetKeysUngrouped(t *testing.T) {
	t.Parallel()

	scriptKey := asset.RandScriptKey(t)
	asset1 := asset.NewAssetNoErr(
		t, asset.RandGenesis(t, asset.Normal), 100, 0, 0, scriptKey,
		nil,
	)
	asset2 := asset.NewAssetNoErr(
		t, asset.RandGenesis(t, asset.Normal), 100, 0, 0, scriptKey,
		nil,
	)
	require.NotEqual(t, asset1.ID(), asset2.ID())
	require.Equal(
		t, asset1.AssetCommitmentKey(), asset2.AssetCommitmentKey(),
	)

	fundingCommitment, err := commitment.FromAssets(
		fn.Ptr(commitment.TapCommitmentV2), asset1, asset2,
	)
	require.NoError(t, err)

	assetKeys := expectedFundingAssetKeys(fundingCommitment)
	require.Len(t, assetKeys, 2)
	require.Contains(t, assetKeys, newFundingAssetKey(asset1))
	require.Contains(t, assetKeys, newFundingAssetKey(asset2))
}

// randFundingProof returns a random, fully encodable proof. Like the input
// proofs exchanged during funding, it carries a challenge witness.
func randFundingProof(t *testing.T) proof.Proof {
	anchorTx := wire.NewMsgTx(2)
	anchorTx.AddTxIn(&wire.TxIn{})
	anchorTx.AddTxOut(&wire.TxOut{Value: 1_000})
	block := wire.MsgBlock{
		Header:       wire.BlockHeader{},
		Transactions: []*wire.MsgTx{anchorTx},
	}

	p := proof.RandProof(
		t, asset.RandGenesis(t, asset.Normal), test.RandPubKey(t),
		block, 0, FundingOutputIndex,
	)

	// Funding output assets never carry time locks; a randomized lock
	// would trip the structural checks before the property under test.
	p.Asset.LockTime = 0
	p.Asset.RelativeLockTime = 0

	return p
}

// TestValidateFundingProofs exercises the checks that reject malformed or
// inconsistent AssetFundingCreated payloads before any proof suffix becomes
// channel state.
func TestValidateFundingProofs(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	newState := func(t *testing.T) *pendingAssetFunding {
		fundingCommitment, err := commitment.FromAssets(
			fn.Ptr(commitment.TapCommitmentV2),
			asset.RandAsset(t, asset.Normal),
		)
		require.NoError(t, err)

		// Seed a verified input proof file under a random PrevID so
		// validation proceeds past the input completeness check.
		inputFile, err := proof.NewFile(proof.V0)
		require.NoError(t, err)

		return &pendingAssetFunding{
			fundingAssetCommitment: fundingCommitment,
			inputProofFiles: map[asset.PrevID]*proof.File{
				{OutPoint: test.RandOp(t)}: inputFile,
			},
		}
	}

	newOutput := func(p proof.Proof) *cmsg.AssetOutput {
		return cmsg.NewAssetOutput(p.Asset.ID(), p.Asset.Amount, p)
	}

	t.Run("missing funding commitment", func(t *testing.T) {
		err := validateFundingProofs(
			ctx, proof.MockVerifierCtx, &pendingAssetFunding{},
			[]*cmsg.AssetOutput{newOutput(randFundingProof(t))},
		)
		require.ErrorContains(t, err, "commitment is missing")
	})

	t.Run("replayed funding proofs", func(t *testing.T) {
		fundingState := newState(t)
		fundingState.fundingOutputProofs = []*proof.Proof{{}}

		err := validateFundingProofs(
			ctx, proof.MockVerifierCtx, fundingState,
			[]*cmsg.AssetOutput{newOutput(randFundingProof(t))},
		)
		require.ErrorContains(t, err, "already received")
	})

	t.Run("missing outputs", func(t *testing.T) {
		err := validateFundingProofs(
			ctx, proof.MockVerifierCtx, newState(t), nil,
		)
		require.ErrorContains(t, err, "proofs are missing")
	})

	t.Run("no verified input proofs", func(t *testing.T) {
		fundingState := newState(t)
		fundingState.inputProofFiles = nil

		err := validateFundingProofs(
			ctx, proof.MockVerifierCtx, fundingState,
			[]*cmsg.AssetOutput{newOutput(randFundingProof(t))},
		)
		require.ErrorContains(t, err, "no verified funding input")
	})

	t.Run("nil output", func(t *testing.T) {
		err := validateFundingProofs(
			ctx, proof.MockVerifierCtx, newState(t),
			[]*cmsg.AssetOutput{nil},
		)
		require.ErrorContains(t, err, "funding output 0 is nil")
	})

	t.Run("asset ID mismatch", func(t *testing.T) {
		suffix := randFundingProof(t)
		output := cmsg.NewAssetOutput(
			asset.RandID(t), suffix.Asset.Amount, suffix,
		)

		err := validateFundingProofs(
			ctx, proof.MockVerifierCtx, newState(t),
			[]*cmsg.AssetOutput{output},
		)
		require.ErrorContains(t, err, "asset ID does not match")
	})

	t.Run("amount mismatch", func(t *testing.T) {
		suffix := randFundingProof(t)
		output := cmsg.NewAssetOutput(
			suffix.Asset.ID(), suffix.Asset.Amount+1, suffix,
		)

		err := validateFundingProofs(
			ctx, proof.MockVerifierCtx, newState(t),
			[]*cmsg.AssetOutput{output},
		)
		require.ErrorContains(t, err, "amount does not match")
	})

	t.Run("peer-supplied additional inputs", func(t *testing.T) {
		suffix := randFundingProof(t)
		suffix.AdditionalInputs = []proof.File{{}}

		outputs := []*cmsg.AssetOutput{newOutput(suffix)}
		err := validateFundingProofs(
			ctx, proof.MockVerifierCtx, newState(t), outputs,
		)
		require.ErrorContains(t, err, "additional inputs")
	})

	t.Run("wrong anchor output index", func(t *testing.T) {
		suffix := randFundingProof(t)
		suffix.InclusionProof.OutputIndex = FundingOutputIndex + 1

		outputs := []*cmsg.AssetOutput{newOutput(suffix)}
		err := validateFundingProofs(
			ctx, proof.MockVerifierCtx, newState(t), outputs,
		)
		require.ErrorContains(t, err, "commits to anchor output")
	})

	t.Run("challenge witness suffix", func(t *testing.T) {
		suffix := randFundingProof(t)

		outputs := []*cmsg.AssetOutput{newOutput(suffix)}
		err := validateFundingProofs(
			ctx, proof.MockVerifierCtx, newState(t), outputs,
		)
		require.ErrorContains(t, err, "has a challenge witness")
	})

	t.Run("unknown input", func(t *testing.T) {
		suffix := randFundingProof(t)
		suffix.ChallengeWitness = nil
		suffix.PrevOut = wire.OutPoint{}

		outputs := []*cmsg.AssetOutput{newOutput(suffix)}
		err := validateFundingProofs(
			ctx, proof.MockVerifierCtx, newState(t), outputs,
		)
		require.ErrorContains(t, err, "no verified input proof")
	})

	t.Run("input witness without previous ID", func(t *testing.T) {
		suffix := randFundingProof(t)
		suffix.Asset.PrevWitnesses[0].PrevID = nil

		outputs := []*cmsg.AssetOutput{newOutput(suffix)}
		err := validateFundingProofs(
			ctx, proof.MockVerifierCtx, newState(t), outputs,
		)
		require.ErrorContains(t, err, "without previous ID")
	})

	t.Run("input reuse across outputs", func(t *testing.T) {
		// Two funding outputs whose witnesses consume the same input
		// must be rejected before any proof verification runs; a peer
		// could otherwise inflate the channel balance by backing
		// several outputs with one input.
		suffix1 := randFundingProof(t)
		suffix2 := randFundingProof(t)
		prevID := asset.PrevID{
			OutPoint:  test.RandOp(t),
			ID:        suffix1.Asset.ID(),
			ScriptKey: asset.RandSerializedKey(t),
		}
		suffix1.Asset.PrevWitnesses[0].PrevID = &prevID
		suffix2.Asset.PrevWitnesses[0].PrevID = &prevID

		outputs := []*cmsg.AssetOutput{
			newOutput(suffix1), newOutput(suffix2),
		}
		err := validateFundingProofs(
			ctx, proof.MockVerifierCtx, newState(t), outputs,
		)
		require.ErrorContains(t, err, "reuses input")
	})

	t.Run("distinct inputs sharing an outpoint", func(t *testing.T) {
		// Two different asset inputs may share one Bitcoin outpoint.
		// The input accounting must not confuse them, so validation
		// proceeds past the first pass (and only fails later on the
		// challenge witness carried by the random test proofs).
		suffix1 := randFundingProof(t)
		suffix2 := randFundingProof(t)
		sharedOutpoint := test.RandOp(t)
		suffix1.Asset.PrevWitnesses[0].PrevID = &asset.PrevID{
			OutPoint:  sharedOutpoint,
			ID:        suffix1.Asset.ID(),
			ScriptKey: asset.RandSerializedKey(t),
		}
		suffix2.Asset.PrevWitnesses[0].PrevID = &asset.PrevID{
			OutPoint:  sharedOutpoint,
			ID:        suffix2.Asset.ID(),
			ScriptKey: asset.RandSerializedKey(t),
		}

		outputs := []*cmsg.AssetOutput{
			newOutput(suffix1), newOutput(suffix2),
		}
		err := validateFundingProofs(
			ctx, proof.MockVerifierCtx, newState(t), outputs,
		)
		require.NotContains(t, err.Error(), "reuses input")
		require.ErrorContains(t, err, "has a challenge witness")
	})
}

// noopErrReporter ignores reported funding errors.
type noopErrReporter struct{}

// ReportError implements the ErrorReporter interface.
func (noopErrReporter) ReportError(context.Context, btcec.PublicKey,
	funding.PendingChanID, error) {
}

// TestAssignFundingProofsConcurrency ensures that handing funding output
// proofs to the event loop neither blocks nor races with concurrent funding
// messages for the same flow. The race detector makes this meaningful.
func TestAssignFundingProofsConcurrency(t *testing.T) {
	t.Parallel()

	f := NewFundingController(FundingControllerCfg{
		ErrReporter: noopErrReporter{},
	})
	f.Wg.Add(1)
	go f.chanFunder()
	t.Cleanup(func() {
		close(f.Quit)
		f.Wg.Wait()
		f.msgQueue.Stop()
	})

	ctx := context.Background()
	peer := *test.RandPubKey(t)
	pid := funding.PendingChanID{7}

	// Seed a funding flow; processing fails at the proof courier check
	// (none is configured), but the flow entry itself remains.
	seeded := f.SendMessage(ctx, msgmux.PeerMsg{
		PeerPub: peer,
		Message: cmsg.NewAssetFundingCreated(pid, nil),
	})
	require.True(t, seeded)

	// Concurrently assign funding output proofs and process incoming
	// funding messages for the same flow.
	fundingProof := randFundingProof(t)
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()

			err := f.assignFundingProofs(
				pid, []*proof.Proof{&fundingProof},
			)
			require.NoError(t, err)
		}()
		go func() {
			defer wg.Done()

			ok := f.SendMessage(ctx, msgmux.PeerMsg{
				PeerPub: peer,
				Message: cmsg.NewAssetFundingCreated(pid, nil),
			})
			require.True(t, ok)
		}()
	}
	wg.Wait()

	// The event loop must still be responsive.
	res := f.DeriveTapscriptRoot(funding.PendingChanID{8})
	root, err := res.Unpack()
	require.NoError(t, err)
	require.True(t, root.IsNone())

	// Handing proofs to a flow that does not exist must fail loudly
	// instead of silently dropping them.
	err = f.assignFundingProofs(
		funding.PendingChanID{9}, []*proof.Proof{&fundingProof},
	)
	require.ErrorContains(t, err, "no funding flow")
}

// TestFundingFlowLimits exercises the bounds on peer-creatable funding
// state: flows per peer, pending chunked proofs, chunks per proof, and
// funding outputs per flow, as well as the reclamation of assembled chunks
// and of expired flows.
func TestFundingFlowLimits(t *testing.T) {
	t.Parallel()

	t.Run("flows per peer", func(t *testing.T) {
		flows := make(fundingFlowIndex)
		peer := *test.RandPubKey(t)

		for i := 0; i < maxActiveFlowsPerPeer; i++ {
			pid := funding.PendingChanID{byte(i + 1)}
			_, _, err := flows.fromMsg(nil, msgmux.PeerMsg{
				PeerPub: peer,
				Message: cmsg.NewAssetFundingCreated(
					pid, nil,
				),
			})
			require.NoError(t, err)
		}
		require.Len(t, flows, maxActiveFlowsPerPeer)

		_, _, err := flows.fromMsg(nil, msgmux.PeerMsg{
			PeerPub: peer,
			Message: cmsg.NewAssetFundingCreated(
				funding.PendingChanID{0xff}, nil,
			),
		})
		require.ErrorContains(t, err, "too many active funding flows")

		// A different peer is not affected by the limit.
		_, _, err = flows.fromMsg(nil, msgmux.PeerMsg{
			PeerPub: *test.RandPubKey(t),
			Message: cmsg.NewAssetFundingCreated(
				funding.PendingChanID{0xfe}, nil,
			),
		})
		require.NoError(t, err)
	})

	t.Run("pending proof streams", func(t *testing.T) {
		fundingState := &pendingAssetFunding{
			inputProofChunks: make(
				map[chainhash.Hash][]cmsg.ProofChunk,
			),
		}

		for i := 0; i < maxFundingInputProofs; i++ {
			var sum [32]byte
			sum[0] = byte(i + 1)
			_, err := fundingState.addInputProofChunk(
				cmsg.NewProofChunk(sum, []byte{1}, false),
			).Unpack()
			require.NoError(t, err)
		}

		var sum [32]byte
		sum[31] = 0xff
		_, err := fundingState.addInputProofChunk(
			cmsg.NewProofChunk(sum, []byte{1}, false),
		).Unpack()
		require.ErrorContains(t, err, "too many pending input proofs")
	})

	t.Run("chunks per proof", func(t *testing.T) {
		fundingState := &pendingAssetFunding{
			inputProofChunks: make(
				map[chainhash.Hash][]cmsg.ProofChunk,
			),
		}

		var sum [32]byte
		sum[0] = 1
		for i := 0; i < maxProofChunks; i++ {
			_, err := fundingState.addInputProofChunk(
				cmsg.NewProofChunk(sum, []byte{1}, false),
			).Unpack()
			require.NoError(t, err)
		}

		_, err := fundingState.addInputProofChunk(
			cmsg.NewProofChunk(sum, []byte{1}, false),
		).Unpack()
		require.ErrorContains(t, err, "too many chunks")
	})

	t.Run("assembled chunks are reclaimed", func(t *testing.T) {
		fundingState := &pendingAssetFunding{
			inputProofChunks: make(
				map[chainhash.Hash][]cmsg.ProofChunk,
			),
		}

		inputProof := randFundingProof(t)
		chunks, err := cmsg.CreateProofChunks(inputProof, 100)
		require.NoError(t, err)
		require.Greater(t, len(chunks), 1)

		for idx, chunk := range chunks {
			finalProof, err := fundingState.addInputProofChunk(
				chunk,
			).Unpack()
			require.NoError(t, err)

			if idx < len(chunks)-1 {
				require.True(t, finalProof.IsNone())
			} else {
				require.False(t, finalProof.IsNone())
			}
		}

		require.Empty(t, fundingState.inputProofChunks)
	})

	t.Run("funding output limit", func(t *testing.T) {
		fundingCommitment, err := commitment.FromAssets(
			fn.Ptr(commitment.TapCommitmentV2),
			asset.RandAsset(t, asset.Normal),
		)
		require.NoError(t, err)

		inputFile, err := proof.NewFile(proof.V0)
		require.NoError(t, err)
		fundingState := &pendingAssetFunding{
			fundingAssetCommitment: fundingCommitment,
			inputProofFiles: map[asset.PrevID]*proof.File{
				{OutPoint: test.RandOp(t)}: inputFile,
			},
		}

		outputs := make([]*cmsg.AssetOutput, maxNumAssetIDs+1)
		for idx := range outputs {
			suffix := randFundingProof(t)
			outputs[idx] = cmsg.NewAssetOutput(
				suffix.Asset.ID(), suffix.Asset.Amount,
				suffix,
			)
		}

		err = validateFundingProofs(
			context.Background(), proof.MockVerifierCtx,
			fundingState, outputs,
		)
		require.ErrorContains(t, err, "too many funding outputs")
	})

	t.Run("expired flows are swept", func(t *testing.T) {
		flows := make(fundingFlowIndex)
		now := time.Now()

		fresh := funding.PendingChanID{1}
		expired := funding.PendingChanID{2}
		flows[fresh] = &pendingAssetFunding{createdAt: now}
		flows[expired] = &pendingAssetFunding{
			createdAt: now.Add(-fundingFlowMaxAge - time.Minute),
		}

		flows.sweepExpired(now)
		require.Contains(t, flows, fresh)
		require.NotContains(t, flows, expired)
	})
}

// TestFundingFlowFailureIsTerminal ensures a responder flow that failed
// validation accepts no further messages and fails descriptor and tapscript
// root requests loudly instead of producing empty channel state.
func TestFundingFlowFailureIsTerminal(t *testing.T) {
	t.Parallel()

	f := NewFundingController(FundingControllerCfg{
		ErrReporter: noopErrReporter{},
	})
	f.Wg.Add(1)
	go f.chanFunder()
	t.Cleanup(func() {
		close(f.Quit)
		f.Wg.Wait()
		f.msgQueue.Stop()
	})

	ctx := context.Background()
	peer := *test.RandPubKey(t)
	pid := funding.PendingChanID{9}

	// This message creates a responder flow and fails validation (no
	// proof courier is configured), which must mark the flow as failed.
	ok := f.SendMessage(ctx, msgmux.PeerMsg{
		PeerPub: peer,
		Message: cmsg.NewAssetFundingCreated(pid, nil),
	})
	require.True(t, ok)

	// Message processing is asynchronous, so poll until the failure has
	// been recorded. A funding descriptor request must then fail instead
	// of returning a descriptor built from zero asset outputs.
	require.Eventually(t, func() bool {
		res := f.DescFromPendingChanID(
			pid, lnwallet.AuxChanState{},
			lntypes.Dual[lnwallet.CommitmentKeyRing]{}, false,
		)
		_, err := res.Unpack()

		return err != nil &&
			strings.Contains(err.Error(), "funding flow failed")
	}, 3*time.Second, 10*time.Millisecond)

	// The tapscript root request must fail the same way.
	rootRes := f.DeriveTapscriptRoot(pid)
	_, err := rootRes.Unpack()
	require.ErrorContains(t, err, "funding flow failed")
}

// TestFundingAckHandling ensures that funding acks can never wedge the
// funding controller's event loop: unsolicited acks create no state, acks
// are only accepted from the bound peer on initiator flows, and duplicates
// are rejected without blocking.
func TestFundingAckHandling(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	f := &FundingController{}

	peer := *test.RandPubKey(t)
	otherPeer := *test.RandPubKey(t)

	newAck := func(peerPub btcec.PublicKey, pid funding.PendingChanID,
		accept bool) msgmux.PeerMsg {

		return msgmux.PeerMsg{
			PeerPub: peerPub,
			Message: cmsg.NewAssetFundingAck(pid, accept),
		}
	}

	t.Run("unsolicited ack creates no flow", func(t *testing.T) {
		flows := make(fundingFlowIndex)
		pid := funding.PendingChanID{1}

		_, err := f.processFundingMsg(
			ctx, flows, newAck(peer, pid, true),
		)
		require.ErrorContains(t, err, "no funding flow for ack")
		require.NotContains(t, flows, pid)
	})

	t.Run("ack for flow we did not initiate", func(t *testing.T) {
		flows := make(fundingFlowIndex)
		pid := funding.PendingChanID{2}
		flows[pid] = &pendingAssetFunding{
			pid:            pid,
			peerPub:        peer,
			fundingAckChan: make(chan bool, 1),
		}

		_, err := f.processFundingMsg(
			ctx, flows, newAck(peer, pid, true),
		)
		require.ErrorContains(t, err, "did not initiate")
	})

	t.Run("ack from wrong peer", func(t *testing.T) {
		flows := make(fundingFlowIndex)
		pid := funding.PendingChanID{3}
		flows[pid] = &pendingAssetFunding{
			pid:            pid,
			peerPub:        peer,
			initiator:      true,
			fundingAckChan: make(chan bool, 1),
		}

		_, err := f.processFundingMsg(
			ctx, flows, newAck(otherPeer, pid, true),
		)
		require.ErrorContains(t, err, "wrong peer")
	})

	t.Run("duplicate acks do not block", func(t *testing.T) {
		flows := make(fundingFlowIndex)
		pid := funding.PendingChanID{4}
		flows[pid] = &pendingAssetFunding{
			pid:            pid,
			peerPub:        peer,
			initiator:      true,
			fundingAckChan: make(chan bool, 1),
		}

		_, err := f.processFundingMsg(
			ctx, flows, newAck(peer, pid, true),
		)
		require.NoError(t, err)

		// A second ack must be rejected instead of blocking the
		// event loop until the buffered value is consumed.
		_, err = f.processFundingMsg(
			ctx, flows, newAck(peer, pid, true),
		)
		require.ErrorContains(t, err, "duplicate funding ack")

		require.True(t, <-flows[pid].fundingAckChan)
	})
}

// TestValidateLocalProofCourier tests that the local proof courier is
// validated correctly.
func TestValidateLocalProofCourier(t *testing.T) {
	serverOpts := []grpc.ServerOption{
		grpc.Creds(insecure.NewCredentials()),
	}
	grpcServer := grpc.NewServer(serverOpts...)

	server := proof.MockUniverseServer{}
	universerpc.RegisterUniverseServer(grpcServer, &server)
	mboxrpc.RegisterMailboxServer(grpcServer, &server)

	mockServerAddr, cleanup, err := test.StartMockGRPCServer(
		t, grpcServer, true,
	)
	require.NoError(t, err)
	t.Cleanup(cleanup)

	tests := []struct {
		name        string
		courierAddr *url.URL
		expectErr   string
	}{
		{
			name: "valid universe rpc courier",
			courierAddr: proof.MockCourierURL(
				t, proof.UniverseRpcCourierType, mockServerAddr,
			),
		},
		{
			name: "valid authmailbox+universe rpc courier",
			courierAddr: proof.MockCourierURL(
				t, proof.AuthMailboxUniRpcCourierType,
				mockServerAddr,
			),
		},
		{
			name: "invalid courier type",
			courierAddr: proof.MockCourierURL(
				t, proof.HashmailCourierType, mockServerAddr,
			),
			expectErr: "unsupported proof courier type " +
				"'hashmail'",
		},
		{
			name:      "nil courier address",
			expectErr: "no proof courier configured",
		},
		{
			name:        "empty courier type",
			courierAddr: &url.URL{},
			expectErr:   "unsupported proof courier type ''",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fc := &FundingController{
				cfg: FundingControllerCfg{
					DefaultCourierAddr: tt.courierAddr,
				},
			}

			// We use a short timeout here, since we don't want to
			// wait for the full default timeout of the funding
			// controller
			ctxb := context.Background()
			ctxb, cancel := context.WithTimeout(
				ctxb, test.StartupWaitTime*2,
			)
			defer cancel()

			err := fc.validateLocalProofCourier(ctxb)
			if tt.expectErr != "" {
				require.ErrorContains(t, err, tt.expectErr)

				return
			}

			require.NoError(t, err)
		})
	}
}
