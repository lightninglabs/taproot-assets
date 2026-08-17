package tapchannel

import (
	"context"
	"net/url"
	"testing"

	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	cmsg "github.com/lightninglabs/taproot-assets/tapchannelmsg"
	mboxrpc "github.com/lightninglabs/taproot-assets/taprpc/authmailboxrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/universerpc"
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
