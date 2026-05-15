package tapfreighter

import (
	"bytes"
	"context"
	"testing"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/stretchr/testify/require"
)

type backoffMockCourier struct {
	*proof.MockProofCourier

	deliverCalls int
}

func newBackoffMockCourier() *backoffMockCourier {
	return &backoffMockCourier{
		MockProofCourier: proof.NewMockProofCourier(),
	}
}

func (m *backoffMockCourier) DeliverProof(context.Context, proof.Recipient,
	*proof.AnnotatedProof, *proof.SendManifest) error {

	m.deliverCalls++

	return &proof.BackoffExecError{}
}

func TestStateStepTransferProofsRetriesIncompleteDelivery(t *testing.T) {
	t.Parallel()

	internalKey := test.PubToKeyDesc(test.RandPubKey(t))
	testProof := randProof(t, 11, internalKey, nil)

	var proofBuf bytes.Buffer
	err := testProof.Encode(&proofBuf)
	require.NoError(t, err)

	output := TransferOutput{
		Anchor: Anchor{
			OutPoint: wire.OutPoint{
				Index: 0,
			},
		},
		ScriptKey:             testProof.Asset.ScriptKey,
		Amount:                11,
		ProofSuffix:           proofBuf.Bytes(),
		ProofCourierAddr:      []byte("mockcourier://localhost:1000"),
		ProofDeliveryComplete: fn.Some(false),
		Position:              0,
	}
	outKey, err := output.UniqueKey()
	require.NoError(t, err)

	assetID := testProof.Asset.ID()
	receiverProof := &proof.AnnotatedProof{
		Locator: proof.Locator{
			AssetID:   &assetID,
			ScriptKey: *output.ScriptKey.PubKey,
		},
	}

	courier := newBackoffMockCourier()
	dispatcher := &proof.MockProofCourierDispatcher{
		Courier: courier,
	}
	porter := &ChainPorter{
		cfg: &ChainPorterConfig{
			ProofCourierDispatcher: dispatcher,
		},
		ContextGuard: &fn.ContextGuard{
			Quit: make(chan struct{}),
		},
	}

	pkg := sendPackage{
		SendState: SendStateTransferProofs,
		OutboundPkg: &OutboundParcel{
			AnchorTx: &wire.MsgTx{
				TxOut: []*wire.TxOut{
					{Value: 1},
				},
			},
			Outputs: []TransferOutput{output},
		},
		FinalProofs: map[OutputIdentifier]*proof.AnnotatedProof{
			outKey: receiverProof,
		},
	}

	nextPkg, err := porter.stateStep(pkg)
	require.NoError(t, err)
	require.Equal(t, SendStateTransferProofs, nextPkg.SendState)
	require.Equal(t, 1, courier.deliverCalls)
}
