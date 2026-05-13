package tapfreighter

import (
	"errors"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btclog/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/stretchr/testify/require"
)

func TestRunChainPorter(t *testing.T) {
	t.Parallel()
}

func newTestChainPorter() *ChainPorter {
	porter := NewChainPorter(&ChainPorterConfig{})
	porter.outboundParcels = make(chan Parcel, 1)

	return porter
}

func newTestSendPackage(state SendState) *sendPackage {
	return &sendPackage{
		SendState: state,
		OutboundPkg: &OutboundParcel{
			AnchorTx: wire.NewMsgTx(2),
		},
	}
}

func init() {
	rand.Seed(time.Now().Unix())

	logger := btclog.NewSLogger(btclog.NewDefaultHandler(os.Stdout))
	UseLogger(logger.SubSystem(Subsystem))
}

// TestVerifySplitCommitmentWitnesses exercises the split witness verifier with
// table-driven vPacket fixtures.
func TestVerifySplitCommitmentWitnesses(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		vPkt        func() tappsbt.VPacket
		expectError bool
	}{
		{
			name: "split leaf with root witness passes",
			vPkt: func() tappsbt.VPacket {
				root := asset.Asset{
					PrevWitnesses: []asset.Witness{{
						PrevID:    &asset.ZeroPrevID,
						TxWitness: wire.TxWitness{{1}},
					}},
				}

				prevWitnesses := []asset.Witness{{
					PrevID: &asset.ZeroPrevID,
					SplitCommitment: &asset.SplitCommitment{
						RootAsset: root,
					},
				}}
				splitLeaf := &asset.Asset{
					PrevWitnesses: prevWitnesses,
				}

				return tappsbt.VPacket{
					Outputs: []*tappsbt.VOutput{{
						Asset: splitLeaf,
					}},
				}
			},
			expectError: false,
		},
		{
			name: "split leaf missing root witness fails",
			vPkt: func() tappsbt.VPacket {
				root := asset.Asset{
					PrevWitnesses: []asset.Witness{{
						PrevID:    &asset.ZeroPrevID,
						TxWitness: wire.TxWitness{},
					}},
				}

				prevWitnesses := []asset.Witness{{
					PrevID: &asset.ZeroPrevID,
					SplitCommitment: &asset.SplitCommitment{
						RootAsset: root,
					},
				}}
				splitLeaf := &asset.Asset{
					PrevWitnesses: prevWitnesses,
				}

				return tappsbt.VPacket{
					Outputs: []*tappsbt.VOutput{{
						Asset: splitLeaf,
					}},
				}
			},
			expectError: true,
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := verifySplitCommitmentWitnesses(tc.vPkt())
			if tc.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
		})
	}
}

func TestAdvanceStateNonBlockingErrSignalBackgroundParcel(t *testing.T) {
	t.Parallel()

	porter := newTestChainPorter()
	pkg := newTestSendPackage(SendStateStartHandleAddrParcel)
	kit := &parcelKit{
		errChan: make(chan error),
	}

	done := make(chan struct{})
	go func() {
		defer close(done)

		porter.advanceState(pkg, kit)
	}()

	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatalf("advanceState blocked on background error delivery")
	}
}

func TestAdvanceStatePermanentFailureClearsRetryBookkeeping(t *testing.T) {
	t.Parallel()

	porter := newTestChainPorter()
	pkg := newTestSendPackage(SendStateStartHandleAddrParcel)
	pkg.Parcel = NewPendingParcel(pkg.OutboundPkg)

	txID := pkg.OutboundPkg.AnchorTx.TxHash()
	porter.postDeliveryRetryAttempts[txID] = 2

	kit := &parcelKit{
		errChan: make(chan error, 1),
	}

	porter.advanceState(pkg, kit)

	select {
	case err := <-kit.errChan:
		require.Error(t, err)
	case <-time.After(200 * time.Millisecond):
		t.Fatalf("expected terminal error")
	}

	_, exists := porter.postDeliveryRetryAttempts[txID]
	require.False(t, exists)
}

func TestSchedulePostDeliveryRetryIncrementsAndRequeues(t *testing.T) {
	t.Parallel()

	porter := newTestChainPorter()
	defer close(porter.Quit)

	pkg := newTestSendPackage(SendStateTransferProofs)
	txID := pkg.OutboundPkg.AnchorTx.TxHash()

	recoverable := porter.schedulePostDeliveryRetry(
		pkg, SendStateTransferProofs, errors.New("recoverable failure"),
	)
	require.True(t, recoverable)
	require.EqualValues(t, 1, porter.postDeliveryRetryAttempts[txID])

	select {
	case retryParcel := <-porter.outboundParcels:
		pendingParcel, ok := retryParcel.(*PendingParcel)
		require.True(t, ok)
		require.Equal(
			t, SendStateBroadcast, pendingParcel.pkg().SendState,
		)

	case <-time.After(1500 * time.Millisecond):
		t.Fatalf("expected pending parcel to be re-queued")
	}
}

func TestSchedulePostDeliveryRetryMaxAttemptsStopsRetrying(t *testing.T) {
	t.Parallel()

	porter := newTestChainPorter()
	defer close(porter.Quit)

	pkg := newTestSendPackage(SendStateTransferProofs)
	txID := pkg.OutboundPkg.AnchorTx.TxHash()

	porter.postDeliveryRetryAttempts[txID] = postDeliveryRetryMaxAttempts

	recoverable := porter.schedulePostDeliveryRetry(
		pkg, SendStateTransferProofs, errors.New("still failing"),
	)
	require.False(t, recoverable)

	_, exists := porter.postDeliveryRetryAttempts[txID]
	require.False(t, exists)

	select {
	case <-porter.outboundParcels:
		t.Fatalf("did not expect pending parcel re-queue")
	case <-time.After(100 * time.Millisecond):
	}
}
