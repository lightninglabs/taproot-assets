package supplyverifier

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightninglabs/taproot-assets/universe/supplycommit"
	"github.com/lightningnetwork/lnd/chainntnfs"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/protofsm"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// stubCommitView reports every spent-outpoint lookup as a miss, the
// state a spend-triggered sync is in before the issuer's commitment
// has been pulled.
type stubCommitView struct {
	SupplyCommitView
}

func (s *stubCommitView) FetchCommitmentBySpentOutpoint(_ context.Context,
	_ asset.Specifier, _ wire.OutPoint) (*supplycommit.RootCommitment,
	error) {

	return nil, ErrCommitmentNotFound
}

// failingFederationView fails to enumerate universe servers, so every
// pull attempt fails fast without any network access.
type failingFederationView struct{}

func (f *failingFederationView) UniverseServers(
	_ context.Context) ([]universe.ServerAddr, error) {

	return nil, errors.New("no reachable servers")
}

// newSyncVerifyTestEnv builds the minimal environment under which a
// SyncVerifyEvent reaches the pull-retry decision.
func newSyncVerifyTestEnv(t *testing.T) *Environment {
	lookup := &supplycommit.MockAssetLookup{}
	lookup.On(
		"FetchAssetMetaForAsset", mock.Anything, mock.Anything,
	).Return(&proof.MetaReveal{}, nil)

	return &Environment{
		AssetSpec: asset.NewSpecifierFromId(
			asset.ID(test.RandBytes(32)),
		),
		SupplyCommitView: &stubCommitView{},
		AssetLookup:      lookup,
		SupplySyncer: NewSupplySyncer(SupplySyncerConfig{
			UniverseFederationView: &failingFederationView{},
		}),
		SpendSyncDelay: time.Millisecond,
		MaxSyncRetries: 3,
		QuitChan:       make(chan struct{}),
	}
}

// spendDetail builds the minimal spend detail a spend notification
// delivers: the spending transaction, its hash, and its height.
func spendDetail() *chainntnfs.SpendDetail {
	spendTx := &wire.MsgTx{
		TxOut: []*wire.TxOut{{PkScript: test.RandBytes(34)}},
	}
	txid := spendTx.TxHash()

	return &chainntnfs.SpendDetail{
		SpenderTxHash:  &txid,
		SpendingTx:     spendTx,
		SpendingHeight: 100,
	}
}

// TestSyncVerifyPullRetryScope pins the retry policy of the sync
// state's commitment pull. A spend-triggered sync retries — the
// observed spend proves the successor commitment exists — first with
// fast in-place attempts, then re-armed once per further confirmation
// of the spending transaction: the issuer act-gates publication on a
// burial depth the verifier cannot know, so the wall clock alone
// exhausts long before the chain clock has caught up. The escalation
// ends at the chain notifier's depth ceiling, and a sync without an
// observed spend does not retry at all: the canonical universe URLs
// the pull targets come from issuer-controlled metadata, so an
// unbounded retry loop would let an issuer park the machine's
// goroutine forever.
func TestSyncVerifyPullRetryScope(t *testing.T) {
	t.Parallel()

	env := newSyncVerifyTestEnv(t)
	state := &SyncVerifyState{}
	spentOutpoint := fn.Some(wire.OutPoint{Index: 1})
	detail := spendDetail()

	// A spend-triggered sync whose pull fails re-enters the sync
	// state with the attempt counter advanced and the spend context
	// preserved.
	trans, err := state.ProcessEvent(&SyncVerifyEvent{
		SpentCommitOutpoint: spentOutpoint,
		SpendDetail:         detail,
		SpendConfDepth:      1,
	}, env)
	require.NoError(t, err)
	require.IsType(t, &SyncVerifyState{}, trans.NextState)

	events, err := trans.NewEvents.UnwrapOrErr(
		errors.New("no retry event emitted"),
	)
	require.NoError(t, err)
	require.Len(t, events.InternalEvent, 1)

	retry, ok := events.InternalEvent[0].(*SyncVerifyEvent)
	require.True(t, ok)
	require.Equal(t, 1, retry.RetryAttempt)
	require.Equal(t, spentOutpoint, retry.SpentCommitOutpoint)
	require.Same(t, detail, retry.SpendDetail)
	require.EqualValues(t, 1, retry.SpendConfDepth)

	// Exhausting the fast attempts escalates to the chain clock:
	// the machine registers for the spending transaction's next
	// confirmation rather than reporting an error.
	trans, err = state.ProcessEvent(&SyncVerifyEvent{
		SpentCommitOutpoint: spentOutpoint,
		RetryAttempt:        env.MaxSyncRetries,
		SpendDetail:         detail,
		SpendConfDepth:      1,
	}, env)
	require.NoError(t, err)
	require.IsType(t, &SyncVerifyState{}, trans.NextState)

	events, err = trans.NewEvents.UnwrapOrErr(
		errors.New("no re-arm event emitted"),
	)
	require.NoError(t, err)
	require.Len(t, events.ExternalEvents, 1)

	confReg, ok := events.ExternalEvents[0].(*protofsm.RegisterConf[Event])
	require.True(t, ok)
	require.Equal(t, *detail.SpenderTxHash, confReg.Txid)
	require.Equal(t, lfn.Some(uint32(2)), confReg.NumConfs)

	// The confirmation firing starts a fresh round of fast attempts
	// one depth further along.
	mapper, err := confReg.PostConfMapper.UnwrapOrErr(
		errors.New("no conf mapper"),
	)
	require.NoError(t, err)

	next, ok := mapper(&chainntnfs.TxConfirmation{}).(*SyncVerifyEvent)
	require.True(t, ok)
	require.Zero(t, next.RetryAttempt)
	require.EqualValues(t, 2, next.SpendConfDepth)
	require.Same(t, detail, next.SpendDetail)
	require.Equal(t, spentOutpoint, next.SpentCommitOutpoint)

	// Past the chain notifier's depth ceiling no burial threshold
	// can still be pending, so the failure is finally reported.
	_, err = state.ProcessEvent(&SyncVerifyEvent{
		SpentCommitOutpoint: spentOutpoint,
		RetryAttempt:        env.MaxSyncRetries,
		SpendDetail:         detail,
		SpendConfDepth:      chainntnfs.MaxNumConfs,
	}, env)
	require.ErrorContains(t, err, "confirmations")

	// Without an observed spend there is no proof the commitment
	// exists, so a failed pull is an error, not a retry.
	_, err = state.ProcessEvent(&SyncVerifyEvent{
		SpentCommitOutpoint: spentOutpoint,
	}, env)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "confirmations")
}

// blockingFederationView blocks until the caller's context is
// cancelled: the shape of a hung network round.
type blockingFederationView struct{}

func (b *blockingFederationView) UniverseServers(
	ctx context.Context) ([]universe.ServerAddr, error) {

	<-ctx.Done()

	return nil, ctx.Err()
}

// TestSyncVerifyPullQuitScoped asserts the commitment pull is scoped
// to the verifier's lifetime: closing the quit channel interrupts an
// in-flight network round rather than waiting it out. The inter-
// attempt retry wait was always quit-aware; without a quit-scoped
// pull context, shutdown stalls behind whatever round is in flight —
// and the federation enumeration before the pull carries no timeout
// of its own at all.
func TestSyncVerifyPullQuitScoped(t *testing.T) {
	t.Parallel()

	env := newSyncVerifyTestEnv(t)
	quit := make(chan struct{})
	env.QuitChan = quit
	env.SupplySyncer = NewSupplySyncer(SupplySyncerConfig{
		UniverseFederationView: &blockingFederationView{},
	})

	done := make(chan error, 1)
	go func() {
		_, err := (&SyncVerifyState{}).ProcessEvent(&SyncVerifyEvent{
			SpentCommitOutpoint: fn.Some(wire.OutPoint{Index: 1}),
		}, env)
		done <- err
	}()

	close(quit)

	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown waited out an in-flight pull")
	}
}
