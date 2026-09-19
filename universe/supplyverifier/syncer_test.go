package supplyverifier

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightninglabs/taproot-assets/universe/supplycommit"
	"github.com/stretchr/testify/require"
)

// recordingUniverseClient counts inserts, optionally failing them.
type recordingUniverseClient struct {
	inserts int
	fail    error
}

func (c *recordingUniverseClient) InsertSupplyCommit(_ context.Context,
	_ asset.Specifier, _ supplycommit.RootCommitment,
	_ supplycommit.SupplyLeaves, _ supplycommit.ChainProof) error {

	c.inserts++

	return c.fail
}

func (c *recordingUniverseClient) FetchSupplyCommit(_ context.Context,
	_ asset.Specifier, _ fn.Option[wire.OutPoint]) (
	supplycommit.FetchSupplyCommitResult, error) {

	return supplycommit.FetchSupplyCommitResult{}, errors.New("unused")
}

func (c *recordingUniverseClient) Close() error {
	return nil
}

// recordingSyncerStore records logged pushes and serves them back as
// the pushed-servers view, the way the durable push log does.
type recordingSyncerStore struct {
	mu     sync.Mutex
	logged []string
}

func (s *recordingSyncerStore) LogSupplyCommitPush(_ context.Context,
	serverAddr universe.ServerAddr, _ asset.Specifier,
	_ supplycommit.RootCommitment, _ supplycommit.SupplyLeaves) error {

	s.mu.Lock()
	defer s.mu.Unlock()
	s.logged = append(s.logged, serverAddr.HostStr())

	return nil
}

func (s *recordingSyncerStore) FetchPushedServers(_ context.Context,
	_ asset.Specifier, _ supplycommit.RootCommitment) ([]string, error) {

	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]string(nil), s.logged...), nil
}

// staticFederationView serves a fixed server list.
type staticFederationView struct {
	servers []universe.ServerAddr
}

func (f *staticFederationView) UniverseServers(
	_ context.Context) ([]universe.ServerAddr, error) {

	return f.servers, nil
}

// TestPushSupplyCommitmentSkipsPushed pins the retry contract of the
// commitment push: a server the push log records as delivered is not
// pushed to again. The dispatcher retries the whole effect whenever
// any one server fails, so without the skip every retry re-presents
// the commitment to servers that already integrated it — and a
// receiver without the re-push absorb answers that with its outpoint
// uniqueness violation, keeping the dispatch's error set non-empty
// and its bookkeeping open forever.
func TestPushSupplyCommitmentSkipsPushed(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	addrA := universe.NewServerAddrFromStr("a.example:10029")
	addrB := universe.NewServerAddrFromStr("b.example:10029")

	clients := map[string]*recordingUniverseClient{
		addrA.HostStr(): {},
		addrB.HostStr(): {fail: errors.New("refused")},
	}
	store := &recordingSyncerStore{}
	syncer := NewSupplySyncer(SupplySyncerConfig{
		ClientFactory: func(
			sa universe.ServerAddr) (UniverseClient, error) {

			return clients[sa.HostStr()], nil
		},
		Store: store,
		UniverseFederationView: &staticFederationView{
			servers: []universe.ServerAddr{addrA, addrB},
		},
	})

	spec := asset.NewSpecifierFromGroupKey(*test.RandPubKey(t))
	commitment := supplycommit.RootCommitment{Txn: wire.NewMsgTx(2)}

	push := func() map[string]error {
		errMap, err := syncer.PushSupplyCommitment(
			ctx, spec, commitment, supplycommit.SupplyLeaves{},
			supplycommit.ChainProof{}, nil,
		)
		require.NoError(t, err)

		return errMap
	}

	// First attempt: both servers are targeted; A succeeds and is
	// logged, B fails and is reported.
	errMap := push()
	require.Len(t, errMap, 1)
	require.Contains(t, errMap, addrB.HostStr())
	require.Equal(t, 1, clients[addrA.HostStr()].inserts)
	require.Equal(t, 1, clients[addrB.HostStr()].inserts)
	require.Equal(t, []string{addrA.HostStr()}, store.logged)

	// The retry consults the push log and targets only the server
	// still missing the commitment; once it accepts, the error set
	// is empty and the dispatch can finally report success.
	clients[addrB.HostStr()].fail = nil

	errMap = push()
	require.Empty(t, errMap)
	require.Equal(t, 1, clients[addrA.HostStr()].inserts)
	require.Equal(t, 2, clients[addrB.HostStr()].inserts)

	// A further redelivery, with every server already logged, pushes
	// to nobody.
	errMap = push()
	require.Empty(t, errMap)
	require.Equal(t, 1, clients[addrA.HostStr()].inserts)
	require.Equal(t, 2, clients[addrB.HostStr()].inserts)
}

// TestManagerInsertSupplyCommitAbsorbsRePush pins the receiver half of
// the same contract: a pushed commitment already stored under its
// outpoint is absorbed before verification. Re-verifying would apply
// the leaves against the already-updated supply tree and fail, turning
// every legitimate re-push into a spurious error.
func TestManagerInsertSupplyCommitAbsorbsRePush(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	view := &MockSupplyCommitView{}
	spec := asset.NewSpecifierFromGroupKey(*test.RandPubKey(t))
	commitment := supplycommit.RootCommitment{
		Txn:      wire.NewMsgTx(2),
		TxOutIdx: 0,
	}

	view.On(
		"FetchCommitmentByOutpoint", ctx, spec,
		commitment.CommitPoint(),
	).Return(&supplycommit.RootCommitment{}, nil)

	m := &Manager{cfg: ManagerCfg{SupplyCommitView: view}}
	err := m.InsertSupplyCommit(
		ctx, spec, commitment, supplycommit.SupplyLeaves{},
	)
	require.NoError(t, err)

	// The absorb happens before verification and before any insert.
	view.AssertNotCalled(t, "InsertSupplyCommit")

	// An unexpected lookup failure propagates rather than being
	// mistaken for absence.
	view2 := &MockSupplyCommitView{}
	view2.On(
		"FetchCommitmentByOutpoint", ctx, spec,
		commitment.CommitPoint(),
	).Return(nil, errors.New("db down"))

	m2 := &Manager{cfg: ManagerCfg{SupplyCommitView: view2}}
	err = m2.InsertSupplyCommit(
		ctx, spec, commitment, supplycommit.SupplyLeaves{},
	)
	require.ErrorContains(t, err, "db down")
}
