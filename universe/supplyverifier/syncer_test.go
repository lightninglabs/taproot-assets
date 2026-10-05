package supplyverifier

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightninglabs/taproot-assets/universe/supplycommit"
	"github.com/stretchr/testify/require"
)

// recordingUniverseClient counts commitment inserts, optionally failing
// them, records the single proofs inserted ahead of them, and serves the
// single proofs it holds by locator hash.
type recordingUniverseClient struct {
	inserts int
	fail    error
	proofs  map[[32]byte]proof.Blob

	// calls records the order of proof and commitment inserts.
	calls []string

	// inserted holds the single proofs inserted, in order.
	inserted []*proof.Proof
}

func (c *recordingUniverseClient) InsertSupplyCommit(_ context.Context,
	_ asset.Specifier, _ supplycommit.RootCommitment,
	_ supplycommit.SupplyLeaves, _ supplycommit.ChainProof) error {

	c.inserts++
	c.calls = append(c.calls, "commit")

	return c.fail
}

func (c *recordingUniverseClient) InsertProof(_ context.Context,
	p *proof.Proof) error {

	c.calls = append(c.calls, "proof")
	c.inserted = append(c.inserted, p)

	return nil
}

func (c *recordingUniverseClient) FetchSupplyCommit(_ context.Context,
	_ asset.Specifier, _ fn.Option[wire.OutPoint]) (
	supplycommit.FetchSupplyCommitResult, error) {

	return supplycommit.FetchSupplyCommitResult{}, errors.New("unused")
}

func (c *recordingUniverseClient) FetchProof(_ context.Context,
	loc proof.Locator) (proof.Blob, error) {

	locHash, err := loc.Hash()
	if err != nil {
		return nil, err
	}

	blob, ok := c.proofs[locHash]
	if !ok {
		return nil, proof.ErrProofNotFound
	}

	return blob, nil
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

// TestPushSupplyCommitmentPublishesBurnProvenance asserts that a commitment
// carrying a burn is pushed only after the provenance of the burn's input:
// the burn leaf's proof is a bare transition, which the server verifies
// against the provenance its own universe holds. The burn itself travels in
// the commitment, so only the proofs before it are published.
func TestPushSupplyCommitmentPublishesBurnProvenance(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	groupPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	delegPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	burnProof, burnFile := randBurnProofWithGroupKey(
		t, groupPrivKey, delegPrivKey.PubKey(),
	)
	genesisProof, err := burnFile.LastProof()
	require.NoError(t, err)
	require.NoError(t, burnFile.AppendProof(burnProof))

	// The local archive holds the burn output's full proof file, keyed
	// the way the chain porter imports it.
	var buf bytes.Buffer
	require.NoError(t, burnFile.Encode(&buf))
	burnOutPoint := burnProof.OutPoint()
	localProofs := proof.NewMockProofArchive()
	err = localProofs.ImportProofs(
		ctx, proof.VerifierCtx{}, false, &proof.AnnotatedProof{
			Locator: proof.Locator{
				AssetID:   fn.Ptr(burnProof.Asset.ID()),
				ScriptKey: *burnProof.Asset.ScriptKey.PubKey,
				OutPoint:  &burnOutPoint,
			},
			Blob: buf.Bytes(),
		},
	)
	require.NoError(t, err)

	addr := universe.NewServerAddrFromStr("a.example:10029")
	client := &recordingUniverseClient{}
	syncer := NewSupplySyncer(SupplySyncerConfig{
		ClientFactory: func(
			universe.ServerAddr) (UniverseClient, error) {

			return client, nil
		},
		Store: &recordingSyncerStore{},
		UniverseFederationView: &staticFederationView{
			servers: []universe.ServerAddr{addr},
		},
		LocalProofs: localProofs,
	})

	leaves := supplycommit.SupplyLeaves{
		BurnLeafEntries: []supplycommit.NewBurnEvent{{
			BurnLeaf: universe.BurnLeaf{
				BurnProof: &burnProof,
			},
		}},
	}
	errMap, err := syncer.PushSupplyCommitment(
		ctx, asset.NewSpecifierFromGroupKey(*test.RandPubKey(t)),
		supplycommit.RootCommitment{Txn: wire.NewMsgTx(2)}, leaves,
		supplycommit.ChainProof{}, nil,
	)
	require.NoError(t, err)
	require.Empty(t, errMap)

	require.Equal(t, []string{"proof", "commit"}, client.calls)

	wantGenesis, err := genesisProof.Bytes()
	require.NoError(t, err)
	gotGenesis, err := client.inserted[0].Bytes()
	require.NoError(t, err)
	require.Equal(t, wantGenesis, gotGenesis)
}

// TestProvenanceAcrossServers asserts that a syncing node assembles a burn's
// full proof file from the single proofs of whichever target universe server
// holds them, walking back from the burn to its genesis.
func TestProvenanceAcrossServers(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	groupPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	delegPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	burnProof, inputFile := randBurnProofWithGroupKey(
		t, groupPrivKey, delegPrivKey.PubKey(),
	)
	genesisProof, err := inputFile.LastProof()
	require.NoError(t, err)

	groupKey := &burnProof.Asset.GroupKey.GroupPubKey
	singleProof := func(p *proof.Proof) ([32]byte, proof.Blob) {
		outPoint := p.OutPoint()
		loc := proof.Locator{
			AssetID:   fn.Ptr(p.Asset.ID()),
			GroupKey:  groupKey,
			ScriptKey: *p.Asset.ScriptKey.PubKey,
			OutPoint:  &outPoint,
		}
		locHash, err := loc.Hash()
		require.NoError(t, err)

		blob, err := p.Bytes()
		require.NoError(t, err)

		return locHash, blob
	}
	genesisHash, genesisBlob := singleProof(genesisProof)
	burnHash, burnBlob := singleProof(&burnProof)

	addrA := universe.NewServerAddrFromStr("a.example:10029")
	addrB := universe.NewServerAddrFromStr("b.example:10029")
	clients := map[string]*recordingUniverseClient{
		addrA.HostStr(): {},
		addrB.HostStr(): {
			proofs: map[[32]byte]proof.Blob{
				genesisHash: genesisBlob,
				burnHash:    burnBlob,
			},
		},
	}
	syncer := NewSupplySyncer(SupplySyncerConfig{
		ClientFactory: func(
			sa universe.ServerAddr) (UniverseClient, error) {

			return clients[sa.HostStr()], nil
		},
		UniverseFederationView: &staticFederationView{
			servers: []universe.ServerAddr{addrA, addrB},
		},
	})

	burnOutPoint := burnProof.OutPoint()
	burnLoc := proof.Locator{
		AssetID:   fn.Ptr(burnProof.Asset.ID()),
		GroupKey:  groupKey,
		ScriptKey: *burnProof.Asset.ScriptKey.PubKey,
		OutPoint:  &burnOutPoint,
	}

	blob, err := syncer.Provenance(nil).FetchProof(ctx, burnLoc)
	require.NoError(t, err)

	file, err := blob.AsFile()
	require.NoError(t, err)
	require.Equal(t, 2, file.NumProofs())

	rawGenesis, err := file.RawProofAt(0)
	require.NoError(t, err)
	require.Equal(t, []byte(genesisBlob), rawGenesis)

	rawBurn, err := file.RawLastProof()
	require.NoError(t, err)
	require.Equal(t, []byte(burnBlob), rawBurn)

	// Once no server holds the chain, the lookup fails with each
	// server's reason.
	clients[addrB.HostStr()].proofs = nil
	_, err = syncer.Provenance(nil).FetchProof(ctx, burnLoc)
	require.ErrorIs(t, err, proof.ErrProofNotFound)
}
