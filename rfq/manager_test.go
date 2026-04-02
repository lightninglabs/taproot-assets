package rfq

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/neutrino/cache/lru"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	tpchmsg "github.com/lightninglabs/taproot-assets/tapchannelmsg"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	asset1 = asset.Asset{
		ScriptKey: asset.ScriptKey{
			PubKey: asset.NUMSPubKey,
		},
		Genesis: asset.Genesis{
			Tag: "111",
		},
	}
	asset2 = asset.Asset{
		ScriptKey: asset.ScriptKey{
			PubKey: asset.NUMSPubKey,
		},
		Genesis: asset.Genesis{
			Tag: "222",
		},
	}
	asset3 = asset.Asset{
		ScriptKey: asset.ScriptKey{
			PubKey: asset.NUMSPubKey,
		},
		Genesis: asset.Genesis{
			Tag: "333",
		},
	}
	testAssetID1 = asset1.ID()
	testAssetID2 = asset2.ID()
	testAssetID3 = asset3.ID()
	proof1       = proof.Proof{
		Asset: asset1,
	}
	proof2 = proof.Proof{
		Asset: asset2,
	}
	proof3 = proof.Proof{
		Asset: asset3,
	}
	testGroupKey = pubKeyFromUint64(2121)
	peer1        = route.Vertex{88}
	peer2        = route.Vertex{77}
)

type mockPolicyStore struct{}

func (mockPolicyStore) StoreSalePolicy(context.Context,
	rfqmsg.BuyAccept) error {

	return nil
}

func (mockPolicyStore) StorePurchasePolicy(context.Context,
	rfqmsg.SellAccept) error {

	return nil
}

func (mockPolicyStore) FetchAcceptedQuotes(context.Context) (
	[]rfqmsg.BuyAccept, []rfqmsg.SellAccept, []rfqmsg.BuyAccept, error) {

	return nil, nil, nil, nil
}

func (mockPolicyStore) StorePeerAcceptedBuyQuote(context.Context,
	rfqmsg.BuyAccept) error {

	return nil
}

func (mockPolicyStore) LookUpScid(_ context.Context,
	_ uint64) (route.Vertex, error) {

	return route.Vertex{}, fmt.Errorf("not found")
}

type mockAliasManager struct {
	addErr   error
	addCalls int
}

func (m *mockAliasManager) AddLocalAlias(context.Context, lnwire.ShortChannelID,
	lnwire.ShortChannelID) error {

	m.addCalls++
	return m.addErr
}

func (*mockAliasManager) DeleteLocalAlias(context.Context,
	lnwire.ShortChannelID, lnwire.ShortChannelID) error {

	return nil
}

func (*mockAliasManager) FetchBaseAlias(context.Context,
	lnwire.ShortChannelID) (lnwire.ShortChannelID, error) {

	return lnwire.ShortChannelID{}, nil
}

type mockChannelLister struct {
	channels []lndclient.ChannelInfo
	err      error
}

func (m *mockChannelLister) ListChannels(context.Context, bool, bool,
	...lndclient.ListChannelsOption) ([]lndclient.ChannelInfo, error) {

	if m.err != nil {
		return nil, m.err
	}

	return m.channels, nil
}

func testBuyAcceptForAliasRetry(t *testing.T, peer route.Vertex) rfqmsg.BuyAccept {
	t.Helper()

	rfqID, err := rfqmsg.NewID()
	require.NoError(t, err)

	rate := rfqmath.BigIntFixedPoint{
		Coefficient: rfqmath.NewBigInt(big.NewInt(100_000)),
		Scale:       0,
	}

	return rfqmsg.BuyAccept{
		Peer:    peer,
		Version: rfqmsg.V1,
		ID:      rfqID,
		AssetRate: rfqmsg.NewAssetRate(
			rate, time.Now().Add(5*time.Minute),
		),
		Request: rfqmsg.BuyRequest{
			Peer:                peer,
			Version:             rfqmsg.V1,
			ID:                  rfqID,
			AssetSpecifier:      asset.NewSpecifierFromId(testAssetID1),
			AssetMaxAmt:         1_000,
			AssetRateHint:       fn.None[rfqmsg.AssetRate](),
			PriceOracleMetadata: "meta",
		},
		AgreedAt: time.Now().UTC(),
	}
}

func testManagerForAliasTests(t *testing.T, aliasErr error) (*Manager,
	*mockAliasManager, chan rfqmsg.OutgoingMsg, chan error) {

	t.Helper()

	managerErrChan := make(chan error, 1)
	aliasMgr := &mockAliasManager{addErr: aliasErr}

	channel := createChannelWithCustomData(
		t, testAssetID1, 10_000, 10_000, proof1, peer1,
	)
	channel.ChannelID = 101

	cfg := ManagerCfg{
		GroupLookup:   &GroupLookupMock{},
		PolicyStore:   mockPolicyStore{},
		AliasManager:  aliasMgr,
		ChannelLister: &mockChannelLister{channels: []lndclient.ChannelInfo{channel}},
		ErrChan:       managerErrChan,
	}
	manager, err := NewManager(cfg)
	require.NoError(t, err)

	manager.orderHandler = &OrderHandler{}

	outgoing := make(chan rfqmsg.OutgoingMsg, 2)
	manager.negotiator = &Negotiator{
		cfg: NegotiatorCfg{
			OutgoingMessages:      outgoing,
			SkipQuoteAcceptVerify: true,
			ErrChan:               make(chan error, 1),
		},
		ContextGuard: &fn.ContextGuard{
			DefaultTimeout: DefaultTimeout,
			Quit:           make(chan struct{}),
		},
	}

	return manager, aliasMgr, outgoing, managerErrChan
}

func TestIsAliasCollisionErr(t *testing.T) {
	t.Parallel()

	collisionErr := status.Error(codes.AlreadyExists, "alias already exists")
	require.True(t, isAliasCollisionErr(collisionErr))
	require.True(t, isAliasCollisionErr(fmt.Errorf("wrapped: %w", collisionErr)))
	require.True(t, isAliasCollisionErr(
		fmt.Errorf("ErrAliasAlreadyExists from lnd"),
	))

	nonCollisionErr := status.Error(codes.Internal, "backend unavailable")
	require.False(t, isAliasCollisionErr(nonCollisionErr))
	require.False(t, isAliasCollisionErr(nil))
}

func TestAddScidAliasCollisionIsRecoverable(t *testing.T) {
	t.Parallel()

	manager, _, _, _ := testManagerForAliasTests(
		t, status.Error(codes.AlreadyExists, "alias already exists"),
	)

	err := manager.addScidAlias(
		42, asset.NewSpecifierFromId(testAssetID1), peer1,
	)
	require.Error(t, err)
	require.True(t, isAliasCollisionErr(err))

	var criticalErr *fn.CriticalError
	require.False(t, errors.As(err, &criticalErr))
}

func TestAddScidAliasNonCollisionIsCritical(t *testing.T) {
	t.Parallel()

	manager, _, _, _ := testManagerForAliasTests(
		t, status.Error(codes.Internal, "db unavailable"),
	)

	err := manager.addScidAlias(
		42, asset.NewSpecifierFromId(testAssetID1), peer1,
	)
	require.Error(t, err)

	var criticalErr *fn.CriticalError
	require.True(t, errors.As(err, &criticalErr))
}

func TestHandleIncomingBuyAcceptAliasCollisionRetries(t *testing.T) {
	t.Parallel()

	manager, aliasMgr, outgoing, managerErrChan := testManagerForAliasTests(
		t, status.Error(codes.AlreadyExists, "alias already exists"),
	)
	buyAccept := testBuyAcceptForAliasRetry(t, peer1)

	err := manager.handleIncomingMessage(context.Background(), &buyAccept)
	require.NoError(t, err)
	require.Equal(t, 1, aliasMgr.addCalls)

	select {
	case msg := <-outgoing:
		retryReq, ok := msg.(*rfqmsg.BuyRequest)
		require.True(t, ok)
		require.NotEqual(t, buyAccept.ID, retryReq.ID)
		require.Equal(t, buyAccept.Peer, retryReq.Peer)
		require.Equal(t, buyAccept.Request.AssetSpecifier,
			retryReq.AssetSpecifier)
		require.Equal(t, buyAccept.Request.AssetMaxAmt,
			retryReq.AssetMaxAmt)
		require.Equal(t, buyAccept.Request.PriceOracleMetadata,
			retryReq.PriceOracleMetadata)
	default:
		t.Fatal("expected a retried buy request")
	}

	_, ok := manager.orderHandler.peerBuyQuotes.Load(
		buyAccept.ShortChannelId(),
	)
	require.False(t, ok, "colliding quote should not be retained")

	select {
	case err := <-managerErrChan:
		t.Fatalf("unexpected critical manager error: %v", err)
	default:
	}
}

func TestHandleIncomingBuyAcceptNonCollisionAliasErrorCritical(t *testing.T) {
	t.Parallel()

	manager, aliasMgr, outgoing, managerErrChan := testManagerForAliasTests(
		t, status.Error(codes.Internal, "db unavailable"),
	)
	buyAccept := testBuyAcceptForAliasRetry(t, peer1)

	err := manager.handleIncomingMessage(context.Background(), &buyAccept)
	require.NoError(t, err)
	require.Equal(t, 1, aliasMgr.addCalls)

	select {
	case managerErr := <-managerErrChan:
		var criticalErr *fn.CriticalError
		require.True(t, errors.As(managerErr, &criticalErr))
	default:
		t.Fatal("expected critical manager error for non-collision failure")
	}

	select {
	case <-outgoing:
		t.Fatal("unexpected retry buy request on non-collision failure")
	default:
	}

	_, ok := manager.orderHandler.peerBuyQuotes.Load(
		buyAccept.ShortChannelId(),
	)
	require.False(t, ok, "failed quote should not be retained")
}

// lookUpPolicyStore is a mock PolicyStore that supports configurable LookUpScid
// responses for testing the Manager.LookUpScid method.
type lookUpPolicyStore struct {
	mockPolicyStore

	// peers maps SCIDs to peers returned by LookUpScid.
	peers map[uint64]route.Vertex
}

func (l *lookUpPolicyStore) LookUpScid(_ context.Context,
	scid uint64) (route.Vertex, error) {

	peer, ok := l.peers[scid]
	if !ok {
		return route.Vertex{}, fmt.Errorf("not found")
	}

	return peer, nil
}

// TestLookUpScidActiveMap verifies that LookUpScid returns the peer from the
// active in-memory peerBuyQuotes map when a matching entry exists.
func TestLookUpScidActiveMap(t *testing.T) {
	t.Parallel()

	store := &lookUpPolicyStore{peers: make(map[uint64]route.Vertex)}
	cfg := ManagerCfg{
		GroupLookup: &GroupLookupMock{},
		PolicyStore: store,
	}
	manager, err := NewManager(cfg)
	require.NoError(t, err)

	// Manually initialise the orderHandler so we can populate the map.
	manager.orderHandler = &OrderHandler{}

	scid := rfqmsg.SerialisedScid(42)
	manager.orderHandler.peerBuyQuotes.Store(scid, rfqmsg.BuyAccept{
		Peer: peer1,
	})

	got, err := manager.LookUpScid(uint64(scid))
	require.NoError(t, err)
	require.Equal(t, peer1, got)
}

// TestLookUpScidLRUCache verifies that LookUpScid returns the peer from the
// LRU cache when it's not in the active map but has been previously cached.
func TestLookUpScidLRUCache(t *testing.T) {
	t.Parallel()

	store := &lookUpPolicyStore{peers: make(map[uint64]route.Vertex)}
	cfg := ManagerCfg{
		GroupLookup: &GroupLookupMock{},
		PolicyStore: store,
	}
	manager, err := NewManager(cfg)
	require.NoError(t, err)

	manager.orderHandler = &OrderHandler{}

	// Pre-populate the LRU cache directly.
	scid := rfqmsg.SerialisedScid(99)
	_, _ = manager.scidCache.Put(scid, &cachedPeer{peer: peer2})

	got, err := manager.LookUpScid(uint64(scid))
	require.NoError(t, err)
	require.Equal(t, peer2, got)
}

// TestLookUpScidDBFallback verifies that LookUpScid falls back to the DB when
// the SCID is not in the active map or LRU cache, and that the result is
// subsequently cached in the LRU.
func TestLookUpScidDBFallback(t *testing.T) {
	t.Parallel()

	store := &lookUpPolicyStore{
		peers: map[uint64]route.Vertex{
			200: peer1,
		},
	}
	cfg := ManagerCfg{
		GroupLookup: &GroupLookupMock{},
		PolicyStore: store,
	}
	manager, err := NewManager(cfg)
	require.NoError(t, err)

	manager.orderHandler = &OrderHandler{}

	// SCID 200 is only in the mock DB, not in the active map or cache.
	got, err := manager.LookUpScid(200)
	require.NoError(t, err)
	require.Equal(t, peer1, got)

	// Verify the result was cached in the LRU.
	cached, err := manager.scidCache.Get(rfqmsg.SerialisedScid(200))
	require.NoError(t, err)
	require.Equal(t, peer1, cached.peer)
}

// TestLookUpScidNotFound verifies that LookUpScid returns an error when the
// SCID is not found in any tier.
func TestLookUpScidNotFound(t *testing.T) {
	t.Parallel()

	store := &lookUpPolicyStore{peers: make(map[uint64]route.Vertex)}
	cfg := ManagerCfg{
		GroupLookup: &GroupLookupMock{},
		PolicyStore: store,
	}
	manager, err := NewManager(cfg)
	require.NoError(t, err)

	manager.orderHandler = &OrderHandler{}

	_, err = manager.LookUpScid(12345)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no peer found for RFQ SCID")
}

// TestLookUpScidConcurrent exercises LookUpScid from multiple goroutines to
// verify there are no data races between the SyncMap, LRU cache, and DB
// fallback paths.
func TestLookUpScidConcurrent(t *testing.T) {
	t.Parallel()

	const numGoroutines = 50
	const numSCIDs = 20

	// Populate the mock DB with numSCIDs entries.
	peers := make(map[uint64]route.Vertex)
	for i := uint64(0); i < numSCIDs; i++ {
		var v route.Vertex
		v[0] = byte(i)
		peers[i] = v
	}
	store := &lookUpPolicyStore{peers: peers}

	cfg := ManagerCfg{
		GroupLookup: &GroupLookupMock{},
		PolicyStore: store,
	}
	manager, err := NewManager(cfg)
	require.NoError(t, err)

	manager.orderHandler = &OrderHandler{}

	// Also put some entries in the active map to exercise that path.
	for i := uint64(0); i < numSCIDs/2; i++ {
		manager.orderHandler.peerBuyQuotes.Store(
			rfqmsg.SerialisedScid(i),
			rfqmsg.BuyAccept{Peer: peers[i]},
		)
	}

	errCh := make(chan error, numGoroutines*numSCIDs)
	var wg sync.WaitGroup

	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for s := uint64(0); s < numSCIDs; s++ {
				got, err := manager.LookUpScid(s)
				if err != nil {
					errCh <- err
					return
				}
				if got != peers[s] {
					errCh <- fmt.Errorf(
						"SCID %d: got %v, "+
							"want %v",
						s, got, peers[s],
					)
					return
				}
			}
		}()
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatal(err)
	}
}

// TestLookUpScidLRUEviction verifies that when the LRU cache is full, evicted
// entries can still be resolved via the DB fallback, and the newly fetched
// result is re-cached.
func TestLookUpScidLRUEviction(t *testing.T) {
	t.Parallel()

	// Create a manager with a tiny LRU cache of size 2 for easier testing.
	peers := map[uint64]route.Vertex{
		1: {0x01},
		2: {0x02},
		3: {0x03},
	}
	store := &lookUpPolicyStore{peers: peers}

	cfg := ManagerCfg{
		GroupLookup: &GroupLookupMock{},
		PolicyStore: store,
	}
	manager, err := NewManager(cfg)
	require.NoError(t, err)

	manager.orderHandler = &OrderHandler{}

	// Replace the cache with a tiny one (size 2).
	manager.scidCache = lru.NewCache[
		rfqmsg.SerialisedScid, *cachedPeer,
	](2)

	// Look up SCIDs 1, 2, 3 (all DB fallback). After this, SCID 1
	// should be evicted from the 2-slot LRU.
	for _, scid := range []uint64{1, 2, 3} {
		got, err := manager.LookUpScid(scid)
		require.NoError(t, err)
		require.Equal(t, peers[scid], got)
	}

	// SCID 1 should have been evicted. Verify it's not in cache.
	_, err = manager.scidCache.Get(rfqmsg.SerialisedScid(1))
	require.Error(t, err, "SCID 1 should have been evicted")

	// But looking it up again should succeed via DB fallback.
	got, err := manager.LookUpScid(1)
	require.NoError(t, err)
	require.Equal(t, peers[uint64(1)], got)

	// And now it should be back in the cache.
	cached, err := manager.scidCache.Get(rfqmsg.SerialisedScid(1))
	require.NoError(t, err)
	require.Equal(t, peers[uint64(1)], cached.peer)
}

// failingPolicyStore is a mock that returns an error from
// StorePeerAcceptedBuyQuote while LookUpScid works normally.
type failingPolicyStore struct {
	mockPolicyStore

	peers map[uint64]route.Vertex
}

func (f *failingPolicyStore) StorePeerAcceptedBuyQuote(context.Context,
	rfqmsg.BuyAccept) error {

	return fmt.Errorf("simulated DB write failure")
}

func (f *failingPolicyStore) LookUpScid(_ context.Context,
	scid uint64) (route.Vertex, error) {

	peer, ok := f.peers[scid]
	if !ok {
		return route.Vertex{}, fmt.Errorf("not found")
	}

	return peer, nil
}

// TestLookUpScidPersistenceFailure verifies that when the DB write for
// StorePeerAcceptedBuyQuote fails, the active in-memory map is unaffected and
// LookUpScid still works for entries in the map.
func TestLookUpScidPersistenceFailure(t *testing.T) {
	t.Parallel()

	store := &failingPolicyStore{
		peers: make(map[uint64]route.Vertex),
	}
	cfg := ManagerCfg{
		GroupLookup: &GroupLookupMock{},
		PolicyStore: store,
	}
	manager, err := NewManager(cfg)
	require.NoError(t, err)

	manager.orderHandler = &OrderHandler{}

	// Simulate the active map having been populated (which happens
	// regardless of DB write success in the real code path).
	scid := rfqmsg.SerialisedScid(42)
	manager.orderHandler.peerBuyQuotes.Store(scid, rfqmsg.BuyAccept{
		Peer: peer1,
	})

	// LookUpScid should find the entry in the active map even though
	// persistence would have failed.
	got, err := manager.LookUpScid(uint64(scid))
	require.NoError(t, err)
	require.Equal(t, peer1, got)

	// SCID 999 is not in any tier — should fail.
	_, err = manager.LookUpScid(999)
	require.Error(t, err)
}

// GroupLookupMock mocks the GroupLookup interface that is required by the
// rfq manager to check asset IDs against asset specifiers.
type GroupLookupMock struct{}

// QueryAssetGroupByID fetches the group information of an asset, if it belongs
// in a group.
func (g *GroupLookupMock) QueryAssetGroupByID(_ context.Context,
	id asset.ID) (*asset.AssetGroup, error) {

	// We only consider testAssetID1 and testAssetID2 to be in the group.
	if id == testAssetID1 || id == testAssetID2 {
		return &asset.AssetGroup{
			GroupKey: &asset.GroupKey{
				GroupPubKey: *testGroupKey,
			},
		}, nil
	}

	return nil, address.ErrAssetGroupUnknown
}

// testCaseComputeChannelAssetBalance is a test case for computing the channel
// asset balances.
type testCaseComputeChannelAssetBalance struct {
	name               string
	activeChannels     []lndclient.ChannelInfo
	specifier          asset.Specifier
	expectedValidPeers int
	expectedLocalBal   uint64
	expectedRemoteBal  uint64
}

// createChannelWithCustomData creates a dummy channel with only the custom data
// and peer fields populated. The custom data encode the local and remote
// balances of the given asset ID.
func createChannelWithCustomData(t *testing.T, id asset.ID, localBalance,
	remoteBalance uint64, proof proof.Proof,
	peer route.Vertex) lndclient.ChannelInfo {

	customData := tpchmsg.ChannelCustomData{
		LocalCommit: *tpchmsg.NewCommitment(
			[]*tpchmsg.AssetOutput{
				tpchmsg.NewAssetOutput(
					id, localBalance, proof,
				),
			},
			[]*tpchmsg.AssetOutput{
				tpchmsg.NewAssetOutput(
					id, remoteBalance, proof,
				),
			},
			nil, nil, lnwallet.CommitAuxLeaves{},
			false,
		),
		OpenChan: *tpchmsg.NewOpenChannel(
			[]*tpchmsg.AssetOutput{
				tpchmsg.NewAssetOutput(
					id,
					localBalance+remoteBalance, proof,
				),
			}, 0, nil,
		),
	}

	data, err := customData.AsJson()
	require.NoError(t, err)

	return lndclient.ChannelInfo{
		CustomChannelData: data,
		PubKeyBytes:       peer,
	}
}

// assertComputeChannelAssetBalance asserts that the manager can compute the
// correct asset balances for the test case. It also compares the results
// against some expected values.
func assertComputeChannelAssetBalance(t *testing.T,
	tc testCaseComputeChannelAssetBalance) {

	mockGroupLookup := &GroupLookupMock{}
	cfg := ManagerCfg{
		GroupLookup: mockGroupLookup,
		PolicyStore: mockPolicyStore{},
	}
	manager, err := NewManager(cfg)
	require.NoError(t, err)

	ctxt, cancel := context.WithTimeout(
		context.Background(), DefaultTimeout,
	)
	defer cancel()

	chanMap, _, err := manager.ComputeChannelAssetBalance(
		ctxt, tc.activeChannels, tc.specifier,
	)
	require.NoError(t, err)

	// We avoid using require.Len directly on the map here as it will print
	// the whole map on fail.
	require.Equal(t, tc.expectedValidPeers, len(chanMap))

	var totalLocal, totalRemote uint64

	for _, v := range chanMap {
		for _, ch := range v {
			totalLocal += ch.AssetInfo.LocalBalance
			totalRemote += ch.AssetInfo.RemoteBalance
		}
	}

	require.Equal(t, tc.expectedLocalBal, totalLocal)
	require.Equal(t, tc.expectedRemoteBal, totalRemote)
}

// TestComputeChannelAssetBalance tests that the rfq manager can correctly
// filter the channels according to the asset ID of the channel and the provided
// asset specifier.
func TestComputeChannelAssetBlanace(t *testing.T) {
	testCases := []testCaseComputeChannelAssetBalance{
		{
			name: "1 asset 1 channel 1 peer",
			activeChannels: []lndclient.ChannelInfo{
				createChannelWithCustomData(
					t, testAssetID1, 10_000, 15_000, proof1,
					peer1,
				),
			},
			specifier: asset.NewSpecifierFromId(
				testAssetID1,
			),
			expectedValidPeers: 1,
			expectedLocalBal:   10_000,
			expectedRemoteBal:  15_000,
		},
		{
			name: "1 asset 2 channels 1 peer",
			activeChannels: []lndclient.ChannelInfo{
				createChannelWithCustomData(
					t, testAssetID1, 10_000, 15_000, proof1,
					peer1,
				),
				createChannelWithCustomData(
					t, testAssetID1, 10_000, 15_000, proof1,
					peer1,
				),
			},
			specifier: asset.NewSpecifierFromId(
				testAssetID1,
			),
			expectedValidPeers: 1,
			expectedLocalBal:   20_000,
			expectedRemoteBal:  30_000,
		},
		{
			name: "1 asset 2 channels 2 peers",
			activeChannels: []lndclient.ChannelInfo{
				createChannelWithCustomData(
					t, testAssetID1, 10_000, 15_000, proof1,
					peer1,
				),
				createChannelWithCustomData(
					t, testAssetID1, 10_000, 15_000, proof1,
					peer2,
				),
			},
			specifier: asset.NewSpecifierFromId(
				testAssetID1,
			),
			expectedValidPeers: 2,
			expectedLocalBal:   20_000,
			expectedRemoteBal:  30_000,
		},
		{
			name: "2 assets 2 channels 2 peers, asset specifier",
			activeChannels: []lndclient.ChannelInfo{
				createChannelWithCustomData(
					t, testAssetID1, 10_000, 15_000, proof1,
					peer1,
				),
				createChannelWithCustomData(
					t, testAssetID2, 10_000, 15_000, proof2,
					peer2,
				),
			},
			specifier: asset.NewSpecifierFromId(
				testAssetID1,
			),
			expectedValidPeers: 1,
			expectedLocalBal:   10_000,
			expectedRemoteBal:  15_000,
		},
		{
			name: "2 assets 2 channels 2 peers, group specifier",
			activeChannels: []lndclient.ChannelInfo{
				createChannelWithCustomData(
					t, testAssetID1, 10_000, 15_000, proof1,
					peer1,
				),
				createChannelWithCustomData(
					t, testAssetID2, 10_000, 15_000, proof2,
					peer2,
				),
			},
			specifier: asset.NewSpecifierFromGroupKey(
				*testGroupKey,
			),
			expectedValidPeers: 2,
			expectedLocalBal:   20_000,
			expectedRemoteBal:  30_000,
		},
		{
			name: "3 assets 3 channels 2 peers, group specifier",
			activeChannels: []lndclient.ChannelInfo{
				createChannelWithCustomData(
					t, testAssetID1, 10_000, 15_000, proof1,
					peer1,
				),
				createChannelWithCustomData(
					t, testAssetID2, 10_000, 15_000, proof2,
					peer2,
				),
				createChannelWithCustomData(
					t, testAssetID3, 10_000, 15_000, proof3,
					peer2,
				),
			},
			specifier: asset.NewSpecifierFromGroupKey(
				*testGroupKey,
			),
			expectedValidPeers: 2,
			expectedLocalBal:   20_000,
			expectedRemoteBal:  30_000,
		},
		{
			name: "3 assets 6 channels 2 peers, group specifier",
			activeChannels: []lndclient.ChannelInfo{
				createChannelWithCustomData(
					t, testAssetID1, 10_000, 15_000, proof1,
					peer1,
				),
				createChannelWithCustomData(
					t, testAssetID2, 10_000, 15_000, proof2,
					peer1,
				),
				createChannelWithCustomData(
					t, testAssetID3, 10_000, 15_000, proof3,
					peer1,
				),
				createChannelWithCustomData(
					t, testAssetID1, 10_000, 15_000, proof1,
					peer2,
				),
				createChannelWithCustomData(
					t, testAssetID2, 10_000, 15_000, proof2,
					peer2,
				),
				createChannelWithCustomData(
					t, testAssetID3, 10_000, 15_000, proof3,
					peer2,
				),
			},
			specifier: asset.NewSpecifierFromGroupKey(
				*testGroupKey,
			),
			expectedValidPeers: 2,
			expectedLocalBal:   40_000,
			expectedRemoteBal:  60_000,
		},
	}

	for idx := range testCases {
		tc := testCases[idx]

		success := t.Run(tc.name, func(t *testing.T) {
			assertComputeChannelAssetBalance(t, tc)
		})
		if !success {
			break
		}
	}
}

// pubKeyFromUint64 is a helper function that generates a public key from a
// uint64 value.
func pubKeyFromUint64(num uint64) *btcec.PublicKey {
	var (
		buf    = make([]byte, 8)
		scalar = new(secp256k1.ModNScalar)
	)
	binary.BigEndian.PutUint64(buf, num)
	_ = scalar.SetByteSlice(buf)
	return secp256k1.NewPrivateKey(scalar).PubKey()
}
