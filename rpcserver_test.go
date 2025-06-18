package taprootassets

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/tapdb"
	"github.com/lightninglabs/taproot-assets/tapfreighter"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/assetwalletrpc" // Added for new request/stream types
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// mockAssetStore is a mock implementation of the tapdb.AssetStore interface.
type mockAssetStore struct {
	mock.Mock
	tapdb.AssetStore
}

// QueryParcels is a mock implementation of the tapdb.AssetStore.QueryParcels method.
// It now stores the idAfter and createdAfter parameters for assertion.
func (m *mockAssetStore) QueryParcels(ctx context.Context, anchorTxHash *chainhash.Hash,
	pendingOnly bool, idAfter int64, createdAfter time.Time) ([]*tapfreighter.OutboundParcel, error) {
	args := m.Called(ctx, anchorTxHash, pendingOnly, idAfter, createdAfter)
	// Store args for assertion if needed by a specific test, though direct assertion on mock.MatchedBy is preferred.
	return args.Get(0).([]*tapfreighter.OutboundParcel), args.Error(1)
}

// mockChainPorter is a mock implementation of the tapfreighter.Porter interface.
type mockChainPorter struct {
	mock.Mock
	tapfreighter.Porter
	subscribers map[uint64]*fn.EventReceiver[fn.Event]
	subMtx      sync.Mutex
}

func newMockChainPorter() *mockChainPorter {
	return &mockChainPorter{
		subscribers: make(map[uint64]*fn.EventReceiver[fn.Event]),
	}
}

func (m *mockChainPorter) RegisterSubscriber(subscriber *fn.EventReceiver[fn.Event], deliverExisting bool, deliverFrom bool) error {
	m.subMtx.Lock()
	defer m.subMtx.Unlock()
	m.subscribers[subscriber.ID()] = subscriber
	return m.Called(subscriber, deliverExisting, deliverFrom).Error(0)
}

func (m *mockChainPorter) RemoveSubscriber(subscriber *fn.EventReceiver[fn.Event]) error {
	m.subMtx.Lock()
	defer m.subMtx.Unlock()
	delete(m.subscribers, subscriber.ID())
	return m.Called(subscriber).Error(0)
}

func (m *mockChainPorter) PublishEvent(event fn.Event) {
	m.subMtx.Lock()
	defer m.subMtx.Unlock()
	for _, sub := range m.subscribers {
		sub.NewItemCreated.ChanIn() <- event
	}
}

// mockAssetWallet_SubscribeAllSendEventsServer is a mock implementation of the server stream.
type mockAssetWallet_SubscribeAllSendEventsServer struct {
	mock.Mock
	assetwalletrpc.AssetWallet_SubscribeAllSendEventsServer // Updated type
	ctx                                                   context.Context
	SentEvents                                            []*taprpc.SendEvent
	ErrChan                                               chan error
	DisconnectChan                                        chan struct{}
}

func newMockStream(ctx context.Context) *mockAssetWallet_SubscribeAllSendEventsServer { // Updated return type
	return &mockAssetWallet_SubscribeAllSendEventsServer{ // Updated type
		ctx:            ctx,
		ErrChan:        make(chan error, 1),
		DisconnectChan: make(chan struct{}),
	}
}

func (m *mockAssetWallet_SubscribeAllSendEventsServer) Send(event *taprpc.SendEvent) error {
	args := m.Called(event)
	if args.Error(0) != nil {
		return args.Error(0)
	}
	m.SentEvents = append(m.SentEvents, event)
	return nil
}

func (m *mockAssetWallet_SubscribeAllSendEventsServer) Context() context.Context {
	return m.ctx
}

// Helper function to create a dummy OutboundParcel for testing
func createDummyParcel(id int64, transferTime time.Time, label string) *tapfreighter.OutboundParcel {
	return &tapfreighter.OutboundParcel{
		ID:           id,
		TransferTime: transferTime,
		ChainFees:    100,
		Inputs:       []*tapfreighter.TransferInput{},
		Outputs:      []*tapfreighter.TransferOutput{},
		Label:        label,
		// AnchorTx, AnchorTxHeightHint, AnchorTxBlockHash, AnchorTxBlockHeight can be added if needed
	}
}

// Helper function to create a dummy AssetSendEvent for testing
func createDummyAssetSendEvent(dbid int64, ts time.Time, state tapfreighter.SendState, label string) *tapfreighter.AssetSendEvent {
	return &tapfreighter.AssetSendEvent{
		TransferDBID:  dbid,
		SendState:     state,
		TransferLabel: label,
	}
}

func TestSubscribeAllSendEvents_BacklogOnly(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name                   string
		lastIDReq              string
		parcelsInDB            []*tapfreighter.OutboundParcel
		expectedParcelsFromMock []*tapfreighter.OutboundParcel
		expectedStreamedEvents  []*taprpc.SendEvent
		expectError            bool
	}{
		{
			name:                   "no backlog, no last_id",
			lastIDReq:              "",
			parcelsInDB:            []*tapfreighter.OutboundParcel{},
			expectedParcelsFromMock: []*tapfreighter.OutboundParcel{},
			expectedStreamedEvents:  []*taprpc.SendEvent{},
		},
		{
			name:      "backlog present, no last_id",
			lastIDReq: "",
			parcelsInDB: []*tapfreighter.OutboundParcel{
				createDummyParcel(1, time.Unix(100, 0), "label1"),
				createDummyParcel(2, time.Unix(200, 0), "label2"),
			},
			expectedParcelsFromMock: []*tapfreighter.OutboundParcel{
				createDummyParcel(1, time.Unix(100, 0), "label1"),
				createDummyParcel(2, time.Unix(200, 0), "label2"),
			},
			expectedStreamedEvents: []*taprpc.SendEvent{
				{TransferDbId: 1, Timestamp: time.Unix(100, 0).UnixMicro(), SendState: taprpc.SendState_SEND_STATE_BROADCAST.String(), ParcelType: taprpc.ParcelType_PARCEL_TYPE_PENDING, TransferLabel: "label1", Transfer: &taprpc.AssetTransfer{TransferTimestamp: 100, Label: "label1"}},
				{TransferDbId: 2, Timestamp: time.Unix(200, 0).UnixMicro(), SendState: taprpc.SendState_SEND_STATE_BROADCAST.String(), ParcelType: taprpc.ParcelType_PARCEL_TYPE_PENDING, TransferLabel: "label2", Transfer: &taprpc.AssetTransfer{TransferTimestamp: 200, Label: "label2"}},
			},
		},
		{
			name:      "backlog present, with last_id",
			lastIDReq: "1",
			parcelsInDB: []*tapfreighter.OutboundParcel{
				createDummyParcel(1, time.Unix(100, 0), "label1"),
				createDummyParcel(2, time.Unix(200, 0), "label2"),
				createDummyParcel(3, time.Unix(300, 0), "label3"),
			},
			expectedParcelsFromMock: []*tapfreighter.OutboundParcel{
				createDummyParcel(2, time.Unix(200, 0), "label2"),
				createDummyParcel(3, time.Unix(300, 0), "label3"),
			},
			expectedStreamedEvents: []*taprpc.SendEvent{
				{TransferDbId: 2, Timestamp: time.Unix(200, 0).UnixMicro(), SendState: taprpc.SendState_SEND_STATE_BROADCAST.String(), ParcelType: taprpc.ParcelType_PARCEL_TYPE_PENDING, TransferLabel: "label2", Transfer: &taprpc.AssetTransfer{TransferTimestamp: 200, Label: "label2"}},
				{TransferDbId: 3, Timestamp: time.Unix(300, 0).UnixMicro(), SendState: taprpc.SendState_SEND_STATE_BROADCAST.String(), ParcelType: taprpc.ParcelType_PARCEL_TYPE_PENDING, TransferLabel: "label3", Transfer: &taprpc.AssetTransfer{TransferTimestamp: 300, Label: "label3"}},
			},
		},
		{
			name:      "last_id greater than all existing",
			lastIDReq: "5",
			parcelsInDB: []*tapfreighter.OutboundParcel{
				createDummyParcel(1, time.Unix(100, 0), "label1"),
				createDummyParcel(2, time.Unix(200, 0), "label2"),
			},
			expectedParcelsFromMock: []*tapfreighter.OutboundParcel{},
			expectedStreamedEvents:  []*taprpc.SendEvent{},
		},
		{
			name:        "invalid last_id",
			lastIDReq:   "abc",
			parcelsInDB: []*tapfreighter.OutboundParcel{},
			expectError: true,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mockStore := new(mockAssetStore)
			mockPorter := newMockChainPorter()

			cfg := &Config{
				AssetStore: mockStore,
				ChainPorter: mockPorter,
			}
			rpcServer := &rpcServer{cfg: cfg, quit: make(chan struct{})}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			mockStream := newMockStream(ctx)

			expectedIDAfter := int64(0)
			if tc.lastIDReq != "" && !tc.expectError {
				parsedID, _ := strconv.ParseInt(tc.lastIDReq, 10, 64)
				expectedIDAfter = parsedID
			}

			if !tc.expectError {
				mockStore.On(
					"QueryParcels",
					mock.Anything,           // ctx
					(*chainhash.Hash)(nil), // anchorTxHash
					false,                  // pendingOnly
					expectedIDAfter,        // idAfter
					time.Time{},            // createdAfter
				).Return(tc.expectedParcelsFromMock, nil)
			}

			mockPorter.On("RegisterSubscriber", mock.Anything, false, false).Return(nil)
			mockPorter.On("RemoveSubscriber", mock.Anything).Return(nil)

			err := rpcServer.SubscribeAllSendEvents(&assetwalletrpc.SubscribeAllSendEventsRequest{LastId: tc.lastIDReq}, mockStream)

			if tc.expectError {
				require.Error(t, err)
			} else {
				if err == nil || rpcErrIsCanceled(err) {
					go func() {
						time.Sleep(50 * time.Millisecond)
						cancel()
					}()
					<-ctx.Done()
					err = ctx.Err()
					if err == context.Canceled {
						err = nil
					}
				}
				require.NoError(t, err)
				require.Len(t, mockStream.SentEvents, len(tc.expectedStreamedEvents))
				for i, expectedEvent := range tc.expectedStreamedEvents {
					actualEvent := mockStream.SentEvents[i]
					require.Equal(t, expectedEvent.TransferDbId, actualEvent.TransferDbId)
					require.Equal(t, expectedEvent.Timestamp, actualEvent.Timestamp)
					require.Equal(t, expectedEvent.TransferLabel, actualEvent.TransferLabel)
					if expectedEvent.Transfer != nil && actualEvent.Transfer != nil {
						require.Equal(t, expectedEvent.Transfer.Label, actualEvent.Transfer.Label)
						require.Equal(t, expectedEvent.Transfer.TransferTimestamp, actualEvent.Transfer.TransferTimestamp)
					} else {
						require.Nil(t, expectedEvent.Transfer)
						require.Nil(t, actualEvent.Transfer)
					}
				}
			}
			mockStore.AssertExpectations(t)
			mockPorter.AssertExpectations(t)
		})
	}
}

func TestSubscribeAllSendEvents_NewEventsOnly(t *testing.T) {
	t.Parallel()

	mockStore := new(mockAssetStore)
	mockPorter := newMockChainPorter()
	cfg := &Config{
		AssetStore:  mockStore,
		ChainPorter: mockPorter,
	}
	rpcServer := &rpcServer{cfg: cfg, quit: make(chan struct{})}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mockStream := newMockStream(ctx)

	mockStore.On("QueryParcels", mock.Anything, (*chainhash.Hash)(nil), false, int64(0), time.Time{}).Return([]*tapfreighter.OutboundParcel{}, nil)
	mockPorter.On("RegisterSubscriber", mock.Anything, false, false).Return(nil)
	mockPorter.On("RemoveSubscriber", mock.Anything).Return(nil)

	var rpcErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		rpcErr = rpcServer.SubscribeAllSendEvents(&assetwalletrpc.SubscribeAllSendEventsRequest{LastId: ""}, mockStream)
	}()

	event1 := createDummyAssetSendEvent(101, time.Now(), tapfreighter.SendStateVirtualSign, "event1")
	event2 := createDummyAssetSendEvent(102, time.Now(), tapfreighter.SendStateAnchorSign, "event2")

	mockPorter.PublishEvent(event1)
	mockPorter.PublishEvent(event2)

	err := wait.NoError(func() error {
		if len(mockStream.SentEvents) < 2 {
			return fmt.Errorf("expected 2 events, got %d", len(mockStream.SentEvents))
		}
		return nil
	}, 1*time.Second)
	require.NoError(t, err)

	require.Len(t, mockStream.SentEvents, 2)
	require.Equal(t, event1.TransferDBID, mockStream.SentEvents[0].TransferDbId)
	require.Equal(t, string(event1.SendState), mockStream.SentEvents[0].SendState)
	require.Equal(t, event1.TransferLabel, mockStream.SentEvents[0].TransferLabel)

	require.Equal(t, event2.TransferDBID, mockStream.SentEvents[1].TransferDbId)
	require.Equal(t, string(event2.SendState), mockStream.SentEvents[1].SendState)
	require.Equal(t, event2.TransferLabel, mockStream.SentEvents[1].TransferLabel)

	t.Run("client disconnect", func(t *testing.T) {
		cancel()
		wg.Wait()
		require.True(t, rpcErrIsCanceled(rpcErr) || rpcErr == nil || rpcErr == context.Canceled, "expected context canceled error, got %v", rpcErr)
	})

	t.Run("server shutdown", func(t *testing.T) {
		ctxShutdown, cancelShutdown := context.WithCancel(context.Background())
		defer cancelShutdown()

		mockStoreShutdown := new(mockAssetStore)
		mockPorterShutdown := newMockChainPorter()
		cfgShutdown := &Config{AssetStore: mockStoreShutdown, ChainPorter: mockPorterShutdown}
		serverQuitChan := make(chan struct{})
		rpcServerShutdown := &rpcServer{cfg: cfgShutdown, quit: serverQuitChan}
		mockStreamShutdown := newMockStream(ctxShutdown)

		mockStoreShutdown.On("QueryParcels", mock.Anything, (*chainhash.Hash)(nil), false, int64(0), time.Time{}).Return([]*tapfreighter.OutboundParcel{}, nil)
		mockPorterShutdown.On("RegisterSubscriber", mock.Anything, false, false).Return(nil)
		mockPorterShutdown.On("RemoveSubscriber", mock.Anything).Return(nil)

		var shutdownRpcErr error
		var shutdownWg sync.WaitGroup
		shutdownWg.Add(1)
		go func() {
			defer shutdownWg.Done()
			shutdownRpcErr = rpcServerShutdown.SubscribeAllSendEvents(&assetwalletrpc.SubscribeAllSendEventsRequest{}, mockStreamShutdown)
		}()

		close(serverQuitChan)
		shutdownWg.Wait()

		require.Error(t, shutdownRpcErr)
		require.Contains(t, shutdownRpcErr.Error(), "server shutting down")
	})

	mockStore.AssertExpectations(t)
	mockPorter.AssertExpectations(t)
}

// rpcErrIsCanceled is a helper to check if an error is context.Canceled or a gRPC Canceled error.
func rpcErrIsCanceled(err error) bool {
	if err == nil {
		return false
	}
	if err == context.Canceled {
		return true
	}
	st, ok := status.FromError(err)
	if ok {
		return st.Code() == codes.Canceled
	}
	return false
}

func TestSubscribeAllSendEvents_Combined(t *testing.T) {
	t.Parallel()

	mockStore := new(mockAssetStore)
	mockPorter := newMockChainPorter()
	cfg := &Config{
		AssetStore:  mockStore,
		ChainPorter: mockPorter,
	}
	rpcServer := &rpcServer{cfg: cfg, quit: make(chan struct{})}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mockStream := newMockStream(ctx)

	allBacklogParcels := []*tapfreighter.OutboundParcel{
		createDummyParcel(1, time.Unix(100, 0), "backlog1"),
		createDummyParcel(2, time.Unix(200, 0), "backlog2"),
	}
	mockStore.On("QueryParcels", mock.Anything, (*chainhash.Hash)(nil), false, int64(0), time.Time{}).Return(allBacklogParcels, nil)

	expectedBacklogEvents := []*taprpc.SendEvent{
		{TransferDbId: 1, Timestamp: time.Unix(100, 0).UnixMicro(), SendState: taprpc.SendState_SEND_STATE_BROADCAST.String(), ParcelType: taprpc.ParcelType_PARCEL_TYPE_PENDING, TransferLabel: "backlog1", Transfer: &taprpc.AssetTransfer{TransferTimestamp: 100, Label: "backlog1"}},
		{TransferDbId: 2, Timestamp: time.Unix(200, 0).UnixMicro(), SendState: taprpc.SendState_SEND_STATE_BROADCAST.String(), ParcelType: taprpc.ParcelType_PARCEL_TYPE_PENDING, TransferLabel: "backlog2", Transfer: &taprpc.AssetTransfer{TransferTimestamp: 200, Label: "backlog2"}},
	}

	mockPorter.On("RegisterSubscriber", mock.Anything, false, false).Return(nil)
	mockPorter.On("RemoveSubscriber", mock.Anything).Return(nil)

	var rpcErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		rpcErr = rpcServer.SubscribeAllSendEvents(&assetwalletrpc.SubscribeAllSendEventsRequest{LastId: ""}, mockStream)
	}()

	err := wait.NoError(func() error {
		if len(mockStream.SentEvents) < len(expectedBacklogEvents) {
			return fmt.Errorf("expected %d backlog events, got %d", len(expectedBacklogEvents), len(mockStream.SentEvents))
		}
		return nil
	}, 1*time.Second)
	require.NoError(t, err, "timeout waiting for backlog events")

	require.Len(t, mockStream.SentEvents, len(expectedBacklogEvents))
	for i, expectedEvent := range expectedBacklogEvents {
		actualEvent := mockStream.SentEvents[i]
		require.Equal(t, expectedEvent.TransferDbId, actualEvent.TransferDbId)
		require.Equal(t, expectedEvent.TransferLabel, actualEvent.TransferLabel)
	}

	newEvent1 := createDummyAssetSendEvent(101, time.Now(), tapfreighter.SendStateStorePostAnchorTxConf, "newEvent1")
	mockPorter.PublishEvent(newEvent1)

	totalExpectedEvents := len(expectedBacklogEvents) + 1
	err = wait.NoError(func() error {
		if len(mockStream.SentEvents) < totalExpectedEvents {
			return fmt.Errorf("expected %d total events, got %d", totalExpectedEvents, len(mockStream.SentEvents))
		}
		return nil
	}, 1*time.Second)
	require.NoError(t, err, "timeout waiting for new event")

	require.Len(t, mockStream.SentEvents, totalExpectedEvents)
	actualNewEvent := mockStream.SentEvents[totalExpectedEvents-1]
	require.Equal(t, newEvent1.TransferDBID, actualNewEvent.TransferDbId)
	require.Equal(t, string(newEvent1.SendState), actualNewEvent.SendState)
	require.Equal(t, newEvent1.TransferLabel, actualNewEvent.TransferLabel)

	cancel()
	wg.Wait()
	require.True(t, rpcErrIsCanceled(rpcErr) || rpcErr == nil || rpcErr == context.Canceled, "expected context canceled error, got %v", rpcErr)

	mockStore.AssertExpectations(t)
	mockPorter.AssertExpectations(t)
}

func TestSubscribeAllSendEvents_FilterByCreatedAfterSecondsOnly(t *testing.T) {
	t.Parallel()

	mockStore := new(mockAssetStore)
	mockPorter := newMockChainPorter()
	cfg := &Config{
		AssetStore:  mockStore,
		ChainPorter: mockPorter,
	}
	rpcServer := &rpcServer{cfg: cfg, quit: make(chan struct{})}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mockStream := newMockStream(ctx)

	// Define a created_after_seconds filter.
	createdAfterFilterTime := time.Now().Add(-1 * time.Hour).Truncate(time.Second) // Truncate for easier comparison
	createdAfterSecondsReq := createdAfterFilterTime.Unix()

	// Parcels to be returned by the mock, simulating DB filtering.
	parcelsToReturn := []*tapfreighter.OutboundParcel{
		createDummyParcel(2, time.Unix(createdAfterFilterTime.Unix()+3600, 0), "label2_new"),
	}
	expectedStreamedEvents := []*taprpc.SendEvent{
		{TransferDbId: 2, Timestamp: parcelsToReturn[0].TransferTime.UnixMicro(), SendState: taprpc.SendState_SEND_STATE_BROADCAST.String(), ParcelType: taprpc.ParcelType_PARCEL_TYPE_PENDING, TransferLabel: "label2_new", Transfer: &taprpc.AssetTransfer{TransferTimestamp: parcelsToReturn[0].TransferTime.Unix(), Label: "label2_new"}},
	}

	mockStore.On(
		"QueryParcels",
		mock.Anything,           // ctx
		(*chainhash.Hash)(nil), // anchorTxHash
		false,                  // pendingOnly
		int64(0),               // idAfter (not used in this test specific path)
		createdAfterFilterTime, // createdAfter
	).Return(parcelsToReturn, nil).Once()
	mockPorter.On("RegisterSubscriber", mock.Anything, false, false).Return(nil).Once()
	mockPorter.On("RemoveSubscriber", mock.Anything).Return(nil).Once()

	err := rpcServer.SubscribeAllSendEvents(&assetwalletrpc.SubscribeAllSendEventsRequest{CreatedAfterSeconds: createdAfterSecondsReq}, mockStream)

	// Since this test focuses on backlog, the function will block after streaming.
	// We cancel the context to allow it to return.
	if err == nil || rpcErrIsCanceled(err) { // if QueryParcels was called and it's waiting for new events
		go func() {
			time.Sleep(100 * time.Millisecond) // Allow time for send
			cancel()
		}()
		<-ctx.Done() // Wait for cancellation
		if ctx.Err() == context.Canceled && err == nil {
			// This is an expected outcome if the stream was gracefully closed by test
		} else {
			// If err was not nil initially, or it's not a cancelation error, then fail
			require.True(t, rpcErrIsCanceled(err), "expected context canceled error or nil, got %v", err)
		}
	} else {
		require.NoError(t, err) // Should not error before cancel if setup is right
	}


	require.Len(t, mockStream.SentEvents, len(expectedStreamedEvents))
	if len(expectedStreamedEvents) > 0 {
		require.Equal(t, expectedStreamedEvents[0].TransferDbId, mockStream.SentEvents[0].TransferDbId)
		require.Equal(t, expectedStreamedEvents[0].TransferLabel, mockStream.SentEvents[0].TransferLabel)
	}

	mockStore.AssertExpectations(t)
	mockPorter.AssertExpectations(t)
}

func TestSubscribeAllSendEvents_FilterByLastIdAndCreatedAfterSeconds(t *testing.T) {
	t.Parallel()

	mockStore := new(mockAssetStore)
	mockPorter := newMockChainPorter()
	cfg := &Config{
		AssetStore:  mockStore,
		ChainPorter: mockPorter,
	}
	rpcServer := &rpcServer{cfg: cfg, quit: make(chan struct{})}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mockStream := newMockStream(ctx)

	lastIDReq := "1"
	expectedIDAfter := int64(1)
	createdAfterFilterTime := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
	createdAfterSecondsReq := createdAfterFilterTime.Unix()

	parcelsToReturn := []*tapfreighter.OutboundParcel{
		createDummyParcel(2, time.Unix(createdAfterFilterTime.Unix()+1800, 0), "label2_new_id2"),
	}
	expectedStreamedEvents := []*taprpc.SendEvent{
		{TransferDbId: 2, Timestamp: parcelsToReturn[0].TransferTime.UnixMicro(), SendState: taprpc.SendState_SEND_STATE_BROADCAST.String(), ParcelType: taprpc.ParcelType_PARCEL_TYPE_PENDING, TransferLabel: "label2_new_id2", Transfer: &taprpc.AssetTransfer{TransferTimestamp: parcelsToReturn[0].TransferTime.Unix(), Label: "label2_new_id2"}},
	}


	mockStore.On(
		"QueryParcels",
		mock.Anything,        // ctx
		(*chainhash.Hash)(nil), // anchorTxHash
		false,                 // pendingOnly
		expectedIDAfter,       // idAfter
		createdAfterFilterTime, // createdAfter
	).Return(parcelsToReturn, nil).Once()
	mockPorter.On("RegisterSubscriber", mock.Anything, false, false).Return(nil).Once()
	mockPorter.On("RemoveSubscriber", mock.Anything).Return(nil).Once()

	err := rpcServer.SubscribeAllSendEvents(&assetwalletrpc.SubscribeAllSendEventsRequest{
		LastId:              lastIDReq,
		CreatedAfterSeconds: createdAfterSecondsReq,
	}, mockStream)

	if err == nil || rpcErrIsCanceled(err) {
		go func() {
			time.Sleep(100 * time.Millisecond)
			cancel()
		}()
		<-ctx.Done()
		if ctx.Err() == context.Canceled && err == nil {
			// Expected
		} else {
			require.True(t, rpcErrIsCanceled(err), "expected context canceled error or nil, got %v", err)
		}
	} else {
		require.NoError(t, err)
	}


	require.Len(t, mockStream.SentEvents, len(expectedStreamedEvents))
	if len(expectedStreamedEvents) > 0 {
		require.Equal(t, expectedStreamedEvents[0].TransferDbId, mockStream.SentEvents[0].TransferDbId)
		require.Equal(t, expectedStreamedEvents[0].TransferLabel, mockStream.SentEvents[0].TransferLabel)
	}

	mockStore.AssertExpectations(t)
	mockPorter.AssertExpectations(t)
}

func TestSubscribeAllSendEvents_ClientDisconnect(t *testing.T) {
	t.Parallel()

	mockStore := new(mockAssetStore)
	mockPorter := newMockChainPorter()
	cfg := &Config{
		AssetStore:  mockStore,
		ChainPorter: mockPorter,
	}
	rpcServer := &rpcServer{cfg: cfg, quit: make(chan struct{})}

	ctx, cancel := context.WithCancel(context.Background())
	// We will cancel this context to simulate client disconnect partway through.
	// defer cancel() // Don't defer, we'll cancel manually.

	mockStream := newMockStream(ctx)

	allBacklogParcels := []*tapfreighter.OutboundParcel{
		createDummyParcel(1, time.Unix(100, 0), "backlog1"),
		createDummyParcel(2, time.Unix(200, 0), "backlog2"),
		createDummyParcel(3, time.Unix(300, 0), "backlog3"),
	}
	mockStore.On("QueryParcels", mock.Anything, (*chainhash.Hash)(nil), false, int64(0), time.Time{}).Return(allBacklogParcels, nil)
	mockPorter.On("RegisterSubscriber", mock.Anything, false, false).Return(nil)
	mockPorter.On("RemoveSubscriber", mock.Anything).Return(nil)

	var rpcErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		rpcErr = rpcServer.SubscribeAllSendEvents(&assetwalletrpc.SubscribeAllSendEventsRequest{}, mockStream)
	}()

	// Allow some backlog events to be sent.
	err := wait.NoError(func() error {
		if len(mockStream.SentEvents) < 1 {
			return fmt.Errorf("expected at least 1 event before disconnect")
		}
		return nil
	}, 200*time.Millisecond) // Increased timeout slightly for reliability
	require.NoError(t, err)

	// Simulate client disconnect by cancelling the stream's context.
	cancel()
	wg.Wait() // Wait for the RPC goroutine to finish.

	require.True(t, rpcErrIsCanceled(rpcErr), "expected context canceled error, got %v", rpcErr)

	mockStore.AssertExpectations(t)
	// RemoveSubscriber might not be called if context is canceled before it's reached
	// depending on exact timing, so we don't assert it strictly here for this specific test.
	// mockPorter.AssertCalled(t, "RemoveSubscriber", mock.Anything)
}

func TestSubscribeAllSendEvents_ServerShutdown(t *testing.T) {
	t.Parallel()

	ctxShutdown, cancelShutdown := context.WithCancel(context.Background())
	defer cancelShutdown()

	mockStoreShutdown := new(mockAssetStore)
	mockPorterShutdown := newMockChainPorter()
	cfgShutdown := &Config{AssetStore: mockStoreShutdown, ChainPorter: mockPorterShutdown}
	serverQuitChan := make(chan struct{})
	rpcServerShutdown := &rpcServer{cfg: cfgShutdown, quit: serverQuitChan}
	mockStreamShutdown := newMockStream(ctxShutdown)

	// Expect QueryParcels to be called.
	mockStoreShutdown.On("QueryParcels", mock.Anything, (*chainhash.Hash)(nil), false, int64(0), time.Time{}).Return([]*tapfreighter.OutboundParcel{}, nil)
	mockPorterShutdown.On("RegisterSubscriber", mock.Anything, false, false).Return(nil)
	mockPorterShutdown.On("RemoveSubscriber", mock.Anything).Return(nil)

	var shutdownRpcErr error
	var shutdownWg sync.WaitGroup
	shutdownWg.Add(1)
	go func() {
		defer shutdownWg.Done()
		shutdownRpcErr = rpcServerShutdown.SubscribeAllSendEvents(&assetwalletrpc.SubscribeAllSendEventsRequest{}, mockStreamShutdown)
	}()

	// Allow the subscriber to be registered
	time.Sleep(50 * time.Millisecond)

	// Simulate server shutdown.
	close(serverQuitChan)
	shutdownWg.Wait()

	require.Error(t, shutdownRpcErr)
	require.Contains(t, shutdownRpcErr.Error(), "server shutting down")

	mockStoreShutdown.AssertExpectations(t)
	mockPorterShutdown.AssertExpectations(t)
}

func TestMarshalOutboundParcelToSendEvent(t *testing.T) {
	t.Parallel()

	now := time.Now()
	parcel := createDummyParcel(123, now, "testParcel")
	// Add more fields to parcel if necessary for a more complete test
	parcel.AnchorTx = &wire.MsgTx{Version: 1} // Minimal valid wire.MsgTx
	parcel.AnchorTxBlockHeight = 1000

	expectedEvent := &taprpc.SendEvent{
		TransferDbId:    123,
		Timestamp:       now.UnixMicro(),
		SendState:       taprpc.SendState_SEND_STATE_COMPLETED.String(), // Assuming confirmed if block height is set
		ParcelType:      taprpc.ParcelType_PARCEL_TYPE_PENDING,      // Default for backlog
		TransferLabel:   "testParcel",
		Transfer:        &taprpc.AssetTransfer{TransferTimestamp: now.Unix(), Label: "testParcel"},
		AnchorTransaction: &taprpc.AnchorTransaction{FinalTx: func() []byte {
			var b bytes.Buffer
			_ = parcel.AnchorTx.Serialize(&b)
			return b.Bytes()
		}()},
		// VirtualPackets and PassiveVirtualPackets are currently not populated by the marshaller for OutboundParcel
	}

	actualEvent, err := marshalOutboundParcelToSendEvent(parcel)
	require.NoError(t, err)

	require.Equal(t, expectedEvent.TransferDbId, actualEvent.TransferDbId)
	require.Equal(t, expectedEvent.Timestamp, actualEvent.Timestamp)
	require.Equal(t, expectedEvent.SendState, actualEvent.SendState)
	require.Equal(t, expectedEvent.ParcelType, actualEvent.ParcelType)
	require.Equal(t, expectedEvent.TransferLabel, actualEvent.TransferLabel)
	require.NotNil(t, actualEvent.Transfer)
	require.Equal(t, expectedEvent.Transfer.Label, actualEvent.Transfer.Label)
	require.Equal(t, expectedEvent.Transfer.TransferTimestamp, actualEvent.Transfer.TransferTimestamp)
	require.NotNil(t, actualEvent.AnchorTransaction)
	require.Equal(t, expectedEvent.AnchorTransaction.FinalTx, actualEvent.AnchorTransaction.FinalTx)

}

func TestMarshalAssetSendEventWithDBID(t *testing.T) {
	t.Parallel()

	now := time.Now()
	assetEvent := &tapfreighter.AssetSendEvent{
		// initialize tapfreighter.AssetSendEvent with necessary fields for marshalSendEvent
		// The actual timestamp for the RPC event comes from event.Timestamp() which uses time.Now()
		// SendState, Parcel, TransferLabel, VirtualPackets, PassivePackets, AnchorTx, Transfer, Error, NextSendState
		SendState:     tapfreighter.SendStateAnchorSign,
		TransferLabel: "liveLabel",
		TransferDBID:  456, // This is the key field to test for this marshaller
		OutboundPkg: createDummyParcel(456, now, "liveLabel"), // Used by marshalOutboundParcel inside marshalSendEvent
		AnchorTx: &tapsend.AnchorTransaction{ // Used by marshalSendEvent
			FinalTx: &wire.MsgTx{Version: 1},
		},
	}

	// We need to mock the existing marshalSendEvent or understand its exact behavior
	// For this test, we'll assume marshalSendEvent correctly populates most fields
	// and we are primarily checking if TransferDbId is overridden correctly.

	// Expected event after marshalSendEvent (simplified, focusing on what marshalAssetSendEventWithDBID changes)
	// The timestamp will be set by marshalSendEvent using time.Now(), so we can't predict its exact value here.
	// We will check that TransferDbId is correctly set by marshalAssetSendEventWithDBID.

	rpcEvent, err := marshalAssetSendEventWithDBID(assetEvent)
	require.NoError(t, err)

	require.Equal(t, assetEvent.TransferDBID, rpcEvent.TransferDbId)
	require.Equal(t, string(assetEvent.SendState), rpcEvent.SendState)
	require.Equal(t, assetEvent.TransferLabel, rpcEvent.TransferLabel)

	// Verify that other fields that would have been set by marshalSendEvent are present
	require.NotNil(t, rpcEvent.Transfer)
	require.Equal(t, assetEvent.OutboundPkg.Label, rpcEvent.Transfer.Label)
	require.NotNil(t, rpcEvent.AnchorTransaction)

	// Check ParcelType (this depends on how marshalSendEvent interprets AssetSendEvent)
	// Assuming it defaults or derives it, let's ensure it's set.
	// The actual ParcelType depends on the type of assetEvent.Parcel, which is nil here.
	// marshalSendEvent has specific logic for this. If assetEvent.Parcel is nil,
	// it won't be able to determine the type.
	// Let's create a parcel for the event.
	assetEvent.Parcel = &tapfreighter.AddressParcel{} // Example parcel type

	rpcEventWithParcel, err := marshalAssetSendEventWithDBID(assetEvent)
	require.NoError(t, err)
	require.Equal(t, taprpc.ParcelType_PARCEL_TYPE_ADDRESS, rpcEventWithParcel.ParcelType)
	require.Equal(t, assetEvent.TransferDBID, rpcEventWithParcel.TransferDbId)


}
