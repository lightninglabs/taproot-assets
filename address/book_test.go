package address

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestBook_NewAddress tests that we can create a new address with the
// `NewAddress` method of the Book type, while mocking the necessary
// dependencies.
func TestBook_NewAddress(t *testing.T) {
	mockStorage := &MockStorage{}
	mockSyncer := &MockAssetSyncer{}
	mockKeyRing := &MockKeyRing{}

	book := NewBook(BookConfig{
		Store:        mockStorage,
		Syncer:       mockSyncer,
		KeyRing:      mockKeyRing,
		Chain:        TestNet3Tap,
		StoreTimeout: time.Second,
	})

	ctx := context.Background()
	assetID := asset.RandID(t)
	specifier := asset.NewSpecifierFromId(assetID)
	amount := uint64(100)
	proofCourierAddr := url.URL{}

	mockKeyRing.On("DeriveNextTaprootAssetKey", ctx).
		Return(keychain.KeyDescriptor{
			PubKey: test.RandPubKey(t),
		}, nil).
		Twice()
	mockStorage.On("QueryAssetGroup", ctx, assetID).
		Return(&asset.AssetGroup{
			Genesis: &asset.Genesis{
				Tag:          "tag",
				FirstPrevOut: test.RandOp(t),
			},
		}, nil)
	mockStorage.On("InsertInternalKey", ctx, mock.Anything).
		Return(nil)
	mockStorage.On("InsertScriptKey", ctx, mock.Anything, mock.Anything).
		Return(nil)
	mockStorage.On("InsertAddrs", ctx, mock.Anything).
		Return(nil)

	addr, err := book.NewAddress(
		ctx, V0, specifier, amount, nil, proofCourierAddr,
	)
	require.NoError(t, err)
	require.NotNil(t, addr)

	mockStorage.AssertExpectations(t)
	mockKeyRing.AssertExpectations(t)
	mockSyncer.AssertExpectations(t)
}

// TestBook_QueryAssetInfo tests that we can query asset info, while mocking the
// necessary dependencies.
func TestBook_QueryAssetInfo(t *testing.T) {
	ctx := context.Background()
	assetID := asset.RandID(t)
	groupKey, _ := btcec.NewPrivateKey()
	groupPub := groupKey.PubKey()
	groupKey2, _ := btcec.NewPrivateKey()
	groupPub2 := groupKey2.PubKey()

	assetGroup := &asset.AssetGroup{
		Genesis: &asset.Genesis{
			Tag: "tag",
		},
		GroupKey: &asset.GroupKey{
			GroupPubKey: *groupPub,
		},
	}

	tests := []struct {
		name         string
		specifier    asset.Specifier
		setupMocks   func(*MockStorage, *MockAssetSyncer)
		expectsError bool
	}{{
		name:      "asset found by ID",
		specifier: asset.NewSpecifierFromId(assetID),
		setupMocks: func(ms *MockStorage, msync *MockAssetSyncer) {
			ms.On("QueryAssetGroup", ctx, assetID).
				Return(assetGroup, nil).
				Once()
		},
		expectsError: false,
	}, {
		name:      "asset found by group key",
		specifier: asset.NewSpecifierFromGroupKey(*groupPub2),
		setupMocks: func(ms *MockStorage, msync *MockAssetSyncer) {
			ms.On("QueryAssetGroupByGroupKey", ctx, groupPub2).
				Return(assetGroup, nil).
				Once()
		},
		expectsError: false,
	}, {
		name:      "asset not found, syncer returns error",
		specifier: asset.NewSpecifierFromId(assetID),
		setupMocks: func(ms *MockStorage, msync *MockAssetSyncer) {
			errUnknown := ErrAssetGroupUnknown
			ms.On("QueryAssetGroup", ctx, assetID).
				Return((*asset.AssetGroup)(nil), errUnknown).
				Once()
			msync.On("SyncAssetInfo", ctx, mock.Anything).
				Return(errUnknown).
				Once()
		},
		expectsError: true,
	}, {
		name: "asset not found, syncer succeeds and asset found " +
			"after sync",
		specifier: asset.NewSpecifierFromId(assetID),
		setupMocks: func(ms *MockStorage, msync *MockAssetSyncer) {
			errUnknown := ErrAssetGroupUnknown
			ms.On("QueryAssetGroup", ctx, assetID).
				Return((*asset.AssetGroup)(nil), errUnknown).
				Once()
			msync.On("SyncAssetInfo", ctx, mock.Anything).
				Return(nil).
				Once()
			ms.On("QueryAssetGroup", ctx, assetID).
				Return(assetGroup, nil).
				Once()
			msync.On("EnableAssetSync", ctx, assetGroup).
				Return(nil).
				Once()
		},
		expectsError: false,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockStorage := &MockStorage{}
			mockSyncer := &MockAssetSyncer{}
			book := NewBook(BookConfig{
				Store:        mockStorage,
				Syncer:       mockSyncer,
				KeyRing:      &MockKeyRing{},
				Chain:        ChainParams{},
				StoreTimeout: time.Second,
			})
			tc.setupMocks(mockStorage, mockSyncer)
			_, err := book.QueryAssetInfo(ctx, tc.specifier)
			if tc.expectsError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			mockStorage.AssertExpectations(t)
			mockSyncer.AssertExpectations(t)
		})
	}
}

// MockStorage is a mock implementation of the Storage interface.
type MockStorage struct {
	mock.Mock
}

func (m *MockStorage) FetchAllAssetMeta(
	ctx context.Context) (map[asset.ID]*proof.MetaReveal, error) {

	args := m.Called(ctx)
	return args.Get(0).(map[asset.ID]*proof.MetaReveal), args.Error(1)
}

func (m *MockStorage) LastEventHeightByVersion(ctx context.Context,
	version Version) (uint32, error) {

	args := m.Called(ctx, version)
	return args.Get(0).(uint32), args.Error(1)
}

func (m *MockStorage) AddrByScriptKeyAndVersion(ctx context.Context,
	key *btcec.PublicKey, version Version) (*AddrWithKeyInfo, error) {

	args := m.Called(ctx, key, version)
	return args.Get(0).(*AddrWithKeyInfo), args.Error(1)
}

func (m *MockStorage) GetOrCreateEvent(ctx context.Context, status Status,
	transfer IncomingTransfer) (*Event, error) {

	args := m.Called(ctx, status, transfer)
	return args.Get(0).(*Event), args.Error(1)
}

func (m *MockStorage) QueryAddrEvents(ctx context.Context,
	params EventQueryParams) ([]*Event, error) {

	args := m.Called(ctx, params)
	return args.Get(0).([]*Event), args.Error(1)
}

func (m *MockStorage) QueryEvent(ctx context.Context, addr *AddrWithKeyInfo,
	outpoint wire.OutPoint) (*Event, error) {

	args := m.Called(ctx, addr, outpoint)
	return args.Get(0).(*Event), args.Error(1)
}

func (m *MockStorage) CompleteEvent(ctx context.Context, event *Event,
	status Status, anchorPoint wire.OutPoint) error {

	args := m.Called(ctx, event, status, anchorPoint)
	return args.Error(0)
}

func (m *MockStorage) InsertAddrs(ctx context.Context,
	addrs ...AddrWithKeyInfo) error {

	args := m.Called(ctx, addrs)
	return args.Error(0)
}

func (m *MockStorage) QueryAddrs(ctx context.Context,
	params QueryParams) ([]AddrWithKeyInfo, error) {

	args := m.Called(ctx, params)
	return args.Get(0).([]AddrWithKeyInfo), args.Error(1)
}

func (m *MockStorage) QueryAssetGroup(ctx context.Context,
	id asset.ID) (*asset.AssetGroup, error) {

	args := m.Called(ctx, id)
	return args.Get(0).(*asset.AssetGroup), args.Error(1)
}

func (m *MockStorage) QueryAssetGroupByGroupKey(ctx context.Context,
	key *btcec.PublicKey) (*asset.AssetGroup, error) {

	args := m.Called(ctx, key)
	return args.Get(0).(*asset.AssetGroup), args.Error(1)
}

func (m *MockStorage) FetchAssetMetaByHash(ctx context.Context,
	metaHash [asset.MetaHashLen]byte) (*proof.MetaReveal, error) {

	args := m.Called(ctx, metaHash)
	return args.Get(0).(*proof.MetaReveal), args.Error(1)
}

func (m *MockStorage) FetchAssetMetaForAsset(ctx context.Context,
	assetID asset.ID) (*proof.MetaReveal, error) {

	args := m.Called(ctx, assetID)
	return args.Get(0).(*proof.MetaReveal), args.Error(1)
}

func (m *MockStorage) AddrByTaprootOutput(ctx context.Context,
	key *btcec.PublicKey) (*AddrWithKeyInfo, error) {

	args := m.Called(ctx, key)
	return args.Get(0).(*AddrWithKeyInfo), args.Error(1)
}

func (m *MockStorage) SetAddrManaged(ctx context.Context, addr *AddrWithKeyInfo,
	managedFrom time.Time) error {

	args := m.Called(ctx, addr, managedFrom)
	return args.Error(0)
}

func (m *MockStorage) InsertInternalKey(ctx context.Context,
	keyDesc keychain.KeyDescriptor) error {

	args := m.Called(ctx, keyDesc)
	return args.Error(0)
}

func (m *MockStorage) InsertScriptKey(ctx context.Context,
	scriptKey asset.ScriptKey, keyType asset.ScriptKeyType) error {

	args := m.Called(ctx, scriptKey, keyType)
	return args.Error(0)
}

// MockAssetSyncer is a mock implementation of the AssetSyncer interface.
type MockAssetSyncer struct {
	mock.Mock
}

func (m *MockAssetSyncer) SyncAssetInfo(ctx context.Context,
	specifier asset.Specifier) error {

	args := m.Called(ctx, specifier)
	return args.Error(0)
}

func (m *MockAssetSyncer) EnableAssetSync(ctx context.Context,
	groupInfo *asset.AssetGroup) error {

	args := m.Called(ctx, groupInfo)
	return args.Error(0)
}

// MockKeyRing is a mock implementation of the KeyRing interface.
type MockKeyRing struct {
	mock.Mock
}

func (m *MockKeyRing) DeriveNextTaprootAssetKey(
	ctx context.Context) (keychain.KeyDescriptor, error) {

	args := m.Called(ctx)
	return args.Get(0).(keychain.KeyDescriptor), args.Error(1)
}

func (m *MockKeyRing) DeriveNextKey(ctx context.Context,
	family keychain.KeyFamily) (keychain.KeyDescriptor, error) {

	args := m.Called(ctx, family)
	return args.Get(0).(keychain.KeyDescriptor), args.Error(1)
}

func (m *MockKeyRing) IsLocalKey(ctx context.Context,
	desc keychain.KeyDescriptor) bool {

	args := m.Called(ctx, desc)
	return args.Bool(0)
}
