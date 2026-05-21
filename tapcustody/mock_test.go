package tapcustody

import (
	"context"
	"fmt"
	"time"

	"github.com/lightninglabs/taproot-assets/asset"
)

// MockAssetSyncer is a mock implementation of address.AssetSyncer used
// by custodian tests to drive asset discovery flows.
type MockAssetSyncer struct {
	Assets map[asset.ID]*asset.AssetGroup

	FetchedAssets chan *asset.AssetGroup

	FetchErrs bool
}

func NewMockAssetSyncer() *MockAssetSyncer {
	return &MockAssetSyncer{
		Assets:        make(map[asset.ID]*asset.AssetGroup),
		FetchedAssets: make(chan *asset.AssetGroup, 1),
		FetchErrs:     false,
	}
}

func (m *MockAssetSyncer) AddAsset(newAsset asset.Asset) {
	assetGroup := &asset.AssetGroup{
		Genesis: &newAsset.Genesis,
	}

	if newAsset.GroupKey != nil {
		assetGroup.GroupKey = newAsset.GroupKey
	}

	m.Assets[newAsset.ID()] = assetGroup
}

func (m *MockAssetSyncer) RemoveAsset(id asset.ID) {
	delete(m.Assets, id)
}

func (m *MockAssetSyncer) FetchAsset(id asset.ID) (*asset.AssetGroup, error) {
	bookDelay := time.Millisecond * 25

	assetGroup, ok := m.Assets[id]
	switch {
	case ok:
		// Broadcast the fetched asset so it can be added to the
		// address book.
		m.FetchedAssets <- assetGroup

		// Wait for the address book to be updated.
		time.Sleep(bookDelay)
		return assetGroup, nil

	case m.FetchErrs:
		return nil, fmt.Errorf("failed to fetch asset info")

	default:
		return nil, nil
	}
}

func (m *MockAssetSyncer) SyncAssetInfo(_ context.Context,
	s asset.Specifier) error {

	if !s.HasId() {
		return fmt.Errorf("no asset ID provided")
	}

	_, err := m.FetchAsset(*s.UnwrapIdToPtr())
	return err
}

func (m *MockAssetSyncer) EnableAssetSync(_ context.Context,
	groupInfo *asset.AssetGroup) error {

	return nil
}
