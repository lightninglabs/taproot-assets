package universe

import (
	"context"

	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/mssmt"
)

type BaseTree interface {
}

// MintingArchiveConfig...
type MintingArchiveConfig struct {
	// Tree....
	Tree BaseTree
}

// MintingArchive...
//
// TODO(roasbeef): also use to implement proof archive backend?
type MintingArchive struct {
	cfg MintingArchiveConfig

	// knownIDs...
	knownIDs map[Identifier]struct{}
}

// NewMintingArchive...
func NewMintingArchive(cfg MintingArchiveConfig) *MintingArchive {
	return &MintingArchive{
		cfg:      cfg,
		knownIDs: make(map[Identifier]struct{}),
	}
}

// RootNode...
func (a *MintingArchive) RootNode(ctx context.Context,
	id Identifier) (mssmt.Node, error) {

	return nil, nil
}

// RegisterIssuance...
func (a *MintingArchive) RegisterIssuance(ctx context.Context, id Identifier,
	key BaseKey, leaf *MintingLeaf) (*IssuanceProof, error) {

	// TODO(roasbeef): does full verificaiton, etc

	return nil, nil
}

// FethcIssuanceProof...
func (a *MintingArchive) FetchIssuanceProof(ctx context.Context, id Identifier,
	key BaseKey) ([]*IssuanceProof, error) {

	return nil, nil
}

// MintingKeys...
func (a *MintingArchive) MintingKeys(ctx context.Context,
	id Identifier) ([]BaseKey, error) {

	return nil, nil
}

// MintingLeaves...
func (a *MintingArchive) MintingLeaves(ctx context.Context,
	id Identifier) ([]*MintingLeaf, error) {

	return nil, nil
}

type GenesisWithGroup struct {
	asset.Genesis

	asset.GroupKey
}

func (g *GenesisWithGroup) UniverseID() *Identifier {
	return nil
}

// KnownAssets...
func (a *MintingArchive) KnownAssets() []GenesisWithGroup {
	return nil
}
