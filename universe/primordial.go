package universe

import (
	"context"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taro/mssmt"
)

// Primordial....
type Primordial struct {
	// TODO(roasbeef): add write thru caching
	cfg *Config
}

// Config...
type Config struct {
	// TreeStorage...
	TreeStorage mssmt.Tree
}

// NewPrimordial...
func NewPrimordial(cfg *Config) (*Primordial, error) {
	return nil, nil
}

// FamilyKey...
func (p *Primordial) FamilyKey(context.Context) (*btcec.PublicKey, error) {
	return nil, nil
	//return cfg.Tree.FamilyKey(ctx)
}

// RootNode...
func (p *Primordial) RootNode(context.Context) (mssmt.Node, error) {
	return nil, nil
}

// Query...
func (p *Primordial) Query(ctx context.Context, key BaseKey) (*IssuanceProof, error) {
	return nil, nil
}

// GenesisPoints...
//
// TODO(roasbeef): also return assetIDs as well? so then just the base
// keys?
func (p *Primordial) GenesisPoints(ctx context.Context) ([]wire.OutPoint, error) {
	return nil, nil
}
