package universe

import (
	"bytes"
	"context"
	"fmt"
	"sync"

	"github.com/lightninglabs/taro/mssmt"
	"github.com/lightninglabs/taro/proof"
)

// MintingArchiveConfig is the main config for the minting archive. This
// includes all the items required to interact with the set of relevant base
// universes.
type MintingArchiveConfig struct {
	// NewBaseTree returns a new base universe backend for the given
	// identifier. This method always returns a new universe instance, even
	// if the identifier has never been seen before.
	NewBaseTree func(id Identifier) BaseBackend

	// HeaderVerifier is used to verify the validity of the header for a
	// genesis proof.
	HeaderVerifier proof.HeaderVerifier

	// UniverseForest is used to interact with the set of known base
	// universe trees, and also obtain associated metadata and statistics.
	UniverseForest BaseForest

	// TODO(roasbeef): query re genesis asset known?

	// TODO(roasbeef): load all at once, or lazy load dynamic?
}

// MintingArchive is a persistence implementation of the Base universe
// interface. This is used by minting sub-systems to register new base universe
// issuance proofs each time an asset is created. It can also be used to
// synchronize state amongst disparate base universe instances, and also to
// serve as initial bootstrap for users wishing to send/receive assets.
//
// TODO(roasbeef): erect universe in front of?
type MintingArchive struct {
	cfg MintingArchiveConfig

	// baseUniverses is a map of all the current known base universe
	// instances for the archive.
	baseUniverses map[Identifier]BaseBackend

	sync.RWMutex
}

// NewMintingArchive creates a new minting archive based on the passed config.
func NewMintingArchive(cfg MintingArchiveConfig) *MintingArchive {
	a := &MintingArchive{
		cfg:           cfg,
		baseUniverses: make(map[Identifier]BaseBackend),
	}

	return a
}

// fetchBaseUni returns the base universe instance for the passed identifier.
// The universe will be laoded in on demand if it has not been seen before.
func (a *MintingArchive) fetchBaseUni(id Identifier) BaseBackend {
	a.Lock()
	defer a.Unlock()

	baseUni, ok := a.baseUniverses[id]
	if !ok {
		baseUni = a.cfg.NewBaseTree(id)
		a.baseUniverses[id] = baseUni
	}

	return baseUni
}

type (
	// uniFetcher takes a base universe ID, and returns the base universe
	// backend associated with the ID.
	uniFetcher func(id Identifier) BaseBackend

	// uniAction is a function that takes a base universe backend, and does
	// something to it, returning a type T and an error.
	uniAction[T any] func(BaseBackend) (T, error)
)

// universeCtx is a context manager that can be used to perform scoped actions
// to a base universe instance.
type universeCtx[T any] struct {
	fetcher uniFetcher
}

// withBaseUni is a helper method that takes a base universe ID, and a applies
// some function f to the base universe backed for that DI.
func (u *universeCtx[T]) withBaseUni(id Identifier,
	f uniAction[T]) (T, error) {

	baseUni := u.fetcher(id)

	return f(baseUni)
}

// withBaseUni is a helper function for performing some action on/with a base
// universe with a generic return value.
func withBaseUni[T any](id Identifier, f uniAction[T]) (T, error) {
	var uniCtx universeCtx[T]

	return uniCtx.withBaseUni(id, f)
}

// RootNode returns the root node of the base universe corresponding to the
// passed ID.
func (a *MintingArchive) RootNode(ctx context.Context,
	id Identifier) (mssmt.Node, error) {

	return withBaseUni(id, func(baseUni BaseBackend) (mssmt.Node, error) {
		return baseUni.RootNode(ctx)
	})
}

// RootNodes returns the set of root nodes for all known base universes assets.
func (a *MintingArchive) RootNodes(ctx context.Context) ([]BaseRoot, error) {
	return a.cfg.UniverseForest.RootNodes(ctx)
}

// RegisterIssuance attempts to register a new issuance proof for a new minting
// event for the specified base universe identifier. This method will return an
// error if the passed minting proof is invalid. If the leaf is already known,
// then no action is taken and the existing issuance commitment proof returned.
func (a *MintingArchive) RegisterIssuance(ctx context.Context, id Identifier,
	key BaseKey, leaf *MintingLeaf) (*IssuanceProof, error) {

	baseUni := a.fetchBaseUni(id)

	// We'll first check to see if we already know of this leaf within the
	// base uni instance. If so, then we'll return the existing issuance
	// proof.
	// TODO(roasbeef): put this logic lower down the stack?
	if proofs, err := baseUni.FetchIssuanceProof(ctx, key); err == nil {
		issuanceProof := proofs[0]
		return issuanceProof, nil
	}

	// Otherwise, this is a new proof, so we'll first perform validation of
	// the minting leaf to ensure it's a valid issuance proof.
	//
	// TODO(roasbeef): add option to skip proof verification?
	var proofVerifier proof.BaseVerifier
	_, err := proofVerifier.Verify(
		ctx, bytes.NewReader(leaf.GenesisProof), a.cfg.HeaderVerifier,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to decode proof: %v", err)
	}

	// Now that we know the proof is valid, we'll insert it into the base
	// universe backend, and return the new issuance proof.
	issuanceProof, err := baseUni.RegisterIssuance(ctx, key, leaf)
	if err != nil {
		return nil, fmt.Errorf("unable to register new "+
			"issuance: %v", err)
	}

	return issuanceProof, nil
}

// FethcIssuanceProof attempts to fetch an issuance proof for the target base
// leaf based on the universe identifier (assetID/groupKey).
func (a *MintingArchive) FetchIssuanceProof(ctx context.Context, id Identifier,
	key BaseKey) ([]*IssuanceProof, error) {

	return withBaseUni(id, func(baseUni BaseBackend) ([]*IssuanceProof, error) {
		return baseUni.FetchIssuanceProof(ctx, key)
	})

}

// MintingKeys returns the set of minting keys known for the specified base
// universe identifier.
func (a *MintingArchive) MintingKeys(ctx context.Context,
	id Identifier) ([]BaseKey, error) {

	return withBaseUni(id, func(baseUni BaseBackend) ([]BaseKey, error) {
		return baseUni.MintingKeys(ctx)
	})
}

// MintingLeaves returns the set of minting leaves known for the specified base
// universe.
func (a *MintingArchive) MintingLeaves(ctx context.Context,
	id Identifier) ([]MintingLeaf, error) {

	return withBaseUni(id, func(baseUni BaseBackend) ([]MintingLeaf, error) {
		return baseUni.MintingLeaves(ctx)
	})
}
