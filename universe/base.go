package universe

import (
	"bytes"
	"context"
	"fmt"
	"sync"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/davecgh/go-spew/spew"
	"github.com/lightninglabs/taproot-assets/proof"
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

	// UniverseStats is used to export statistics related to the set of
	// external/internal queries to the base universe instance.
	UniverseStats Telemetry

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

// fetchUniverse returns the base universe instance for the passed identifier.
// The universe will be loaded in on demand if it has not been seen before.
func (a *MintingArchive) fetchUniverse(id Identifier) BaseBackend {
	a.Lock()
	defer a.Unlock()

	baseUni, ok := a.baseUniverses[id]
	if !ok {
		baseUni = a.cfg.NewBaseTree(id)
		a.baseUniverses[id] = baseUni
	}

	return baseUni
}

// uniFetcher takes a base universe ID, and returns the base universe
// backend associated with the ID.
type uniFetcher interface {
	fetchUniverse(id Identifier) BaseBackend
}

// uniAction is a function that takes a base universe backend, and does
// something to it, returning a type T and an error.
type uniAction[T any] func(BaseBackend) (T, error)

// withBaseUni is a helper function for performing some action on/with a base
// universe with a generic return value.
func withBaseUni[T any](fetcher uniFetcher, id Identifier,
	f uniAction[T]) (T, error) {

	baseUni := fetcher.fetchUniverse(id)

	return f(baseUni)
}

// RootNode returns the root node of the base universe corresponding to the
// passed ID.
func (a *MintingArchive) RootNode(ctx context.Context,
	id Identifier) (BaseRoot, error) {

	log.Debugf("Looking up root node for base Universe %v", spew.Sdump(id))

	return withBaseUni(a, id, func(baseUni BaseBackend) (BaseRoot, error) {
		smtNode, assetName, err := baseUni.RootNode(ctx)
		if err != nil {
			return BaseRoot{}, err
		}

		return BaseRoot{
			ID:        id,
			Node:      smtNode,
			AssetName: assetName,
		}, nil
	})
}

// RootNodes returns the set of root nodes for all known base universes assets.
func (a *MintingArchive) RootNodes(ctx context.Context) ([]BaseRoot, error) {
	log.Debugf("Fetching all known Universe roots")

	return a.cfg.UniverseForest.RootNodes(ctx)
}

// RegisterIssuance attempts to register a new issuance proof for a new minting
// event for the specified base universe identifier. This method will return an
// error if the passed minting proof is invalid. If the leaf is already known,
// then no action is taken and the existing issuance commitment proof returned.
func (a *MintingArchive) RegisterIssuance(ctx context.Context, id Identifier,
	key BaseKey, leaf *MintingLeaf) (*IssuanceProof, error) {

	log.Debugf("Inserting new proof into Universe: id=%v, base_key=%v",
		id.StringForLog(), spew.Sdump(key))

	baseUni := a.fetchUniverse(id)

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
	// The proofs we insert are just the state transition, so we'll encode
	// it as a file first as that's what the expected wants.
	//
	// TODO(roasbeef): add option to skip proof verification?
	var newProof proof.Proof
	err := newProof.Decode(bytes.NewReader(leaf.GenesisProof))
	if err != nil {
		return nil, fmt.Errorf("unable to decode proof: %v", err)
	}
	assetSnapshot, err := newProof.Verify(ctx, nil, a.cfg.HeaderVerifier)
	if err != nil {
		return nil, fmt.Errorf("unable to verify proof: %v", err)
	}

	newAsset := assetSnapshot.Asset

	// The final asset we extract from the proof should also match up with
	// both the universe ID and also the base key.
	switch {
	// If the group key is present, then that should match the group key of
	// the universe.
	case id.GroupKey != nil && !bytes.Equal(
		schnorr.SerializePubKey(id.GroupKey),
		schnorr.SerializePubKey(&newAsset.GroupKey.GroupPubKey),
	):
		return nil, fmt.Errorf("group key mismatch: expected %x, "+
			"got %x", id.GroupKey.SerializeCompressed(),
			newAsset.GroupKey.GroupPubKey.SerializeCompressed())

	// If the group key is nil, then the asset ID should match.
	case id.GroupKey == nil && id.AssetID != newAsset.ID():
		return nil, fmt.Errorf("asset id mismatch: expected %v, got %v",
			id.AssetID, newAsset.ID())

	// The outpoint of the final resting place of the asset should match
	// the leaf key
	//
	// TODO(roasbeef): this restrict to issuance
	case assetSnapshot.OutPoint != key.MintingOutpoint:
		return nil, fmt.Errorf("outpoint mismatch: expected %v, got %v",
			key.MintingOutpoint, assetSnapshot.OutPoint)

	// The script key should also match exactly.
	case !newAsset.ScriptKey.PubKey.IsEqual(key.ScriptKey.PubKey):
		return nil, fmt.Errorf("script key mismatch: expected %v, "+
			"got %v", key.ScriptKey.PubKey.SerializeCompressed(),
			newAsset.ScriptKey.PubKey.SerializeCompressed())
	}

	// Now that we know the proof is valid, we'll insert it into the base
	// universe backend, and return the new issuance proof.
	issuanceProof, err := a.cfg.UniverseForest.RegisterIssuance(
		ctx, id, key, leaf, assetSnapshot.MetaReveal,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to register new "+
			"issuance: %v", err)
	}

	// Log a sync event for the newly inserted leaf in the background as an
	// async goroutine.
	go func() {
		err := a.cfg.UniverseStats.LogNewProofEvent(
			context.Background(), id, key,
		)
		if err != nil {
			log.Warnf("unable to log new proof event (id=%v): %v",
				id.StringForLog(), err)
		}
	}()

	return issuanceProof, nil
}

// FetchIssuanceProof attempts to fetch an issuance proof for the target base
// leaf based on the universe identifier (assetID/groupKey).
func (a *MintingArchive) FetchIssuanceProof(ctx context.Context, id Identifier,
	key BaseKey) ([]*IssuanceProof, error) {

	log.Debugf("Retrieving Universe proof for: id=%v, base_key=%v",
		id.StringForLog(), spew.Sdump(key))

	// Log a sync event for the leaf query leaf in the background as an
	// async goroutine.
	defer func() {
		go func() {
			err := a.cfg.UniverseStats.LogSyncEvent(
				context.Background(), id, key,
			)
			if err != nil {
				log.Warnf("unable to log sync event (id=%v, "+
					"key=%v): %v", id.StringForLog(),
					spew.Sdump(key), err)
			}
		}()
	}()

	return withBaseUni(
		a, id, func(baseUni BaseBackend) ([]*IssuanceProof, error) {
			return baseUni.FetchIssuanceProof(ctx, key)
		},
	)
}

// MintingKeys returns the set of minting keys known for the specified base
// universe identifier.
func (a *MintingArchive) MintingKeys(ctx context.Context,
	id Identifier) ([]BaseKey, error) {

	log.Debugf("Retrieving all keys for Universe: id=%v", id.StringForLog())

	return withBaseUni(a, id, func(baseUni BaseBackend) ([]BaseKey, error) {
		return baseUni.MintingKeys(ctx)
	})
}

// MintingLeaves returns the set of minting leaves known for the specified base
// universe.
func (a *MintingArchive) MintingLeaves(ctx context.Context,
	id Identifier) ([]MintingLeaf, error) {

	log.Debugf("Retrieving all leaves for Universe: id=%v",
		id.StringForLog())

	return withBaseUni(
		a, id, func(baseUni BaseBackend) ([]MintingLeaf, error) {
			return baseUni.MintingLeaves(ctx)
		},
	)
}

// DeleteRoot deletes all universe leaves, and the universe root, for the
// specified base universe.
func (a *MintingArchive) DeleteRoot(ctx context.Context,
	id Identifier) (string, error) {

	log.Debugf("Deleting universe tree for Universe: id=%v", id.String())

	uniStr, err := withBaseUni(a, id, func(baseUni BaseBackend) (string,
		error) {

		return baseUni.DeleteUniverse(ctx)
	})

	if err != nil {
		log.Tracef("Failed to delete universe tree: %w", err)
	}
	return uniStr, err
}
