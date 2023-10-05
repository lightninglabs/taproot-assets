package universe

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/davecgh/go-spew/spew"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
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

	// GroupVerifier is used to verify the validity of the group key for a
	// genesis proof.
	GroupVerifier proof.GroupVerifier

	// Multiverse is used to interact with the set of known base
	// universe trees, and also obtain associated metadata and statistics.
	Multiverse MultiverseArchive

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

	return a.cfg.Multiverse.RootNodes(ctx)
}

// RegisterIssuance attempts to register a new issuance proof for a new minting
// event for the specified base universe identifier. This method will return an
// error if the passed minting proof is invalid. If the leaf is already known,
// then no action is taken and the existing issuance commitment proof returned.
func (a *MintingArchive) RegisterIssuance(ctx context.Context, id Identifier,
	key LeafKey, leaf *Leaf) (*Proof, error) {

	log.Debugf("Inserting new proof into Universe: id=%v, base_key=%v",
		id.StringForLog(), spew.Sdump(key))

	newProof := leaf.Proof

	// If universe proof type unspecified in universe ID, set based on the
	// provided asset proof.
	if id.ProofType == ProofTypeUnspecified {
		var err error
		id.ProofType, err = NewProofTypeFromAssetProof(newProof)
		if err != nil {
			return nil, err
		}
	}

	// We'll first check to see if we already know of this leaf within the
	// multiverse. If so, then we'll return the existing issuance proof.
	issuanceProofs, err := a.cfg.Multiverse.FetchProofLeaf(ctx, id, key)
	switch {
	case err == nil && len(issuanceProofs) > 0:
		issuanceProof := issuanceProofs[0]

		// The only valid case for an update of a proof is if the mint
		// TX was re-organized out of the chain. If the block hash is
		// still the same, we don't see this as an update and just
		// return the existing proof.
		existingProof := issuanceProof.Leaf.Proof
		if existingProof.BlockHeader.BlockHash() ==
			newProof.BlockHeader.BlockHash() {

			return issuanceProof, nil
		}

	case errors.Is(err, ErrNoUniverseProofFound):
		// Don't return an error if we don't find the proof. We will
		// continue on to insert the new proof.

	case err != nil:
		return nil, err
	}

	// Otherwise, this is a new proof, so we'll first perform validation of
	// the minting leaf to ensure it's a valid issuance proof.
	//
	//
	// TODO(roasbeef): add option to skip proof verification?

	// Before we can validate a non-issuance proof we need to fetch the
	// previous asset snapshot (which is the proof verification result for
	// the previous/parent proof in the proof file).
	prevAssetSnapshot, err := a.getPrevAssetSnapshot(ctx, id, *newProof)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch previous asset "+
			"snapshot: %w", err)
	}

	assetSnapshot, err := a.verifyIssuanceProof(
		ctx, id, key, leaf, prevAssetSnapshot,
	)
	if err != nil {
		return nil, err
	}

	// Now that we know the proof is valid, we'll insert it into the base
	// multiverse backend, and return the new issuance proof.
	issuanceProof, err := a.cfg.Multiverse.UpsertProofLeaf(
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

// verifyIssuanceProof verifies the passed minting leaf is a valid issuance
// proof, returning the asset snapshot if so.
func (a *MintingArchive) verifyIssuanceProof(ctx context.Context, id Identifier,
	key LeafKey, leaf *Leaf,
	prevAssetSnapshot *proof.AssetSnapshot) (*proof.AssetSnapshot, error) {

	assetSnapshot, err := leaf.Proof.Verify(
		ctx, prevAssetSnapshot, a.cfg.HeaderVerifier,
		a.cfg.GroupVerifier,
	)
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

	// The script key should also match exactly.
	case !newAsset.ScriptKey.PubKey.IsEqual(key.ScriptKey.PubKey):
		return nil, fmt.Errorf("script key mismatch: expected %v, got "+
			"%v", key.ScriptKey.PubKey.SerializeCompressed(),
			newAsset.ScriptKey.PubKey.SerializeCompressed())
	}

	return assetSnapshot, nil
}

// RegisterNewIssuanceBatch inserts a batch of new minting leaves within the
// target universe tree (based on the ID), stored at the base key(s). We assume
// the proofs within the batch have already been checked that they don't yet
// exist in the local database.
func (a *MintingArchive) RegisterNewIssuanceBatch(ctx context.Context,
	items []*IssuanceItem) error {

	log.Infof("Verifying %d new proofs for insertion into Universe",
		len(items))

	// Issuances that also create an asset group, group anchors, must be
	// verified and stored before any issuances that may be reissuances into
	// the same asset group. This is required for proper verification of
	// reissuances, which may be in this batch.
	var anchorItems []*IssuanceItem
	nonAnchorItems := make([]*IssuanceItem, 0, len(items))
	for ind := range items {
		item := items[ind]
		// Any group anchor issuance proof must have a group key reveal
		// attached, so tht can be used to partition anchor assets and
		// non-anchor assets.
		switch {
		case item.Leaf.Proof.GroupKeyReveal != nil:
			anchorItems = append(anchorItems, item)
		default:
			nonAnchorItems = append(nonAnchorItems, item)
		}
	}

	verifyBatch := func(batchItems []*IssuanceItem) error {
		err := fn.ParSlice(
			ctx, batchItems, func(ctx context.Context,
				i *IssuanceItem) error {

				assetSnapshot, err := a.verifyIssuanceProof(
					ctx, i.ID, i.Key, i.Leaf, nil,
				)
				if err != nil {
					return err
				}

				i.MetaReveal = assetSnapshot.MetaReveal

				return nil
			},
		)
		if err != nil {
			return fmt.Errorf("unable to verify issuance proofs: "+
				"%w", err)
		}

		return nil
	}

	err := verifyBatch(anchorItems)
	if err != nil {
		return err
	}

	log.Infof("Inserting %d verified group anchor proofs into Universe",
		len(anchorItems))
	err = a.cfg.Multiverse.RegisterBatchIssuance(ctx, anchorItems)
	if err != nil {
		return fmt.Errorf("unable to register new group anchor "+
			"issuance proofs: %w", err)
	}

	err = verifyBatch(nonAnchorItems)
	if err != nil {
		return err
	}

	log.Infof("Inserting %d verified proofs into Universe",
		len(nonAnchorItems))
	err = a.cfg.Multiverse.RegisterBatchIssuance(ctx, nonAnchorItems)
	if err != nil {
		return fmt.Errorf("unable to register new issuance proofs: %w",
			err)
	}

	// Log a sync event for the newly inserted leaf in the background as an
	// async goroutine.
	ids := fn.Map(items, func(item *IssuanceItem) Identifier {
		return item.ID
	})
	go func() {
		err := a.cfg.UniverseStats.LogNewProofEvents(
			context.Background(), ids...,
		)
		if err != nil {
			log.Warnf("unable to log new proof events: %v", err)
		}
	}()

	return nil
}

// getPrevAssetSnapshot returns the previous asset snapshot for the passed
// proof. If the proof is a genesis proof, then nil is returned.
func (a *MintingArchive) getPrevAssetSnapshot(ctx context.Context,
	uniID Identifier, newProof proof.Proof) (*proof.AssetSnapshot, error) {

	// If this is a genesis proof, then there is no previous asset (and
	// therefore no previous asset snapshot).
	if newProof.Asset.IsGenesisAsset() {
		return nil, nil
	}

	// Query for proof associated with the previous asset.
	prevID, err := newProof.Asset.PrimaryPrevID()
	if err != nil {
		return nil, err
	}

	if prevID == nil {
		return nil, fmt.Errorf("no previous asset ID found")
	}

	// Parse script key for previous asset.
	prevScriptKeyPubKey, err := btcec.ParsePubKey(
		prevID.ScriptKey[:],
	)
	if err != nil {
		return nil, fmt.Errorf("unable to parse previous "+
			"script key: %v", err)
	}
	prevScriptKey := asset.NewScriptKey(prevScriptKeyPubKey)

	prevLeafKey := LeafKey{
		OutPoint:  prevID.OutPoint,
		ScriptKey: &prevScriptKey,
	}

	prevProofs, err := a.cfg.Multiverse.FetchProofLeaf(
		ctx, uniID, prevLeafKey,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch previous "+
			"proof: %v", err)
	}

	prevProof := prevProofs[0].Leaf.Proof

	// Construct minimal asset snapshot for previous asset.
	// This is a minimal the proof verification result for the
	// previous (input) asset. We know that it was already verified
	// as it was present in the multiverse/universe archive.
	return &proof.AssetSnapshot{
		Asset:    &prevProof.Asset,
		OutPoint: prevID.OutPoint,
	}, nil
}

// FetchIssuanceProof attempts to fetch an issuance proof for the target base
// leaf based on the universe identifier (assetID/groupKey).
func (a *MintingArchive) FetchIssuanceProof(ctx context.Context, id Identifier,
	key LeafKey) ([]*Proof, error) {

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

	return a.cfg.Multiverse.FetchProofLeaf(ctx, id, key)
}

// UniverseLeafKeys returns the set of leaf keys known for the specified
// universe identifier.
func (a *MintingArchive) UniverseLeafKeys(ctx context.Context,
	id Identifier) ([]LeafKey, error) {

	log.Debugf("Retrieving all keys for Universe: id=%v", id.StringForLog())

	return withBaseUni(a, id, func(baseUni BaseBackend) ([]LeafKey, error) {
		return baseUni.MintingKeys(ctx)
	})
}

// MintingLeaves returns the set of minting leaves known for the specified base
// universe.
func (a *MintingArchive) MintingLeaves(ctx context.Context,
	id Identifier) ([]Leaf, error) {

	log.Debugf("Retrieving all leaves for Universe: id=%v",
		id.StringForLog())

	return withBaseUni(
		a, id, func(baseUni BaseBackend) ([]Leaf, error) {
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
