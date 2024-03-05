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
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/proof"
)

// ArchiveConfig is the main config for the archive. This includes all the items
// required to interact with the set of relevant universes.
type ArchiveConfig struct {
	// NewBaseTree returns a new base universe backend for the given
	// identifier. This method always returns a new universe instance, even
	// if the identifier has never been seen before.
	NewBaseTree func(id Identifier) BaseBackend

	// HeaderVerifier is used to verify the validity of the header for a
	// genesis proof.
	HeaderVerifier proof.HeaderVerifier

	// MerkleVerifier is used to verify the validity of the transaction
	// merkle proof.
	MerkleVerifier proof.MerkleVerifier

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

// Archive is a persistence implementation of the universe interface. This is
// used by minting sub-systems to upsert new universe issuance proofs each time
// an asset is created. It can also be used to synchronize state amongst
// disparate universe instances, and also to serve as initial bootstrap for
// users wishing to send/receive assets.
//
// TODO(roasbeef): erect universe in front of?
type Archive struct {
	cfg ArchiveConfig

	// baseUniverses is a map of all the current known base universe
	// instances for the archive.
	baseUniverses map[Identifier]BaseBackend

	sync.RWMutex
}

// NewArchive creates a new universe archive based on the passed config.
func NewArchive(cfg ArchiveConfig) *Archive {
	a := &Archive{
		cfg:           cfg,
		baseUniverses: make(map[Identifier]BaseBackend),
	}

	return a
}

// Close closes the archive, stopping all goroutines and freeing all resources.
func (a *Archive) Close() error {
	return nil
}

// fetchUniverse returns the base universe instance for the passed identifier.
// The universe will be loaded in on demand if it has not been seen before.
func (a *Archive) fetchUniverse(id Identifier) BaseBackend {
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
func (a *Archive) RootNode(ctx context.Context,
	id Identifier) (Root, error) {

	log.Debugf("Looking up root node for base Universe %v", spew.Sdump(id))

	return a.cfg.Multiverse.UniverseRootNode(ctx, id)
}

type RootNodesQuery struct {
	WithAmountsById bool
	SortDirection   SortDirection
	Offset          int32
	Limit           int32
}

// RootNodes returns the set of root nodes for all known base universes assets.
func (a *Archive) RootNodes(ctx context.Context,
	q RootNodesQuery) ([]Root, error) {

	log.Tracef("Fetching all known Universe roots (with_amounts_by_id=%v"+
		", sort_direction=%v, offset=%v, limit=%v)", q.WithAmountsById,
		q.SortDirection, q.Offset, q.Limit)

	return a.cfg.Multiverse.RootNodes(ctx, q)
}

// MultiverseRoot returns the root node of the multiverse for the specified
// proof type. If the given list of universe IDs is non-empty, then the root
// will be calculated just for those universes.
func (a *Archive) MultiverseRoot(ctx context.Context, proofType ProofType,
	filterByIDs []Identifier) (fn.Option[MultiverseRoot], error) {

	log.Debugf("Fetching multiverse root for proof type: %v", proofType)

	none := fn.None[MultiverseRoot]()

	// If we don't have any IDs, then we'll return the multiverse root for
	// the given proof type.
	if len(filterByIDs) == 0 {
		rootNode, err := a.cfg.Multiverse.MultiverseRootNode(
			ctx, proofType,
		)
		if err != nil {
			return none, err
		}

		return rootNode, nil
	}

	// Otherwise, we'll run the query to fetch the multiverse leaf for each
	// of the specified assets.
	uniTargets := make([]MultiverseLeafDesc, len(filterByIDs))
	for idx, id := range filterByIDs {
		if id.GroupKey != nil {
			uniTargets[idx] = fn.NewRight[asset.ID](*id.GroupKey)
		} else {
			uniTargets[idx] = fn.NewLeft[asset.ID, btcec.PublicKey](
				id.AssetID,
			)
		}
	}

	multiverseLeaves, err := a.cfg.Multiverse.FetchLeaves(
		ctx, uniTargets, proofType,
	)
	if err != nil {
		return none, fmt.Errorf("unable to fetch multiverse "+
			"leaves: %w", err)
	}

	// Now that we have the leaves, we'll insert them into an in-memory
	// tree, so we can obtain the root for this unique combination.
	memStore := mssmt.NewDefaultStore()
	tree := mssmt.NewCompactedTree(memStore)

	for _, leaf := range multiverseLeaves {
		_, err = tree.Insert(ctx, leaf.ID.Bytes(), leaf.LeafNode)
		if err != nil {
			return none, fmt.Errorf("unable to insert "+
				"leaf: %w", err)
		}
	}

	customRoot, err := tree.Root(ctx)
	if err != nil {
		return none, fmt.Errorf("unable to obtain root: %w", err)
	}

	multiverseRoot := MultiverseRoot{
		ProofType: proofType,
		Node:      customRoot,
	}

	return fn.Some(multiverseRoot), nil
}

// UpsertProofLeaf attempts to upsert a proof for an asset issuance or transfer
// event. This method will return an error if the passed proof is invalid. If
// the leaf is already known, then no action is taken and the existing
// commitment proof returned.
func (a *Archive) UpsertProofLeaf(ctx context.Context, id Identifier,
	key LeafKey, leaf *Leaf) (*Proof, error) {

	log.Debugf("Inserting new proof into Universe: id=%v, base_key=%v",
		id.StringForLog(), spew.Sdump(key))

	// If universe proof type unspecified in universe ID, set based on the
	// provided asset proof.
	newAsset := leaf.Asset
	if id.ProofType == ProofTypeUnspecified {
		var err error
		id.ProofType, err = NewProofTypeFromAsset(newAsset)
		if err != nil {
			return nil, err
		}
	}

	// Ensure the proof is of the correct type for the target universe.
	err := ValidateProofUniverseType(newAsset, id)
	if err != nil {
		return nil, err
	}

	// We need to decode the new proof now.
	var newProof proof.Proof
	if err := newProof.Decode(bytes.NewReader(leaf.RawProof)); err != nil {
		return nil, err
	}

	// We'll first check to see if we already know of this leaf within the
	// multiverse. If so, then we'll return the existing issuance proof.
	issuanceProofs, err := a.cfg.Multiverse.FetchProofLeaf(ctx, id, key)
	switch {
	case err == nil && len(issuanceProofs) > 0:
		issuanceProof := issuanceProofs[0]

		var existingProof proof.Proof
		if err := existingProof.Decode(bytes.NewReader(
			issuanceProof.Leaf.RawProof,
		)); err != nil {
			return nil, err
		}

		// The only valid case for an update of a proof is if the mint
		// TX was re-organized out of the chain. If the block hash is
		// still the same, we don't see this as an update and just
		// return the existing proof.
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
	prevAssetSnapshot, err := a.getPrevAssetSnapshot(
		ctx, id, newAsset, nil,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch previous asset "+
			"snapshot: %w", err)
	}

	assetSnapshot, err := a.verifyIssuanceProof(
		ctx, id, key, &newProof, prevAssetSnapshot,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to verify proof: %w", err)
	}

	// Now that we know the proof is valid, we'll insert it into the base
	// multiverse backend, and return the new issuance proof.
	issuanceProof, err := a.cfg.Multiverse.UpsertProofLeaf(
		ctx, id, key, leaf, assetSnapshot.MetaReveal,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to register new "+
			"issuance: %w", err)
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
func (a *Archive) verifyIssuanceProof(ctx context.Context, id Identifier,
	key LeafKey, newProof *proof.Proof,
	prevAssetSnapshot *proof.AssetSnapshot) (*proof.AssetSnapshot, error) {

	assetSnapshot, err := newProof.Verify(
		ctx, prevAssetSnapshot, a.cfg.HeaderVerifier,
		a.cfg.MerkleVerifier, a.cfg.GroupVerifier,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to verify proof: %w", err)
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

// extractBatchDeps constructs map from leaf key to asset in a batch. This is
// useful for when we're validating an asset state transition in a batch, and
// the input asset it depends on is created in the batch.
func extractBatchDeps(batch []*Item) map[UniverseKey]*asset.Asset {
	batchDeps := make(map[UniverseKey]*asset.Asset)
	for _, item := range batch {
		batchDeps[item.Key.UniverseKey()] = item.Leaf.Asset
	}

	return batchDeps
}

// UpsertProofLeafBatch inserts a batch of proof leaves within the target
// universe tree. We assume the proofs within the batch have already been
// checked that they don't yet exist in the local database.
func (a *Archive) UpsertProofLeafBatch(ctx context.Context,
	items []*Item) error {

	log.Infof("Verifying %d new proofs for insertion into Universe",
		len(items))

	// Issuances that also create an asset group, group anchors, must be
	// verified and stored before any issuances that may be reissuances into
	// the same asset group. This is required for proper verification of
	// reissuances, which may be in this batch.
	var anchorItems []*Item
	nonAnchorItems := make([]*Item, 0, len(items))
	assetProofs := make(map[LeafKey]*proof.Proof)
	for ind := range items {
		item := items[ind]

		// If unspecified, set universe ID proof type based on leaf
		// proof type.
		if item.ID.ProofType == ProofTypeUnspecified {
			var err error
			item.ID.ProofType, err = NewProofTypeFromAsset(
				item.Leaf.Asset,
			)
			if err != nil {
				return err
			}
		}

		// Ensure that the target universe ID proof type corresponds to
		// the leaf proof type.
		err := ValidateProofUniverseType(item.Leaf.Asset, item.ID)
		if err != nil {
			return err
		}

		// At this point, we'll need to decode the proof so we can
		// partition it below.
		var assetProof proof.Proof
		err = assetProof.Decode(bytes.NewReader(item.Leaf.RawProof))
		if err != nil {
			return fmt.Errorf("unable to decode proof: %w", err)
		}

		assetProofs[item.Key] = &assetProof

		// Any group anchor issuance proof must have a group key reveal
		// attached, so that can be used to partition anchor assets and
		// non-anchor assets.
		switch {
		case assetProof.GroupKeyReveal != nil:
			anchorItems = append(anchorItems, item)
		default:
			nonAnchorItems = append(nonAnchorItems, item)
		}
	}

	batchDeps := extractBatchDeps(items)

	verifyBatch := func(batchItems []*Item) error {
		err := fn.ParSlice(
			ctx, batchItems, func(ctx context.Context,
				i *Item) error {

				prevAssets, err := a.getPrevAssetSnapshot(
					ctx, i.ID, i.Leaf.Asset, batchDeps,
				)
				if err != nil {
					return fmt.Errorf("unable to "+
						"fetch previous asset "+
						"snapshot: %w", err)
				}

				assetProof, ok := assetProofs[i.Key]
				if !ok {
					return fmt.Errorf("missing proof "+
						"for key=%v", i.Key)
				}

				assetSnapshot, err := a.verifyIssuanceProof(
					ctx, i.ID, i.Key, assetProof, prevAssets,
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
	err = a.cfg.Multiverse.UpsertProofLeafBatch(ctx, anchorItems)
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
	err = a.cfg.Multiverse.UpsertProofLeafBatch(ctx, nonAnchorItems)
	if err != nil {
		return fmt.Errorf("unable to register new issuance proofs: %w",
			err)
	}

	// Log a sync event for the newly inserted leaf in the background as an
	// async goroutine.
	ids := fn.Map(items, func(item *Item) Identifier {
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

// UniverseKey represents the key used to locate an item within a universe.
type UniverseKey [32]byte

// getPrevAssetSnapshot returns the previous asset snapshot for the passed
// proof. If the proof is a genesis proof, then nil is returned.
func (a *Archive) getPrevAssetSnapshot(ctx context.Context,
	uniID Identifier, newAsset *asset.Asset,
	batchAssets map[UniverseKey]*asset.Asset) (*proof.AssetSnapshot, error) {

	// If this is a genesis proof, then there is no previous asset (and
	// therefore no previous asset snapshot).
	if newAsset.IsGenesisAsset() {
		return nil, nil
	}

	// Query for proof associated with the previous asset.
	prevID, err := newAsset.PrimaryPrevID()
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
			"script key: %w", err)
	}
	prevScriptKey := asset.NewScriptKey(prevScriptKeyPubKey)

	prevLeafKey := LeafKey{
		OutPoint:  prevID.OutPoint,
		ScriptKey: &prevScriptKey,
	}

	// First, we'll check if the prev asset that we need is already amongst
	// the batch we have, if so then we won't have it in our universe tree
	// yet, so we'll return it directly.
	if batchAssets != nil {
		newScriptKey := newAsset.ScriptKey.PubKey.SerializeCompressed()

		inputAsset, ok := batchAssets[prevLeafKey.UniverseKey()]
		if ok {
			log.Debugf("script_key=%x spends item in batch, "+
				"universe_key=%x using batch input",
				newScriptKey, prevLeafKey.UniverseKey())

			return &proof.AssetSnapshot{
				Asset:    inputAsset,
				OutPoint: prevID.OutPoint,
			}, nil
		}
	}

	// If we can't find the previous asset in the batch, then we'll query
	// our local universe.
	prevProofs, err := a.cfg.Multiverse.FetchProofLeaf(
		ctx, uniID, prevLeafKey,
	)

	// If we've failed in finding the previous proof in the transfer
	// universe, we will try to find it in the issuance universe.
	if uniID.ProofType == ProofTypeTransfer &&
		errors.Is(err, ErrNoUniverseProofFound) {

		uniID.ProofType = ProofTypeIssuance
		prevProofs, err = a.cfg.Multiverse.FetchProofLeaf(
			ctx, uniID, prevLeafKey,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("unable to fetch previous "+
			"proof: %v, id=%v, leaf_key=%v, new_script_key=%x", err,
			spew.Sdump(uniID), spew.Sdump(prevLeafKey),
			newAsset.ScriptKey.PubKey.SerializeCompressed())
	}

	prevAsset := prevProofs[0].Leaf.Asset

	// TODO(roasbeef): need more than one snapshot, for inputs

	// Construct minimal asset snapshot for previous asset.
	// This is a minimal the proof verification result for the
	// previous (input) asset. We know that it was already verified
	// as it was present in the multiverse/universe archive.
	return &proof.AssetSnapshot{
		Asset:    prevAsset,
		OutPoint: prevID.OutPoint,
	}, nil
}

// FetchProofLeaf attempts to fetch a proof leaf for the target leaf key
// and given a universe identifier (assetID/groupKey).
func (a *Archive) FetchProofLeaf(ctx context.Context, id Identifier,
	key LeafKey) ([]*Proof, error) {

	log.Tracef("Retrieving Universe proof for: id=%v, base_key=%v",
		id.StringForLog(), spew.Sdump(key))

	return a.cfg.Multiverse.FetchProofLeaf(ctx, id, key)
}

type UniverseLeafKeysQuery struct {
	Id            Identifier
	SortDirection SortDirection
	Offset        int32
	Limit         int32
}

// UniverseLeafKeys returns the set of leaf keys known for the specified
// universe identifier.
func (a *Archive) UniverseLeafKeys(ctx context.Context,
	q UniverseLeafKeysQuery) ([]LeafKey, error) {

	log.Debugf("Retrieving all keys for Universe: id=%v", q.Id.StringForLog())

	return a.cfg.Multiverse.UniverseLeafKeys(ctx, q)
}

// MintingLeaves returns the set of minting leaves known for the specified base
// universe.
func (a *Archive) MintingLeaves(ctx context.Context,
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
func (a *Archive) DeleteRoot(ctx context.Context,
	id Identifier) (string, error) {

	log.Debugf("Deleting universe tree for Universe: id=%v", id.String())

	uniStr, err := a.cfg.Multiverse.DeleteUniverse(ctx, id)
	if err != nil {
		log.Tracef("Failed to delete universe tree: %w", err)
	}

	return uniStr, err
}
