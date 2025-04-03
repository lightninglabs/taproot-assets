package tapdb

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/universe"

	lfn "github.com/lightningnetwork/lnd/fn/v2"
)

// BurnUniverseTree is a structure that holds the DB for burn operations.
type BurnUniverseTree struct {
	db BatchedUniverseTree
}

// NewBurnUniverseTree returns a new BurnUniverseTree with the target DB.
func NewBurnUniverseTree(db BatchedUniverseTree) *BurnUniverseTree {
	return &BurnUniverseTree{db: db}
}

// Sum returns the sum of the burn leaves for the given asset.
func (bt *BurnUniverseTree) Sum(ctx context.Context,
	spec asset.Specifier) universe.BurnTreeSum {

	// Derive identifier from the asset.Specifier.
	id, err := specifierToIdentifier(spec, universe.ProofTypeBurn)
	if err != nil {
		return lfn.Err[lfn.Option[uint64]](err)
	}

	// Use the generic helper to get the sum.
	return getUniverseTreeSum(ctx, bt.db, id)
}

// ErrNotBurn is returned when a proof is not a burn proof.
var ErrNotBurn = errors.New("not a burn proof")

// InsertBurns attempts to insert a set of new burn leaves into the burn tree
// identified by the passed asset.Specifier. If a given proof isn't a true burn
// proof, then an error is returned. This check is performed upfront. If the
// proof is valid, then the burn leaf is inserted into the tree, with a new
// merkle proof returned.
func (bt *BurnUniverseTree) InsertBurns(ctx context.Context,
	spec asset.Specifier,
	burnLeaves ...*universe.BurnLeaf) universe.BurnLeafResp {

	if len(burnLeaves) == 0 {
		return lfn.Err[[]*universe.AuthenticatedBurnLeaf](
			fmt.Errorf("no burn leaves provided"),
		)
	}

	// Derive identifier (and thereby the namespace) from the
	// asset.Specifier.
	id, err := specifierToIdentifier(spec, universe.ProofTypeBurn)
	if err != nil {
		return lfn.Err[[]*universe.AuthenticatedBurnLeaf](err)
	}

	// Perform upfront validation for all proofs. Make sure that all the
	// assets are actually burns.
	for _, burnLeaf := range burnLeaves {
		if !burnLeaf.BurnProof.Asset.IsBurn() {
			return lfn.Err[[]*universe.AuthenticatedBurnLeaf](
				fmt.Errorf("%w: proof for asset %v is not a "+
					"burn proof, has type %v",
					ErrNotBurn,
					burnLeaf.BurnProof.Asset.ID(),
					burnLeaf.BurnProof.Asset.Type),
			)
		}
	}

	var finalResults []*universe.AuthenticatedBurnLeaf

	var writeTx BaseUniverseStoreOptions
	txErr := bt.db.ExecTx(ctx, &writeTx, func(db BaseUniverseStore) error {
		for _, burnLeaf := range burnLeaves {
			leafKey := burnLeaf.UniverseKey

			// Encode the burn proof to get the raw bytes.
			var proofBuf bytes.Buffer
			err := burnLeaf.BurnProof.Encode(&proofBuf)
			if err != nil {
				return fmt.Errorf("unable to encode burn "+
					"proof: %w", err)
			}
			rawProofBytes := proofBuf.Bytes()

			// Construct the universe.Leaf required by
			// universeUpsertProofLeaf.
			burnProof := burnLeaf.BurnProof
			leaf := &universe.Leaf{
				GenesisWithGroup: universe.GenesisWithGroup{
					Genesis:  burnProof.Asset.Genesis,
					GroupKey: burnProof.Asset.GroupKey,
				},
				RawProof: rawProofBytes,
				Asset:    &burnLeaf.BurnProof.Asset,
				Amt:      burnLeaf.BurnProof.Asset.Amount,
			}

			// Call the generic upsert function. MetaReveal is nil
			// for burns, as this isn't an issuance instance. We
			// also skip inserting into the multi-verse tree for
			// now.
			uniProof, err := universeUpsertProofLeaf(
				ctx, db, id, leafKey, leaf, nil, true,
			)
			if err != nil {
				return fmt.Errorf("unable to upsert burn "+
					"leaf for key %v: %w", leafKey, err)
			}

			authLeaf := &universe.AuthenticatedBurnLeaf{
				BurnLeaf:     burnLeaf,
				BurnTreeRoot: uniProof.UniverseRoot,
				BurnProof:    uniProof.UniverseInclusionProof,
			}
			finalResults = append(finalResults, authLeaf)
		}

		return nil
	})
	if txErr != nil {
		return lfn.Err[[]*universe.AuthenticatedBurnLeaf](txErr)
	}

	return lfn.Ok(finalResults)
}

// queryBurnLeaves retrieves UniverseLeaf records based on burn OutPoints.
func queryBurnLeaves(ctx context.Context, dbtx BaseUniverseStore,
	spec asset.Specifier,
	burnPoints ...wire.OutPoint) ([]UniverseLeaf, error) {

	uniNamespace, err := specifierToIdentifier(
		spec, universe.ProofTypeBurn,
	)
	if err != nil {
		return nil, fmt.Errorf("error deriving identifier: %w", err)
	}

	namespace := uniNamespace.String()

	// If no burn points are provided, we query all leaves in the namespace.
	if len(burnPoints) == 0 {
		// If no specific points, query all leaves in the namespace.
		dbLeaves, err := dbtx.QueryUniverseLeaves(
			ctx, UniverseLeafQuery{
				Namespace: namespace,
			},
		)
		if errors.Is(err, sql.ErrNoRows) {
			// No leaves found is not an error in this case.
			return nil, sql.ErrNoRows
		}
		if err != nil {
			return nil, fmt.Errorf("error querying all leaves "+
				"for namespace %s: %w", &uniNamespace, err)
		}

		return dbLeaves, nil
	}

	// Otherwise, we'll query for leaves matching the burn points.
	var leavesToQuery []UniverseLeaf
	for _, burnPoint := range burnPoints {
		burnPointBytes, err := encodeOutpoint(burnPoint)
		if err != nil {
			return nil, fmt.Errorf("unable to encode burn "+
				"point %v: %w", burnPoint, err)
		}

		// Query leaves matching the burn point and namespace.
		// ScriptKeyBytes is nil here as we want all script keys for
		// this burn point.
		dbLeaves, err := dbtx.QueryUniverseLeaves(
			ctx, UniverseLeafQuery{
				MintingPointBytes: burnPointBytes,
				Namespace:         namespace,
			},
		)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("error querying leaves "+
				"for burn point %v: %w", burnPoint, err)
		}

		leavesToQuery = append(leavesToQuery, dbLeaves...)
	}

	if len(leavesToQuery) == 0 {
		// Return sql.ErrNoRows if no leaves were found.
		return nil, sql.ErrNoRows
	}

	return leavesToQuery, nil
}

// decodeAndBuildAuthBurnLeaf decodes the raw leaf, reconstructs the key, and
// builds the AuthenticatedBurnLeaf.
func decodeAndBuildAuthBurnLeaf(dbLeaf UniverseLeaf) (
	*universe.BurnLeaf, uniKey, error) {

	var burnProof proof.Proof
	err := burnProof.Decode(bytes.NewReader(dbLeaf.GenesisProof))
	if err != nil {
		return nil, uniKey{}, fmt.Errorf("unable to decode burn "+
			"proof: %w", err)
	}

	// Reconstruct the LeafKey used for SMT insertion.
	scriptPub, err := schnorr.ParsePubKey(dbLeaf.ScriptKeyBytes)
	if err != nil {
		return nil, uniKey{}, fmt.Errorf("unable to parse script "+
			"key: %w", err)
	}
	scriptKey := asset.NewScriptKey(scriptPub)

	leafKey := universe.AssetLeafKey{
		BaseLeafKey: universe.BaseLeafKey{
			OutPoint:  burnProof.OutPoint(),
			ScriptKey: &scriptKey,
		},
		AssetID: burnProof.Asset.ID(),
	}

	burnLeaf := &universe.BurnLeaf{
		UniverseKey: &leafKey,
		BurnProof:   &burnProof,
	}

	return burnLeaf, leafKey.UniverseKey(), nil
}

// buildAuthBurnLeaf constructs the final AuthenticatedBurnLeaf.
func buildAuthBurnLeaf(decodedLeaf *universe.BurnLeaf,
	inclusionProof *mssmt.Proof,
	root mssmt.Node) *universe.AuthenticatedBurnLeaf {

	return &universe.AuthenticatedBurnLeaf{
		BurnLeaf:     decodedLeaf,
		BurnTreeRoot: root,
		BurnProof:    inclusionProof,
	}
}

// QueryBurns attempts to query a set of burn leaves for the given asset
// specifier. If the burn leaf points are empty, then all burn leaves are
// returned.
func (bt *BurnUniverseTree) QueryBurns(ctx context.Context,
	spec asset.Specifier,
	burnPoints ...wire.OutPoint) universe.BurnLeafQueryResp {

	// Derive identifier from the asset.Specifier.
	id, err := specifierToIdentifier(spec, universe.ProofTypeBurn)
	if err != nil {
		return lfn.Err[lfn.Option[[]*universe.AuthenticatedBurnLeaf]](
			err,
		)
	}

	// Use the generic list helper to list the leaves from the universe
	// Tree. We pass in our custom decode function to handle the logic
	// specific to BurnLeaf.
	return queryUniverseLeavesAndProofs(
		ctx, bt.db, spec, id, queryBurnLeaves,
		decodeAndBuildAuthBurnLeaf, buildAuthBurnLeaf, burnPoints...,
	)
}

// decodeBurnDesc decodes the raw bytes into a BurnDesc.
func decodeBurnDesc(dbLeaf UniverseLeaf) (*universe.BurnDesc, error) {
	var burnProof proof.Proof
	err := burnProof.Decode(bytes.NewReader(dbLeaf.GenesisProof))
	if err != nil {
		return nil, fmt.Errorf("unable to decode burn proof: %w", err)
	}

	// Extract information for BurnDesc.
	assetSpec := burnProof.Asset.Specifier()
	amt := burnProof.Asset.Amount
	burnPoint := burnProof.OutPoint()

	return &universe.BurnDesc{
		AssetSpec: assetSpec,
		Amt:       amt,
		BurnPoint: burnPoint,
	}, nil
}

// ListBurns attempts to list all burn leaves for the given asset.
func (bt *BurnUniverseTree) ListBurns(ctx context.Context,
	spec asset.Specifier) universe.ListBurnsResp {

	// Derive identifier from the asset.Specifier.
	id, err := specifierToIdentifier(spec, universe.ProofTypeBurn)
	if err != nil {
		return lfn.Err[lfn.Option[[]*universe.BurnDesc]](err)
	}

	// Use the generic list helper.
	return listUniverseLeaves(ctx, bt.db, id, decodeBurnDesc)
}

// Compile-time assertion to ensure BurnUniverseTree implements the
// universe.BurnTree interface.
var _ universe.BurnTree = (*BurnUniverseTree)(nil)
