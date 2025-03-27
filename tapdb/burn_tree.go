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

// burnSpecifierToIdentifier converts an asset.Specifier into a
// universe.Identifier for the burn tree.
func burnSpecifierToIdentifier(spec asset.Specifier) (universe.Identifier,
	error) {

	var id universe.Identifier

	// The specifier must have a group key to be able to be used within the
	// ignore tree context.
	if !spec.HasGroupPubKey() {
		return id, fmt.Errorf("group key must be set")
	}

	id.GroupKey = spec.UnwrapGroupKeyToPtr()
	id.ProofType = universe.ProofTypeBurn

	return id, nil
}

// Sum returns the sum of the burn leaves for the given asset.
func (bt *BurnUniverseTree) Sum(ctx context.Context,
	spec asset.Specifier) universe.BurnTreeSum {

	// Derive identifier from the asset.Specifier.
	id, err := burnSpecifierToIdentifier(spec)
	if err != nil {
		return lfn.Err[lfn.Option[uint64]](err)
	}
	namespace := id.String()

	var sumOpt lfn.Option[uint64]

	readTx := NewBaseUniverseReadTx()
	txErr := bt.db.ExecTx(ctx, &readTx, func(db BaseUniverseStore) error {
		tree := mssmt.NewCompactedTree(
			newTreeStoreWrapperTx(db, namespace),
		)

		// Get the root of the tree to retrieve the sum.
		root, err := tree.Root(ctx)
		if err != nil {
			return err
		}

		// If root is empty, return empty sum.
		if root.NodeHash() == mssmt.EmptyTreeRootHash {
			return nil
		}

		// Return the sum from the root.
		sumOpt = lfn.Some(root.NodeSum())

		return nil
	})
	if txErr != nil {
		return lfn.Err[lfn.Option[uint64]](txErr)
	}

	return lfn.Ok(sumOpt)
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
	id, err := burnSpecifierToIdentifier(spec)
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
		insertedProofs := make(
			map[universe.LeafKey]*universe.Proof, len(burnLeaves),
		)

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

			insertedProofs[leafKey] = uniProof
		}

		// Now, construct the AuthenticatedBurnLeaf results.
		for _, burnLeaf := range burnLeaves {
			uniProof, ok := insertedProofs[burnLeaf.UniverseKey]
			if !ok {
				// This should not happen if the loop above
				// succeeded.
				return fmt.Errorf("internal error: proof "+
					"not found for key %v",
					burnLeaf.UniverseKey)
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

// QueryBurns attempts to query a set of burn leaves for the given asset
// specifier. If the burn leaf points are empty, then all burn leaves are
// returned.
func (bt *BurnUniverseTree) QueryBurns(ctx context.Context,
	spec asset.Specifier,
	burnPoints ...wire.OutPoint) universe.BurnLeafQueryResp {

	// Derive identifier from the asset.Specifier.
	id, err := burnSpecifierToIdentifier(spec)
	if err != nil {
		return lfn.Err[lfn.Option[[]*universe.AuthenticatedBurnLeaf]](
			err,
		)
	}
	namespace := id.String()

	var resultLeaves []*universe.AuthenticatedBurnLeaf

	readTx := NewBaseUniverseReadTx()
	txErr := bt.db.ExecTx(ctx, &readTx, func(db BaseUniverseStore) error {
		// Create the tree within the transaction for getting root and
		// proofs.
		tree := mssmt.NewCompactedTree(
			newTreeStoreWrapperTx(db, namespace),
		)

		// Get the tree root once for all queries. Handle the case
		// where the tree might be empty.
		root, err := tree.Root(ctx)
		if err != nil {
			return err
		}

		var leavesToQuery []UniverseLeaf

		switch {
		// If specific burn points are provided, query for each of them.
		case len(burnPoints) > 0:
			for _, burnPoint := range burnPoints {
				burnPointBytes, err := encodeOutpoint(burnPoint)
				if err != nil {
					return fmt.Errorf("unable to encode "+
						"burn point %v: %w", burnPoint,
						err)
				}

				// Query leaves matching the burn point and
				// namespace. ScriptKeyBytes is nil here as we
				// want all script keys for this burn point.
				dbLeaves, err := db.QueryUniverseLeaves(
					ctx, UniverseLeafQuery{
						MintingPointBytes: burnPointBytes, //nolint:lll
						Namespace:         namespace,
					},
				)
				if err != nil {
					// If no rows found for a specific
					// point, continue to the next.
					if errors.Is(err, sql.ErrNoRows) {
						continue
					}
					return fmt.Errorf("error querying "+
						"leaves for burn point %v: %w",
						burnPoint, err)
				}

				if len(dbLeaves) == 0 {
					continue
				}

				leavesToQuery = append(
					leavesToQuery, dbLeaves...,
				)
			}
		// If no specific points, query all leaves in the namespace.
		default:
			dbLeaves, err := db.QueryUniverseLeaves(
				ctx, UniverseLeafQuery{
					Namespace: namespace,
				},
			)

			// It's okay if no leaves are found in the namespace.
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("error querying all "+
					"leaves for namespace %s: %w",
					namespace, err)
			}
			leavesToQuery = dbLeaves
		}

		// Process the found leaves. We'll generate the inclusion proof
		// for each leaf, and then construct the final authenticated
		// resp.
		for _, dbLeaf := range leavesToQuery {
			// Decode the stored proof blob.
			var burnProof proof.Proof
			err = burnProof.Decode(
				bytes.NewReader(dbLeaf.GenesisProof),
			)
			if err != nil {
				return fmt.Errorf("unable to decode burn "+
					"proof: %w", err)
			}

			// Reconstruct the LeafKey used for SMT insertion.
			scriptPub, err := schnorr.ParsePubKey(
				dbLeaf.ScriptKeyBytes,
			)
			if err != nil {
				return fmt.Errorf("unable to parse script "+
					"key: %w", err)
			}
			scriptKey := asset.NewScriptKey(scriptPub)

			leafKey := universe.LeafKey{
				OutPoint:  burnProof.OutPoint(),
				ScriptKey: &scriptKey,
			}
			smtKey := leafKey.UniverseKey()

			// Generate the inclusion proof.
			inclusionProof, err := tree.MerkleProof(ctx, smtKey)
			if err != nil {
				return fmt.Errorf("error generating proof "+
					"for smt key %x: %w", smtKey, err)
			}

			// Construct the final authenticated leaf.
			authLeaf := &universe.AuthenticatedBurnLeaf{
				BurnLeaf: &universe.BurnLeaf{
					UniverseKey: leafKey,
					BurnProof:   &burnProof,
				},
				BurnTreeRoot: root,
				BurnProof:    inclusionProof,
			}
			resultLeaves = append(resultLeaves, authLeaf)
		}

		return nil
	})
	if txErr != nil {
		return lfn.Err[lfn.Option[[]*universe.AuthenticatedBurnLeaf]](
			txErr,
		)
	}

	if len(resultLeaves) == 0 {
		return lfn.Ok(lfn.None[[]*universe.AuthenticatedBurnLeaf]())
	}

	return lfn.Ok(lfn.Some(resultLeaves))
}

// ListBurns attempts to list all burn leaves for the given asset.
func (bt *BurnUniverseTree) ListBurns(ctx context.Context,
	spec asset.Specifier) universe.ListBurnsResp {

	// Derive identifier from the asset.Specifier.
	id, err := burnSpecifierToIdentifier(spec)
	if err != nil {
		return lfn.Err[lfn.Option[[]*universe.BurnDesc]](err)
	}
	namespace := id.String()

	var burnDescs []*universe.BurnDesc

	readTx := NewBaseUniverseReadTx()
	txErr := bt.db.ExecTx(ctx, &readTx, func(db BaseUniverseStore) error {
		// Query all leaves in the namespace.
		universeLeaves, err := db.QueryUniverseLeaves(
			ctx, UniverseLeafQuery{
				Namespace: namespace,
			},
		)

		// If no leaves are found, then we'll just return an empty list.
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil
		}

		for _, dbLeaf := range universeLeaves {
			var burnProof proof.Proof
			err = burnProof.Decode(
				bytes.NewReader(dbLeaf.GenesisProof),
			)
			if err != nil {
				return fmt.Errorf("unable to decode burn "+
					"proof: %w", err)
			}

			// Extract information for BurnDesc.
			assetSpec := burnProof.Asset.Specifier()
			amt := burnProof.Asset.Amount
			burnPoint := burnProof.OutPoint()

			burnDescs = append(burnDescs, &universe.BurnDesc{
				AssetSpec: assetSpec,
				Amt:       amt,
				BurnPoint: burnPoint,
			})
		}

		return nil
	})
	if txErr != nil {
		return lfn.Err[lfn.Option[[]*universe.BurnDesc]](txErr)
	}

	if len(burnDescs) == 0 {
		return lfn.Ok(lfn.None[[]*universe.BurnDesc]())
	}

	return lfn.Ok(lfn.Some(burnDescs))
}

// Compile-time assertion to ensure BurnUniverseTree implements the
// universe.BurnTree interface.
var _ universe.BurnTree = (*BurnUniverseTree)(nil)
