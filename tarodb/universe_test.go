package tarodb

import (
	"context"
	"database/sql"
	"math/rand"
	"reflect"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/chanutils"
	"github.com/lightninglabs/taro/internal/test"
	"github.com/lightninglabs/taro/mssmt"
	"github.com/lightninglabs/taro/tarodb/sqlc"
	"github.com/lightninglabs/taro/universe"
	"github.com/stretchr/testify/require"
)

func randUniverseID(t *testing.T) universe.Identifier {
	t.Helper()

	var id universe.Identifier
	_, err := rand.Read(id.AssetID[:])
	require.NoError(t, err)

	// 50/50 chance to also add a group key.
	if rand.Intn(2) == 0 {
		groupKey, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		id.GroupKey = groupKey.PubKey()
	}

	return id
}

func newTestUniverse(t *testing.T,
	id universe.Identifier) (*BaseUniverseTree, sqlc.Querier) {

	db := NewTestDB(t)

	dbTxer := NewTransactionExecutor[BaseUniverseStore](db,
		func(tx *sql.Tx) BaseUniverseStore {
			return db.WithTx(tx)
		},
	)

	return NewBaseUniverseTree(dbTxer, id), db
}

// TestUniverseEmptyTree...
func TestUniverseEmptyTree(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	id := randUniverseID(t)
	baseUniverse, _ := newTestUniverse(t, id)

	_, err := baseUniverse.RootNode(ctx)
	require.ErrorIs(t, err, ErrNoUniverseRoot)
}

func randBaseKey(t *testing.T) universe.BaseKey {
	return universe.BaseKey{
		MintingOutpoint: test.RandOp(t),
		ScriptKey: chanutils.Ptr(
			asset.NewScriptKey(test.RandPubKey(t)),
		),
	}
}

func randMintingLeaf(t *testing.T, assetGen asset.Genesis,
	groupKey *btcec.PublicKey) universe.MintingLeaf {

	var proof [200]byte
	_, err := rand.Read(proof[:])
	require.NoError(t, err)

	leaf := universe.MintingLeaf{
		GenesisWithGroup: universe.GenesisWithGroup{
			Genesis: assetGen,
		},
		GenesisProof: proof[:],
		Amt:          uint64(rand.Int31()),
	}
	if groupKey != nil {
		leaf.GroupKey = &asset.GroupKey{
			GroupPubKey: *groupKey,
		}
	}

	return leaf
}

// leaWithKey is a two tuple that associates new minting leaf with a key.
type leafWithKey struct {
	universe.BaseKey

	universe.MintingLeaf
}

// TestUniverseIssuanceProofs tests that we're able to insert issuance proofs
// for a given asset ID, and then retrieve them all with proper inclusion
// proofs.
func TestUniverseIssuanceProofs(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	id := randUniverseID(t)
	baseUniverse, _ := newTestUniverse(t, id)

	const numLeaves = 4

	// All the leaves will be under the same base universe tree, so we want
	// them to have the same asset ID.
	assetGen := asset.RandGenesis(t, asset.Normal)

	// We'll start by making a series of random minting key (outpoint,
	// scriptKey) leaf pairs.
	testLeaves := make([]leafWithKey, numLeaves)
	for i := 0; i < numLeaves; i++ {
		targetKey := randBaseKey(t)
		leaf := randMintingLeaf(t, assetGen, id.GroupKey)

		testLeaves[i] = leafWithKey{targetKey, leaf}
	}

	// Next, with each leaf and key created, we'll now attempt to add them
	// to the tree by registering the issuance event.
	var leafSum uint64
	for _, testLeaf := range testLeaves {
		// Each new leaf should add to the accumulated sum.
		leafSum += testLeaf.Amt

		targetKey := testLeaf.BaseKey
		leaf := testLeaf.MintingLeaf

		issuanceProof, err := baseUniverse.RegisterIssuance(
			ctx, targetKey, &leaf,
		)
		require.NoError(t, err)

		// The root should now reflect a proper sum value.
		rootNode, err := baseUniverse.RootNode(ctx)
		require.NoError(t, err)
		require.Equal(t, leafSum, rootNode.NodeSum())

		// The root returned in the proof should match the one we just
		// fetched.
		require.True(
			t,
			mssmt.IsEqualNode(rootNode, issuanceProof.UniverseRoot),
		)

		// We should be able to verify the issuance proof given the
		// root of the SMT.
		proofRoot := issuanceProof.InclusionProof.Root(
			targetKey.UniverseKey(), leaf.SmtLeafNode(),
		)
		require.True(t, mssmt.IsEqualNode(rootNode, proofRoot))

		// We should be able to fetch the issuance proof now, using
		// that very same target key generated.
		dbProof, err := baseUniverse.FetchIssuanceProof(ctx, targetKey)
		require.NoError(t, err)

		uniProof := dbProof[0]

		// The proof should have the proper values populated.
		require.Equal(t, targetKey, uniProof.MintingKey)
		require.True(t, mssmt.IsEqualNode(rootNode, uniProof.UniverseRoot))

		// The issuance proof we obtained should have a valid inclusion
		// proof.
		dbProofRoot := uniProof.InclusionProof.Root(
			uniProof.MintingKey.UniverseKey(),
			uniProof.Leaf.SmtLeafNode(),
		)
		require.True(
			t, mssmt.IsEqualNode(uniProof.UniverseRoot, dbProofRoot),
		)
	}

	// Next, we'll query for all the available keys, this should match the
	// number of insertions we just did.
	mintingKeys, err := baseUniverse.MintingKeys(ctx)
	require.NoError(t, err)
	require.Equal(t, numLeaves, len(mintingKeys))

	// The set of leaves we created above should match what was returned.
	require.True(t, chanutils.All(mintingKeys, func(key universe.BaseKey) bool {
		for _, testLeaf := range testLeaves {
			if reflect.DeepEqual(key, testLeaf.BaseKey) {
				return true
			}
		}

		return false
	}))

	// Finally, we should be able to query for the complete set of leaves,
	// which matches what we inserted above.
	dbLeaves, err := baseUniverse.MintingLeaves(ctx)
	require.NoError(t, err)
	require.Equal(t, numLeaves, len(dbLeaves))
	require.True(t, chanutils.All(dbLeaves, func(leaf universe.MintingLeaf) bool {
		for _, testLeaf := range testLeaves {
			if leaf.Genesis.ID() == testLeaf.MintingLeaf.Genesis.ID() {
				return true
			}
		}
		return false
	}))
}

// TODO(roasbeef): query tests for the set of leaves: all leaves, just by script key, etc

// TODO(roasbeef): isolation tests
//  * several diff leaves of diff asset IDs
//  * able to get them all ,etc
