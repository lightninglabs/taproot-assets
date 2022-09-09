package tarodb

import (
	"bytes"
	"context"
	"math/rand"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/commitment"
	"github.com/lightninglabs/taro/mssmt"
	"github.com/lightninglabs/taro/proof"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

func randOp(t *testing.T) wire.OutPoint {
	op := wire.OutPoint{
		Index: uint32(randInt[int32]()),
	}
	_, err := rand.Read(op.Hash[:])
	require.NoError(t, err)

	return op
}

func randGenesis(t *testing.T, assetType asset.Type) *asset.Genesis {
	metadata := make([]byte, randInt[int]()%32+1)
	_, err := rand.Read(metadata)
	require.NoError(t, err)

	return &asset.Genesis{
		FirstPrevOut: randOp(t),
		Tag:          "kek",
		Metadata:     metadata,
		OutputIndex:  uint32(randInt[int32]()),
		Type:         assetType,
	}
}

func randPrivKey(t *testing.T) *btcec.PrivateKey {
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	return privKey
}

func randPubKey(t *testing.T) *btcec.PublicKey {
	return randPrivKey(t).PubKey()
}

func randAssetID(t *testing.T) asset.ID {
	var a asset.ID
	_, err := rand.Read(a[:])
	require.NoError(t, err)

	return a
}

func randWitnesses(t *testing.T) wire.TxWitness {
	numElements := randInt[int]() % 5
	if numElements == 0 {
		return nil
	}

	w := make(wire.TxWitness, numElements)
	for i := 0; i < numElements; i++ {
		elem := make([]byte, 10)
		_, err := rand.Read(elem)
		require.NoError(t, err)

		w[i] = elem
	}

	return w
}

func randSplitCommit(t *testing.T,
	asset asset.Asset) *asset.SplitCommitment {

	// 50/50 chance there's no commitment at all.
	if randInt[int]()%2 == 0 {
		return nil
	}

	rootLoc := commitment.SplitLocator{
		OutputIndex: uint32(randInt[int32]()),
		AssetID:     randAssetID(t),
		Amount:      asset.Amount / 2,
		ScriptKey:   *randPubKey(t),
	}
	splitLoc := commitment.SplitLocator{
		OutputIndex: uint32(randInt[int32]()),
		AssetID:     randAssetID(t),
		Amount:      asset.Amount / 2,
		ScriptKey:   *randPubKey(t),
	}

	split, err := commitment.NewSplitCommitment(
		&asset, randOp(t), &rootLoc, &splitLoc,
	)
	require.NoError(t, err)

	assetSplit := split.SplitAssets[splitLoc].PrevWitnesses[0]

	return assetSplit.SplitCommitment
}

func randAsset(t *testing.T) *asset.Asset {
	genesis := randGenesis(t, asset.Normal)

	famPriv := randPrivKey(t)
	genSigner := asset.NewRawKeyGenesisSigner(famPriv)

	famKey, sig, err := genSigner.SignGenesis(
		keychain.KeyDescriptor{
			PubKey: famPriv.PubKey(),
		}, *genesis,
	)
	require.NoError(t, err)

	newAsset := &asset.Asset{
		Genesis:          *genesis,
		Amount:           uint64(randInt[uint32]()),
		LockTime:         uint64(randInt[int32]()),
		RelativeLockTime: uint64(randInt[int32]()),
		ScriptKey: keychain.KeyDescriptor{
			PubKey: randPubKey(t),
			KeyLocator: keychain.KeyLocator{
				Family: randInt[keychain.KeyFamily](),
				Index:  uint32(randInt[int32]()),
			},
		},
	}
	// 50/50 chance that we'll actually have a family key.
	if randInt[int]()%2 == 0 {
		newAsset.FamilyKey = &asset.FamilyKey{
			RawKey: keychain.KeyDescriptor{
				PubKey: famKey,
			},
			FamKey: *famKey,
			Sig:    *sig,
		}
	}

	// Go with an even amount to make the splits always work nicely.
	if newAsset.Amount%2 != 0 {
		newAsset.Amount++
	}

	// For the witnesses, we'll flip a coin: we'll either make a genesis
	// witness, or a set of actual witnesses.
	var witnesses []asset.Witness
	if randInt[int]()%2 == 0 {
		witnesses = append(witnesses, asset.Witness{
			PrevID:          &asset.PrevID{},
			TxWitness:       nil,
			SplitCommitment: nil,
		})
	} else {
		numWitness := randInt[int]() % 10
		witnesses = make([]asset.Witness, numWitness)
		for i := 0; i < numWitness; i++ {
			witnesses[i] = asset.Witness{
				PrevID: &asset.PrevID{
					OutPoint:  randOp(t),
					ID:        randAssetID(t),
					ScriptKey: *randPubKey(t),
				},
				TxWitness: randWitnesses(t),
				// For simplicity we just use the base asset itself as
				// the "anchor" asset in the split commitment.
				SplitCommitment: randSplitCommit(t, *newAsset),
			}
		}
	}

	newAsset.PrevWitnesses = witnesses

	return newAsset
}

func assetWitnessEqual(t *testing.T, a, b []asset.Witness) {
	require.Equal(t, len(a), len(b))

	for i := 0; i < len(a); i++ {
		witA := a[i]
		witB := b[i]

		require.Equal(t, witA.PrevID, witB.PrevID)
		require.Equal(t, witA.TxWitness, witB.TxWitness)

		require.Equal(
			t, witA.SplitCommitment == nil, witB.SplitCommitment == nil,
		)

		if witA.SplitCommitment != nil {
			var bufA, bufB bytes.Buffer

			err := witA.SplitCommitment.RootAsset.Encode(&bufA)
			require.NoError(t, err)

			err = witB.SplitCommitment.RootAsset.Encode(&bufB)
			require.NoError(t, err)

			require.Equal(t, bufA.Bytes(), bufB.Bytes())

			splitA := witA.SplitCommitment
			splitB := witB.SplitCommitment
			require.Equal(
				t, len(splitA.Proof.Nodes), len(splitB.Proof.Nodes),
			)
			for i := range splitA.Proof.Nodes {
				nodeA := splitA.Proof.Nodes[i]
				nodeB := splitB.Proof.Nodes[i]
				require.True(t, mssmt.IsEqualNode(nodeA, nodeB))
			}
		}
	}
}

// TestImportAssetProof tests that given a valid asset proof (mainly the final
// snapshot information), we're able to properly import all the components on
// disk, then retrieve the asset as if it were ours.
func TestImportAssetProof(t *testing.T) {
	t.Parallel()

	// First, we'll create a new instance of the database.
	_, assetStore, db := newAssetStore(t)

	// Next, we'll make a new random asset that also has a few inputs with
	// dummy witness information.
	testAsset := randAsset(t)

	assetRoot, err := commitment.NewAssetCommitment(testAsset)
	require.NoError(t, err)

	taroRoot, err := commitment.NewTaroCommitment(assetRoot)
	require.NoError(t, err)

	// With our asset created, we can now create the AnnotatedProof we use
	// to import assets into the database.
	var blockHash chainhash.Hash
	_, err = rand.Read(blockHash[:])
	require.NoError(t, err)

	anchorTx := wire.NewMsgTx(2)
	anchorTx.AddTxIn(&wire.TxIn{})
	anchorTx.AddTxOut(&wire.TxOut{
		PkScript: bytes.Repeat([]byte{0x01}, 34),
		Value:    10,
	})

	assetID := testAsset.ID()
	anchorPoint := wire.OutPoint{
		Hash:  anchorTx.TxHash(),
		Index: 0,
	}
	proof := &proof.AnnotatedProof{
		Locator: proof.Locator{
			AssetID:   &assetID,
			ScriptKey: *testAsset.ScriptKey.PubKey,
		},
		Blob: bytes.Repeat([]byte{0x0}, 100),
		AssetSnapshot: &proof.AssetSnapshot{
			Asset:             testAsset,
			OutPoint:          anchorPoint,
			AnchorBlockHash:   blockHash,
			AnchorBlockHeight: randInt[uint32](),
			AnchorTxIndex:     randInt[uint32](),
			AnchorTx:          anchorTx,
			OutputIndex:       0,
			InternalKey:       randPubKey(t),
			ScriptRoot:        taroRoot,
		},
	}
	if testAsset.FamilyKey != nil {
		proof.FamilyKey = &testAsset.FamilyKey.FamKey
	}

	// We'll now insert the internal key information as well as the script
	// key ahead of time to reflect the address creation that happens
	// elsewhere.
	ctx := context.Background()
	_, err = db.UpsertInternalKey(ctx, InternalKey{
		RawKey:    proof.InternalKey.SerializeCompressed(),
		KeyFamily: randInt[int32](),
		KeyIndex:  randInt[int32](),
	})
	require.NoError(t, err)
	_, err = db.UpsertInternalKey(ctx, InternalKey{
		RawKey:    testAsset.ScriptKey.PubKey.SerializeCompressed(),
		KeyFamily: int32(testAsset.ScriptKey.Family),
		KeyIndex:  int32(testAsset.ScriptKey.Index),
	})
	require.NoError(t, err)

	// We'll add the chain transaction of the proof now to simulate a
	// batched transfer on a higher layer.
	var anchorTxBuf bytes.Buffer
	err = proof.AnchorTx.Serialize(&anchorTxBuf)
	require.NoError(t, err)
	anchorTXID := proof.AnchorTx.TxHash()
	_, err = db.UpsertChainTx(ctx, ChainTx{
		Txid:        anchorTXID[:],
		RawTx:       anchorTxBuf.Bytes(),
		BlockHeight: sqlInt32(proof.AnchorBlockHeight),
		BlockHash:   proof.AnchorBlockHash[:],
		TxIndex:     sqlInt32(proof.AnchorTxIndex),
	})
	require.NoError(t, err, "unable to insert chain tx: %w", err)

	// With all our test data constructed, we'll now attempt to import the
	// asset into the database.
	require.NoError(t, assetStore.ImportProofs(context.Background(), proof))

	// We should now be able to retrieve the set of all assets inserted on
	// disk.
	assets, err := assetStore.FetchAllAssets(context.Background(), nil)
	require.NoError(t, err)
	require.Len(t, assets, 1)

	// The DB asset should match the asset we inserted exactly.
	dbAsset := assets[0]

	// Before comparison, we unset the split commitments so we can compare
	// them directly.
	assetWitnessEqual(t, testAsset.PrevWitnesses, dbAsset.PrevWitnesses)

	dbAsset.PrevWitnesses = nil
	testAsset.PrevWitnesses = nil

	require.Equal(t, testAsset, dbAsset.Asset)

	// Finally, we'll verify all the anchor information that was inserted
	// on disk.
	require.Equal(t, proof.AnchorBlockHash, dbAsset.AnchorBlockHash)
	require.Equal(t, proof.OutPoint, dbAsset.AnchorOutpoint)
	require.Equal(t, proof.AnchorTx.TxHash(), dbAsset.AnchorTx.TxHash())
}

// TestInternalKeyUpsert tests that if we insert an internal key that's a
// duplicate, it works and we get the primary key of the key that was already
// inserted.
func TestInternalKeyUpsert(t *testing.T) {
	t.Parallel()

	// First, we'll create a new instance of the database.
	_, _, db := newAssetStore(t)

	testKey := randPubKey(t)

	// Now we'll insert two internal keys that are the same. We should get
	// the same response back (the primary key) for both of them.
	ctx := context.Background()
	k1, err := db.UpsertInternalKey(ctx, InternalKey{
		RawKey:    testKey.SerializeCompressed(),
		KeyFamily: 1,
		KeyIndex:  2,
	})
	require.NoError(t, err)

	k2, err := db.UpsertInternalKey(ctx, InternalKey{
		RawKey:    testKey.SerializeCompressed(),
		KeyFamily: 1,
		KeyIndex:  2,
	})
	require.NoError(t, err)

	require.Equal(t, k1, k2)
}
