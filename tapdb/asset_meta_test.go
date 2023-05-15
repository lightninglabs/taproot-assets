package tapdb

import (
	"context"
	"math/rand"
	"testing"

	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/stretchr/testify/require"
)

// TestAssetMetaUpsert tests that we can properly replace the on disk blob for
// a given asset meta.
func TestAssetMetaUpsert(t *testing.T) {
	t.Parallel()

	_, _, db := newAssetStore(t)

	var metaBlob [100]byte
	_, err := rand.Read(metaBlob[:])
	require.NoError(t, err)

	assetMeta := &proof.MetaReveal{
		Data: metaBlob[:],
	}

	metaHash := assetMeta.MetaHash()

	// We'll start by inserting a new asset meta into the database. We'll
	// only insert the hash at this point.
	ctx := context.Background()
	metaID, err := db.UpsertAssetMeta(ctx, NewAssetMeta{
		MetaDataHash: metaHash[:],
	})
	require.NoError(t, err)

	// If we try and insert the same meta hash again, then we should get
	// the same meta ID.
	metaID2, err := db.UpsertAssetMeta(ctx, NewAssetMeta{
		MetaDataHash: metaHash[:],
	})
	require.NoError(t, err)

	require.Equal(t, metaID, metaID2)

	// Now we'll insert the meta hash again, but this time we'll add the
	// blob.
	metaID, err = db.UpsertAssetMeta(ctx, NewAssetMeta{
		MetaDataHash: metaHash[:],
		MetaDataBlob: assetMeta.Data,
	})
	require.NoError(t, err)

	// If we fetch the meta, then we should get the blob back this time.
	fetchedMeta, err := db.FetchAssetMeta(ctx, metaID)
	require.NoError(t, err)
	require.Equal(t, metaBlob[:], fetchedMeta.MetaDataBlob)

	// If we insert a meta of all zeroes twice, then we should get the same
	// value back.
	var zeroMeta [32]byte
	zeroMetaID, err := db.UpsertAssetMeta(ctx, NewAssetMeta{
		MetaDataHash: zeroMeta[:],
	})
	require.NoError(t, err)
	zeroMetaID2, err := db.UpsertAssetMeta(ctx, NewAssetMeta{
		MetaDataHash: zeroMeta[:],
	})
	require.NoError(t, err)

	require.Equal(t, zeroMetaID, zeroMetaID2)
}
