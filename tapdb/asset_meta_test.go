package tapdb

import (
	"context"
	"math/rand"
	"net/url"
	"testing"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
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
		MetaDataHash:            metaHash[:],
		MetaDataBlob:            assetMeta.Data,
		MetaDecimalDisplay:      sqlInt32(11),
		MetaUniverseCommitments: sqlBool(true),
		MetaCanonicalUniverses:  []byte("http://test1\x00http://test2"),
		MetaDelegationKey:       asset.NUMSBytes,
	})
	require.NoError(t, err)

	// If we fetch the meta, then we should get the blob back this time.
	fetchedMeta, err := db.FetchAssetMeta(ctx, metaID)
	require.NoError(t, err)
	require.Equal(t, metaBlob[:], fetchedMeta.AssetsMetum.MetaDataBlob)
	require.Equal(
		t, sqlInt32(11), fetchedMeta.AssetsMetum.MetaDecimalDisplay,
	)
	require.Equal(
		t, sqlBool(true),
		fetchedMeta.AssetsMetum.MetaUniverseCommitments,
	)
	require.Equal(
		t, []byte("http://test1\x00http://test2"),
		fetchedMeta.AssetsMetum.MetaCanonicalUniverses,
	)
	require.Equal(
		t, asset.NUMSBytes,
		fetchedMeta.AssetsMetum.MetaDelegationKey,
	)

	parsed, err := parseAssetMetaReveal(fetchedMeta.AssetsMetum)
	require.NoError(t, err)
	require.True(t, parsed.IsSome())

	url1, err := url.ParseRequestURI("http://test1")
	require.NoError(t, err)
	url2, err := url.ParseRequestURI("http://test2")
	require.NoError(t, err)
	parsed.WhenSome(func(reveal proof.MetaReveal) {
		require.Equal(t, fn.Some(uint32(11)), reveal.DecimalDisplay)
		require.Equal(t, true, reveal.UniverseCommitments)
		require.Equal(
			t, fn.Some([]url.URL{*url1, *url2}),
			reveal.CanonicalUniverses,
		)
		require.Equal(
			t, fn.MaybeSome(asset.NUMSPubKey), reveal.DelegationKey,
		)
	})

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
