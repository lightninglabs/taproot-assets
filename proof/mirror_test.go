package proof

import (
	"context"
	"testing"

	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/stretchr/testify/require"
)

// TestDispatchMirrorSync drives the mirror-sync dispatcher against a
// file source and a file mirror: a rewrite copies what the source
// holds and is a no-op on a source miss; a delete removes the mirror's
// file and is a no-op once it is gone. Both are replayed to pin the
// idempotence outbox redelivery relies on.
func TestDispatchMirrorSync(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	source, err := NewFileArchiver(t.TempDir())
	require.NoError(t, err)
	mirror, err := NewFileArchiver(t.TempDir())
	require.NoError(t, err)
	cfg := MirrorSyncCfg{Source: source, Mirror: mirror}

	op := test.RandOp(t)
	loc := Locator{
		AssetID:   randAssetID(),
		ScriptKey: *test.RandPubKey(t),
		OutPoint:  &op,
	}

	dispatch := func(syncOp MirrorSyncOp) error {
		version, data, err := MirrorSyncPayload{
			Op:       syncOp,
			Locators: []Locator{loc},
		}.Encode()
		require.NoError(t, err)

		return DispatchMirrorSync(ctx, cfg, version, data)
	}

	// A rewrite of a proof the source does not hold leaves the
	// mirror alone.
	require.NoError(t, dispatch(MirrorSyncRewrite))
	has, err := mirror.HasProof(ctx, loc)
	require.NoError(t, err)
	require.False(t, has)

	// Once the source holds it, a rewrite copies it — and creates
	// the mirror's file, since the mirror may lag the source.
	blob := Blob("first")
	require.NoError(t, source.ImportProofs(
		ctx, MockVerifierCtx, false, &AnnotatedProof{
			Locator: loc,
			Blob:    blob,
		},
	))
	require.NoError(t, dispatch(MirrorSyncRewrite))
	got, err := mirror.FetchProof(ctx, loc)
	require.NoError(t, err)
	require.EqualValues(t, blob, got)

	// A rewrite after the source changed brings the mirror along.
	blob = Blob("second")
	require.NoError(t, source.ImportProofs(
		ctx, MockVerifierCtx, true, &AnnotatedProof{
			Locator: loc,
			Blob:    blob,
		},
	))
	require.NoError(t, dispatch(MirrorSyncRewrite))
	require.NoError(t, dispatch(MirrorSyncRewrite))
	got, err = mirror.FetchProof(ctx, loc)
	require.NoError(t, err)
	require.EqualValues(t, blob, got)

	// A delete removes the mirror's file, and replays harmlessly.
	require.NoError(t, dispatch(MirrorSyncDelete))
	require.NoError(t, dispatch(MirrorSyncDelete))
	has, err = mirror.HasProof(ctx, loc)
	require.NoError(t, err)
	require.False(t, has)
}
