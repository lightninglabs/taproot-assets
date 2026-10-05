package tapchannel

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/stretchr/testify/require"
)

// errBlobMissing is the sentinel the in-memory test store returns when no
// blob exists for the queried key. The SQLAuxCloseStore translates it to
// ErrNoAuxCloseInfo for callers.
var errBlobMissing = errors.New("blob missing")

// memBlobStore is an in-memory AuxCloseBlobStore for unit tests. We use it
// instead of spinning up a real sqlite handle so the encode/decode roundtrip
// can be tested without dragging the tapdb layer into this package's test
// dependency graph.
type memBlobStore struct {
	data map[wire.OutPoint][]byte
}

func newMemBlobStore() *memBlobStore {
	return &memBlobStore{data: make(map[wire.OutPoint][]byte)}
}

func (m *memBlobStore) PutAuxCloseBlob(_ context.Context,
	op wire.OutPoint, blob []byte) error {

	m.data[op] = append([]byte(nil), blob...)
	return nil
}

func (m *memBlobStore) FetchAuxCloseBlob(_ context.Context,
	op wire.OutPoint) ([]byte, error) {

	v, ok := m.data[op]
	if !ok {
		return nil, errBlobMissing
	}
	return append([]byte(nil), v...), nil
}

func (m *memBlobStore) DeleteAuxCloseBlob(_ context.Context,
	op wire.OutPoint) error {

	delete(m.data, op)
	return nil
}

// TestSQLAuxCloseStoreRoundTrip verifies that a persistedCloseInfo survives
// a Put/Get round-trip through SQLAuxCloseStore byte-for-byte. The
// supportSTXO flag is exercised in both states to catch an "always write
// the same byte" regression in the encoder.
func TestSQLAuxCloseStoreRoundTrip(t *testing.T) {
	t.Parallel()

	for _, supportSTXO := range []bool{true, false} {
		supportSTXO := supportSTXO
		name := fmt.Sprintf("supportSTXO=%v", supportSTXO)
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			testSQLAuxCloseStoreRoundTrip(t, supportSTXO)
		})
	}
}

func testSQLAuxCloseStoreRoundTrip(t *testing.T, supportSTXO bool) {
	store := NewSQLAuxCloseStore(newMemBlobStore(), errBlobMissing)
	ctx := context.Background()

	original := &persistedCloseInfo{
		vPackets: []*tappsbt.VPacket{
			tappsbt.RandPacket(t, true, true),
			tappsbt.RandPacket(t, true, true),
		},
		pristineVPackets: []*tappsbt.VPacket{
			tappsbt.RandPacket(t, true, true),
		},
		noAssetAllocs: []noAssetAlloc{
			{
				outputIndex: 0,
				internalKey: test.RandPubKey(t),
			},
			{
				outputIndex: 3,
				internalKey: test.RandPubKey(t),
			},
		},
		assetOutputs: []closeAssetOutput{
			{
				outputIndex: 1,
				pkScript:    test.RandBytes(34),
			},
			{
				outputIndex: 2,
				pkScript:    test.RandBytes(34),
			},
		},
		closeFee:    12345,
		supportSTXO: supportSTXO,
	}

	chanPoint := wire.OutPoint{
		Hash:  chainhash.Hash{0xab, 0xcd, 0xef},
		Index: 7,
	}

	require.NoError(
		t, store.Put(ctx, chanPoint, []*persistedCloseInfo{original}),
	)

	got, err := store.Get(ctx, chanPoint)
	require.NoError(t, err)
	require.Len(t, got, 1)

	requirePersistedCloseInfoEqual(t, original, got[0])

	// Sanity: Delete removes the entry and subsequent Get returns
	// ErrNoAuxCloseInfo.
	require.NoError(t, store.Delete(ctx, chanPoint))
	_, err = store.Get(ctx, chanPoint)
	require.ErrorIs(t, err, ErrNoAuxCloseInfo)
}

// requirePersistedCloseInfoEqual compares two persistedCloseInfo values
// field-by-field. VPackets are compared by re-serializing both sides and
// asserting byte equality — that's the strictest practical check, since
// reflect.DeepEqual on the rich VPacket struct is fragile (unexported fields,
// map iteration order, pointer identity on shared sub-objects).
func requirePersistedCloseInfoEqual(t *testing.T,
	want, got *persistedCloseInfo) {

	t.Helper()

	require.Equal(t, want.closeFee, got.closeFee)
	require.Equal(t, want.supportSTXO, got.supportSTXO)
	require.Len(t, got.vPackets, len(want.vPackets))
	require.Len(t, got.pristineVPackets, len(want.pristineVPackets))
	require.Len(t, got.noAssetAllocs, len(want.noAssetAllocs))
	require.Equal(t, want.assetOutputs, got.assetOutputs)

	for i := range want.vPackets {
		requireVPacketBytesEqual(t, want.vPackets[i], got.vPackets[i])
	}
	for i := range want.pristineVPackets {
		requireVPacketBytesEqual(
			t, want.pristineVPackets[i], got.pristineVPackets[i],
		)
	}
	for i := range want.noAssetAllocs {
		require.Equal(
			t, want.noAssetAllocs[i].outputIndex,
			got.noAssetAllocs[i].outputIndex,
			"alloc %d outputIndex mismatch", i,
		)
		require.True(
			t,
			want.noAssetAllocs[i].internalKey.IsEqual(
				got.noAssetAllocs[i].internalKey,
			),
			"alloc %d internalKey mismatch", i,
		)
	}
}

func requireVPacketBytesEqual(t *testing.T, want, got *tappsbt.VPacket) {
	t.Helper()

	var wantBuf, gotBuf bytes.Buffer
	require.NoError(t, want.Serialize(&wantBuf))
	require.NoError(t, got.Serialize(&gotBuf))
	require.Equal(t, wantBuf.Bytes(), gotBuf.Bytes())
}

// newTestCloseInfo returns a persisted close info with random content and the
// given fee.
func newTestCloseInfo(t *testing.T, closeFee int64) *persistedCloseInfo {
	return &persistedCloseInfo{
		vPackets: []*tappsbt.VPacket{
			tappsbt.RandPacket(t, true, true),
		},
		pristineVPackets: []*tappsbt.VPacket{
			tappsbt.RandPacket(t, true, true),
		},
		noAssetAllocs: []noAssetAlloc{{
			outputIndex: 0,
			internalKey: test.RandPubKey(t),
		}},
		assetOutputs: []closeAssetOutput{{
			outputIndex: 1,
			pkScript:    test.RandBytes(34),
		}},
		closeFee:    closeFee,
		supportSTXO: true,
	}
}

// TestSQLAuxCloseStoreCandidates verifies that several close candidates of a
// channel survive a Put/Get round-trip in order, and that the candidate cap
// is enforced.
func TestSQLAuxCloseStoreCandidates(t *testing.T) {
	t.Parallel()

	store := NewSQLAuxCloseStore(newMemBlobStore(), errBlobMissing)
	ctx := context.Background()
	chanPoint := wire.OutPoint{Index: 1}

	candidates := []*persistedCloseInfo{
		newTestCloseInfo(t, 100),
		newTestCloseInfo(t, 200),
		newTestCloseInfo(t, 300),
	}
	require.NoError(t, store.Put(ctx, chanPoint, candidates))

	got, err := store.Get(ctx, chanPoint)
	require.NoError(t, err)
	require.Len(t, got, len(candidates))
	for i := range candidates {
		requirePersistedCloseInfoEqual(t, candidates[i], got[i])
	}

	// An empty candidate list round-trips as well.
	require.NoError(t, store.Put(ctx, chanPoint, nil))
	got, err = store.Get(ctx, chanPoint)
	require.NoError(t, err)
	require.Empty(t, got)

	// More candidates than the cap are refused.
	tooMany := make([]*persistedCloseInfo, maxCloseCandidates+1)
	for i := range tooMany {
		tooMany[i] = newTestCloseInfo(t, int64(i))
	}
	require.Error(t, store.Put(ctx, chanPoint, tooMany))
}

// TestSQLAuxCloseStoreLegacyFormat verifies that a blob written in the
// previous single candidate format is still read, as a single candidate
// without asset outputs.
func TestSQLAuxCloseStoreLegacyFormat(t *testing.T) {
	t.Parallel()

	blobs := newMemBlobStore()
	store := NewSQLAuxCloseStore(blobs, errBlobMissing)
	ctx := context.Background()
	chanPoint := wire.OutPoint{Index: 2}

	legacy := newTestCloseInfo(t, 4321)
	legacy.assetOutputs = nil

	// The legacy format is the version byte followed by a single
	// candidate body.
	var buf bytes.Buffer
	require.NoError(
		t, binary.Write(
			&buf, binary.BigEndian, closeInfoFormatVersionSingle,
		),
	)
	require.NoError(t, encodeCloseInfoBody(&buf, legacy))
	require.NoError(t, blobs.PutAuxCloseBlob(ctx, chanPoint, buf.Bytes()))

	got, err := store.Get(ctx, chanPoint)
	require.NoError(t, err)
	require.Len(t, got, 1)
	requirePersistedCloseInfoEqual(t, legacy, got[0])

	// An unknown version is rejected.
	buf.Reset()
	require.NoError(t, binary.Write(&buf, binary.BigEndian, uint8(9)))
	require.NoError(t, blobs.PutAuxCloseBlob(ctx, chanPoint, buf.Bytes()))
	_, err = store.Get(ctx, chanPoint)
	require.ErrorContains(t, err, "unsupported close info version")
}
