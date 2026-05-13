package tapchannel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
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
		closeFee:    12345,
		supportSTXO: supportSTXO,
	}

	chanPoint := wire.OutPoint{
		Hash:  chainhash.Hash{0xab, 0xcd, 0xef},
		Index: 7,
	}

	require.NoError(t, store.Put(ctx, chanPoint, original))

	got, err := store.Get(ctx, chanPoint)
	require.NoError(t, err)

	requirePersistedCloseInfoEqual(t, original, got)

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
