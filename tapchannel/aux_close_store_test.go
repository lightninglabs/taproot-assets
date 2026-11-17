package tapchannel

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"testing"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/tapchannelmsg"
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
// a Put/Get round-trip through SQLAuxCloseStore byte-for-byte. The STXO
// features are exercised in every state to catch an "always write the same
// byte" regression in the encoder.
func TestSQLAuxCloseStoreRoundTrip(t *testing.T) {
	t.Parallel()

	allFeatures := []STXOFeatures{
		{},
		{STXO: true},
		{STXO: true, Spender: true},
	}
	for _, stxoFeatures := range allFeatures {
		stxoFeatures := stxoFeatures
		name := fmt.Sprintf("stxoFeatures=%+v", stxoFeatures)
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			testSQLAuxCloseStoreRoundTrip(t, stxoFeatures)
		})
	}
}

func testSQLAuxCloseStoreRoundTrip(t *testing.T, stxoFeatures STXOFeatures) {
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
				value:       1000,
				isLocal:     true,
			},
			{
				outputIndex: 2,
				pkScript:    test.RandBytes(34),
				value:       1000,
				isLocal:     false,
			},
		},
		closeFee:     12345,
		stxoFeatures: stxoFeatures,
		templateID:   closeTemplateID(test.RandHash()),
	}

	chanPoint := wire.OutPoint{
		Hash:  chainhash.Hash{0xab, 0xcd, 0xef},
		Index: 7,
	}

	require.NoError(t, store.Put(
		ctx, chanPoint, &persistedChanClose{closeInfo: original},
	))

	got, err := store.Get(ctx, chanPoint)
	require.NoError(t, err)
	require.Nil(t, got.shutdownMsg)

	requirePersistedCloseInfoEqual(t, original, got.closeInfo)

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
	require.Equal(t, want.stxoFeatures, got.stxoFeatures)
	require.Equal(t, want.assetOutputs, got.assetOutputs)
	require.Equal(t, want.templateID, got.templateID)
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

// newTestCloseInfo returns a persisted close info with random content and the
// given fee and STXO features.
func newTestCloseInfo(t *testing.T, closeFee int64,
	stxoFeatures STXOFeatures) *persistedCloseInfo {

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
			value:       1000,
			isLocal:     true,
		}},
		closeFee:     closeFee,
		stxoFeatures: stxoFeatures,
		templateID:   closeTemplateID(test.RandHash()),
	}
}

// newTestShutdownMsg returns a shutdown message with random keys.
func newTestShutdownMsg(t *testing.T) *tapchannelmsg.AuxShutdownMsg {
	t.Helper()

	scriptKeys := tapchannelmsg.ScriptKeyMap{
		asset.ID(test.RandHash()): *test.RandPubKey(t),
	}

	return tapchannelmsg.NewAuxShutdownMsg(
		test.RandPubKey(t), test.RandPubKey(t), scriptKeys,
		&url.URL{Scheme: "universerpc", Host: "localhost:10029"},
	)
}

// requireShutdownMsgEqual compares two shutdown messages by their encoding.
func requireShutdownMsgEqual(t *testing.T,
	want, got *tapchannelmsg.AuxShutdownMsg) {

	t.Helper()

	require.NotNil(t, got)

	var wantBuf, gotBuf bytes.Buffer
	require.NoError(t, want.Encode(&wantBuf))
	require.NoError(t, got.Encode(&gotBuf))
	require.Equal(t, wantBuf.Bytes(), gotBuf.Bytes())
}

// TestSQLAuxCloseStoreChanClose verifies that the close state of a channel
// survives a Put/Get round-trip in every combination of its parts: the
// shutdown records alone, as they are written before the close info exists,
// both, and an empty state.
func TestSQLAuxCloseStoreChanClose(t *testing.T) {
	t.Parallel()

	store := NewSQLAuxCloseStore(newMemBlobStore(), errBlobMissing)
	ctx := context.Background()
	chanPoint := wire.OutPoint{Index: 1}

	// The shutdown records alone.
	shutdownMsg := newTestShutdownMsg(t)
	require.NoError(t, store.Put(ctx, chanPoint, &persistedChanClose{
		shutdownMsg: shutdownMsg,
	}))

	got, err := store.Get(ctx, chanPoint)
	require.NoError(t, err)
	requireShutdownMsgEqual(t, shutdownMsg, got.shutdownMsg)
	require.Nil(t, got.closeInfo)

	// The close info added to them.
	closeInfo := newTestCloseInfo(t, 100, STXOFeatures{STXO: true})
	require.NoError(t, store.Put(ctx, chanPoint, &persistedChanClose{
		shutdownMsg: shutdownMsg,
		closeInfo:   closeInfo,
	}))

	got, err = store.Get(ctx, chanPoint)
	require.NoError(t, err)
	requireShutdownMsgEqual(t, shutdownMsg, got.shutdownMsg)
	requirePersistedCloseInfoEqual(t, closeInfo, got.closeInfo)

	// An empty state round-trips as well.
	require.NoError(t, store.Put(ctx, chanPoint, &persistedChanClose{}))
	got, err = store.Get(ctx, chanPoint)
	require.NoError(t, err)
	require.Nil(t, got.shutdownMsg)
	require.Nil(t, got.closeInfo)
}

// TestSQLAuxCloseStoreLegacyFormats verifies that blobs written in the
// previous formats are still read, as a close info without asset outputs
// and template ID, and without shutdown records. Version 2 predates the
// spender flag, version 3 carries it.
func TestSQLAuxCloseStoreLegacyFormats(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		version      uint8
		stxoFeatures STXOFeatures
	}{
		{
			name:         "version 2, no stxo",
			version:      closeInfoFormatVersionSTXO,
			stxoFeatures: STXOFeatures{},
		},
		{
			name:         "version 2, stxo",
			version:      closeInfoFormatVersionSTXO,
			stxoFeatures: STXOFeatures{STXO: true},
		},
		{
			name:         "version 3, stxo",
			version:      closeInfoFormatVersionSingle,
			stxoFeatures: STXOFeatures{STXO: true},
		},
		{
			name:         "version 3, stxo and spender",
			version:      closeInfoFormatVersionSingle,
			stxoFeatures: STXOFeatures{STXO: true, Spender: true},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			blobs := newMemBlobStore()
			store := NewSQLAuxCloseStore(blobs, errBlobMissing)
			ctx := context.Background()
			chanPoint := wire.OutPoint{Index: 2}

			legacy := newTestCloseInfo(t, 4321, tc.stxoFeatures)
			legacy.assetOutputs = nil
			legacy.templateID = closeTemplateID{}

			// The legacy formats are the version byte followed by
			// a single candidate body, with the spender flag only
			// from version 3 on.
			withSpender := tc.version >=
				closeInfoFormatVersionSingle

			var buf bytes.Buffer
			err := binary.Write(&buf, binary.BigEndian, tc.version)
			require.NoError(t, err)
			err = encodeCloseInfoBody(&buf, legacy, withSpender)
			require.NoError(t, err)
			err = blobs.PutAuxCloseBlob(ctx, chanPoint, buf.Bytes())
			require.NoError(t, err)

			got, err := store.Get(ctx, chanPoint)
			require.NoError(t, err)
			require.Nil(t, got.shutdownMsg)
			requirePersistedCloseInfoEqual(t, legacy, got.closeInfo)
		})
	}

	// An unknown version is rejected.
	blobs := newMemBlobStore()
	store := NewSQLAuxCloseStore(blobs, errBlobMissing)
	ctx := context.Background()
	chanPoint := wire.OutPoint{Index: 3}

	var buf bytes.Buffer
	require.NoError(t, binary.Write(&buf, binary.BigEndian, uint8(9)))
	require.NoError(t, blobs.PutAuxCloseBlob(ctx, chanPoint, buf.Bytes()))
	_, err := store.Get(ctx, chanPoint)
	require.ErrorContains(t, err, "unsupported close info version")
}
