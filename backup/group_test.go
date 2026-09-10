package backup

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

// newTestGroup creates an asset group of the given version, anchored at a
// random genesis, with a random raw key and group witness.
func newTestGroup(t *testing.T, version asset.GroupKeyVersion,
	customRoot fn.Option[chainhash.Hash]) *asset.AssetGroup {

	anchorGen := asset.RandGenesis(t, asset.Normal)
	anchorID := anchorGen.ID()
	internalKey := test.RandPubKey(t)

	groupKey := &asset.GroupKey{
		Version: version,
		RawKey: keychain.KeyDescriptor{
			PubKey: internalKey,
		},
		CustomTapscriptRoot: customRoot,
		Witness:             wire.TxWitness{test.RandBytes(64)},
	}

	switch version {
	case asset.GroupKeyV0:
		groupKey.TapscriptRoot = test.RandBytes(32)
		gkr := asset.NewGroupKeyRevealV0(
			asset.ToSerialized(internalKey), groupKey.TapscriptRoot,
		)
		groupPubKey, err := gkr.GroupPubKey(anchorID)
		require.NoError(t, err)
		groupKey.GroupPubKey = *groupPubKey

	case asset.GroupKeyV1:
		gkr, err := asset.NewGroupKeyRevealV1(
			asset.PedersenVersion, *internalKey, anchorID,
			customRoot,
		)
		require.NoError(t, err)
		groupPubKey, err := gkr.GroupPubKey(anchorID)
		require.NoError(t, err)
		groupKey.GroupPubKey = *groupPubKey
		groupKey.TapscriptRoot = gkr.TapscriptRoot()

	default:
		t.Fatalf("unknown group key version %d", version)
	}

	return &asset.AssetGroup{
		Genesis:  &anchorGen,
		GroupKey: groupKey,
	}
}

// newTestGroupKeyBackup records the given group the way the writer does.
func newTestGroupKeyBackup(group *asset.AssetGroup) *GroupKeyBackup {
	return &GroupKeyBackup{
		AnchorGenesis:       *group.Genesis,
		Version:             group.GroupKey.Version,
		RawKey:              group.GroupKey.RawKey.PubKey,
		TapscriptRoot:       group.GroupKey.TapscriptRoot,
		CustomTapscriptRoot: group.GroupKey.CustomTapscriptRoot,
		Witness:             group.GroupKey.Witness,
	}
}

// newTestReissuance creates an asset minted into the given group, with its
// own genesis that differs from the group anchor's.
func newTestReissuance(t *testing.T, group *asset.AssetGroup) *asset.Asset {
	a := newTestAsset(t)
	a.GroupKey = &asset.GroupKey{
		GroupPubKey: group.GroupKey.GroupPubKey,
		Witness:     wire.TxWitness{test.RandBytes(64)},
	}
	require.NotEqual(t, group.Genesis.ID(), a.ID())

	return a
}

type mockGroupLookup struct {
	mu    sync.Mutex
	group *asset.AssetGroup
	err   error
	calls int
}

func (m *mockGroupLookup) QueryAssetGroupByGroupKey(_ context.Context,
	_ *btcec.PublicKey) (*asset.AssetGroup, error) {

	m.mu.Lock()
	defer m.mu.Unlock()

	m.calls++
	return m.group, m.err
}

// set replaces what the lookup answers with.
func (m *mockGroupLookup) set(group *asset.AssetGroup, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.group, m.err = group, err
}

// noRoot is a group without a custom tapscript subtree.
var noRoot = fn.None[chainhash.Hash]()

// groupVersions lists the group key constructions the backup must cover.
var groupVersions = []struct {
	name       string
	version    asset.GroupKeyVersion
	customRoot fn.Option[chainhash.Hash]
}{{
	name:    "v0",
	version: asset.GroupKeyV0,
}, {
	name:    "v1",
	version: asset.GroupKeyV1,
}, {
	name:       "v1 custom root",
	version:    asset.GroupKeyV1,
	customRoot: fn.Some(chainhash.Hash(test.RandBytes(32))),
}}

// TestGroupKeyBackupRoundtrip asserts that the recorded group survives
// encoding and still re-derives the tweaked group key afterwards.
func TestGroupKeyBackupRoundtrip(t *testing.T) {
	t.Parallel()

	for _, tc := range groupVersions {
		t.Run(tc.name, func(t *testing.T) {
			group := newTestGroup(t, tc.version, tc.customRoot)
			gkb := newTestGroupKeyBackup(group)

			var buf bytes.Buffer
			require.NoError(t, gkb.Encode(&buf))

			var decoded GroupKeyBackup
			require.NoError(t, decoded.Decode(&buf))
			require.Equal(t, gkb, &decoded)

			derived, err := decoded.GroupKey()
			require.NoError(t, err)
			require.True(t, derived.GroupPubKey.IsEqual(
				&group.GroupKey.GroupPubKey,
			))
			require.Equal(t, group.GroupKey.TapscriptRoot,
				derived.TapscriptRoot)
			require.Equal(t, group.GroupKey.Witness,
				derived.Witness)
		})
	}

	t.Run("without raw key", func(t *testing.T) {
		group := newTestGroup(t, asset.GroupKeyV0, noRoot)
		gkb := newTestGroupKeyBackup(group)
		gkb.RawKey = nil

		require.ErrorContains(t, gkb.Encode(&bytes.Buffer{}),
			"without raw key")
		_, err := gkb.GroupKey()
		require.ErrorContains(t, err, "without raw key")
	})

	t.Run("asset backup entry", func(t *testing.T) {
		group := newTestGroup(t, asset.GroupKeyV1, noRoot)

		for _, ab := range []*AssetBackup{
			newTestAssetBackup(t), newTestAssetBackupV2(t),
			newTestAssetBackupV3(t),
		} {
			ab.GroupKeyInfo = newTestGroupKeyBackup(group)

			var buf bytes.Buffer
			require.NoError(t, ab.Encode(&buf))

			var decoded AssetBackup
			require.NoError(t, decoded.Decode(&buf))
			require.Equal(t, ab.GroupKeyInfo, decoded.GroupKeyInfo)
		}

		// Entries without group info stay without it.
		ab := newTestAssetBackup(t)
		var buf bytes.Buffer
		require.NoError(t, ab.Encode(&buf))
		var decoded AssetBackup
		require.NoError(t, decoded.Decode(&buf))
		require.Nil(t, decoded.GroupKeyInfo)
	})
}

// TestNewGroupKeyBackup asserts that the writer only records groups it can
// re-derive, and surfaces database errors.
func TestNewGroupKeyBackup(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	group := newTestGroup(t, asset.GroupKeyV0, noRoot)
	groupPubKey := &group.GroupKey.GroupPubKey

	t.Run("recorded", func(t *testing.T) {
		gkb, err := newGroupKeyBackup(
			ctx, &mockGroupLookup{group: group}, groupPubKey,
		)
		require.NoError(t, err)
		require.Equal(t, newTestGroupKeyBackup(group), gkb)
	})

	t.Run("unknown group", func(t *testing.T) {
		gkb, err := newGroupKeyBackup(
			ctx, &mockGroupLookup{
				err: address.ErrAssetGroupUnknown,
			}, groupPubKey,
		)
		require.NoError(t, err)
		require.Nil(t, gkb)
	})

	t.Run("lookup error", func(t *testing.T) {
		dbErr := errors.New("db locked")
		_, err := newGroupKeyBackup(
			ctx, &mockGroupLookup{err: dbErr}, groupPubKey,
		)
		require.ErrorIs(t, err, dbErr)
	})

	t.Run("no anchor genesis", func(t *testing.T) {
		partial := &asset.AssetGroup{GroupKey: group.GroupKey}
		gkb, err := newGroupKeyBackup(
			ctx, &mockGroupLookup{group: partial}, groupPubKey,
		)
		require.NoError(t, err)
		require.Nil(t, gkb)
	})

	// A group the wallet only learned from a reissuance proof has the
	// tweaked key stored as its raw key. That record does not derive the
	// group key and must not be written.
	t.Run("raw key unknown", func(t *testing.T) {
		gk := *group.GroupKey
		gk.RawKey = keychain.KeyDescriptor{PubKey: groupPubKey}
		bogus := &asset.AssetGroup{
			Genesis:  group.Genesis,
			GroupKey: &gk,
		}
		gkb, err := newGroupKeyBackup(
			ctx, &mockGroupLookup{group: bogus}, groupPubKey,
		)
		require.NoError(t, err)
		require.Nil(t, gkb)
	})

	t.Run("cached per group", func(t *testing.T) {
		lookup := &mockGroupLookup{group: group}
		groups := newGroupBackups(lookup)

		for i := 0; i < 3; i++ {
			gkb, err := groups.forGroup(ctx, groupPubKey)
			require.NoError(t, err)
			require.NotNil(t, gkb)
		}
		require.Equal(t, 1, lookup.calls)

		none, err := newGroupBackups(nil).forGroup(ctx, groupPubKey)
		require.NoError(t, err)
		require.Nil(t, none)
	})
}

// TestCreateAssetBackupRecordsGroup asserts that grouped leaves get their
// group recorded and ungrouped leaves do not.
func TestCreateAssetBackupRecordsGroup(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	group := newTestGroup(t, asset.GroupKeyV1, noRoot)
	groups := newGroupBackups(&mockGroupLookup{group: group})

	reissued := newTestReissuance(t, group)
	ab, err := createAssetBackup(
		ctx, &asset.ChainAsset{Asset: reissued}, nil, nil, groups,
	)
	require.NoError(t, err)
	require.Equal(t, newTestGroupKeyBackup(group), ab.GroupKeyInfo)

	ab, err = createAssetBackup(
		ctx, &asset.ChainAsset{Asset: newTestAsset(t)}, nil, nil,
		groups,
	)
	require.NoError(t, err)
	require.Nil(t, ab.GroupKeyInfo)

	dbErr := errors.New("db locked")
	_, err = createAssetBackup(
		ctx, &asset.ChainAsset{Asset: reissued}, nil, nil,
		newGroupBackups(&mockGroupLookup{err: dbErr}),
	)
	require.ErrorIs(t, err, dbErr)
}
