package backup

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightningnetwork/lnd/chainntnfs"
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

type mockGroupRegistrar struct {
	geneses []*asset.Genesis
	groups  []*asset.GroupKey
	err     error
}

func (m *mockGroupRegistrar) InsertAssetGen(_ context.Context,
	gen *asset.Genesis, group *asset.GroupKey) error {

	if m.err != nil {
		return m.err
	}

	m.geneses = append(m.geneses, gen)
	m.groups = append(m.groups, group)

	return nil
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

// TestRecordedGroups asserts that the import accepts a recorded group for
// verification only if it derives the group key the entry claims, and that
// the pre-pass writes nothing: a group is persisted by persistRecordedGroup
// once a leaf of it imported, once per group, and registrar failures are
// fatal.
func TestRecordedGroups(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	for _, tc := range groupVersions {
		t.Run(tc.name, func(t *testing.T) {
			group := newTestGroup(t, tc.version, tc.customRoot)
			gkb := newTestGroupKeyBackup(group)
			first := newTestReissuance(t, group)
			second := newTestReissuance(t, group)
			entries := []*AssetBackup{
				{Asset: first, GroupKeyInfo: gkb},
				{Asset: second, GroupKeyInfo: gkb},
				{Asset: newTestAsset(t)},
			}

			known := make(map[asset.SerializedKey]bool)
			groups := recordedGroups(entries, known)

			key := asset.ToSerialized(&group.GroupKey.GroupPubKey)
			require.True(t, known[key])
			require.Len(t, known, 1)
			require.Len(t, groups, 1)
			require.Equal(t, group.Genesis, groups[key].Genesis)
			require.Equal(t, group.GroupKey, groups[key].GroupKey)

			// Nothing has been imported yet, so nothing is
			// persisted. The file's claim is only good for this
			// import until a leaf corroborates it.
			registrar := &mockGroupRegistrar{}
			cfg := &ImportConfig{GroupRegistrar: registrar}
			persisted := make(map[asset.SerializedKey]struct{})
			require.Empty(t, registrar.groups)

			// A leaf of the group imported: the group is persisted
			// with the anchor genesis and the full group key.
			err := persistRecordedGroup(
				ctx, cfg, first, groups, persisted,
			)
			require.NoError(t, err)
			require.Len(t, registrar.groups, 1)
			require.Equal(t, group.Genesis, registrar.geneses[0])
			require.Equal(t, group.GroupKey, registrar.groups[0])

			// A second leaf of the same group does not persist it
			// again, an ungrouped leaf persists nothing.
			err = persistRecordedGroup(
				ctx, cfg, second, groups, persisted,
			)
			require.NoError(t, err)
			err = persistRecordedGroup(
				ctx, cfg, newTestAsset(t), groups, persisted,
			)
			require.NoError(t, err)
			require.Len(t, registrar.groups, 1)
		})
	}

	t.Run("group not recorded", func(t *testing.T) {
		// A leaf of a group the file did not describe, for example one
		// whitelisted from a group anchor proof, persists nothing. The
		// proof import itself stores what it knows about the group.
		group := newTestGroup(t, asset.GroupKeyV0, noRoot)
		registrar := &mockGroupRegistrar{}
		err := persistRecordedGroup(
			ctx, &ImportConfig{GroupRegistrar: registrar},
			newTestReissuance(t, group), recordedGroupSet{},
			make(map[asset.SerializedKey]struct{}),
		)
		require.NoError(t, err)
		require.Empty(t, registrar.groups)
	})

	t.Run("no registrar", func(t *testing.T) {
		group := newTestGroup(t, asset.GroupKeyV0, noRoot)
		leaf := newTestReissuance(t, group)
		entries := []*AssetBackup{{
			Asset:        leaf,
			GroupKeyInfo: newTestGroupKeyBackup(group),
		}}

		known := make(map[asset.SerializedKey]bool)
		groups := recordedGroups(entries, known)
		require.True(t, known[asset.ToSerialized(
			&group.GroupKey.GroupPubKey,
		)])

		err := persistRecordedGroup(
			ctx, &ImportConfig{}, leaf, groups,
			make(map[asset.SerializedKey]struct{}),
		)
		require.NoError(t, err)
	})

	t.Run("registrar error", func(t *testing.T) {
		group := newTestGroup(t, asset.GroupKeyV0, noRoot)
		leaf := newTestReissuance(t, group)
		entries := []*AssetBackup{{
			Asset:        leaf,
			GroupKeyInfo: newTestGroupKeyBackup(group),
		}}
		groups := recordedGroups(
			entries, make(map[asset.SerializedKey]bool),
		)

		dbErr := errors.New("db locked")
		err := persistRecordedGroup(
			ctx, &ImportConfig{
				GroupRegistrar: &mockGroupRegistrar{err: dbErr},
			}, leaf, groups, make(map[asset.SerializedKey]struct{}),
		)
		require.ErrorIs(t, err, dbErr)
	})

	// Records that do not derive the claimed group key must not whitelist
	// it, and since they are not collected they can never be persisted.
	tamperCases := []struct {
		name   string
		tamper func(t *testing.T, gkb *GroupKeyBackup, a *asset.Asset)
	}{{
		name: "other raw key",
		tamper: func(t *testing.T, gkb *GroupKeyBackup,
			_ *asset.Asset) {

			gkb.RawKey = test.RandPubKey(t)
		},
	}, {
		name: "other anchor genesis",
		tamper: func(t *testing.T, gkb *GroupKeyBackup,
			_ *asset.Asset) {

			gkb.AnchorGenesis = asset.RandGenesis(t, asset.Normal)
		},
	}, {
		name: "other tapscript root",
		tamper: func(t *testing.T, gkb *GroupKeyBackup,
			_ *asset.Asset) {

			gkb.TapscriptRoot = test.RandBytes(32)
		},
	}, {
		name: "other version",
		tamper: func(t *testing.T, gkb *GroupKeyBackup,
			_ *asset.Asset) {

			gkb.Version = asset.GroupKeyV1
		},
	}, {
		name: "claimed key not derived",
		tamper: func(t *testing.T, _ *GroupKeyBackup,
			a *asset.Asset) {

			a.GroupKey.GroupPubKey = *test.RandPubKey(t)
		},
	}, {
		name: "no witness",
		tamper: func(t *testing.T, gkb *GroupKeyBackup,
			_ *asset.Asset) {

			gkb.Witness = nil
		},
	}}
	for _, tc := range tamperCases {
		t.Run(tc.name, func(t *testing.T) {
			group := newTestGroup(t, asset.GroupKeyV0, noRoot)
			gkb := newTestGroupKeyBackup(group)
			a := newTestReissuance(t, group)
			tc.tamper(t, gkb, a)

			known := make(map[asset.SerializedKey]bool)
			groups := recordedGroups(
				[]*AssetBackup{{Asset: a, GroupKeyInfo: gkb}},
				known,
			)
			require.Empty(t, known)
			require.Empty(t, groups)
		})
	}

	t.Run("info on ungrouped asset ignored", func(t *testing.T) {
		group := newTestGroup(t, asset.GroupKeyV0, noRoot)
		known := make(map[asset.SerializedKey]bool)
		groups := recordedGroups([]*AssetBackup{{
			Asset:        newTestAsset(t),
			GroupKeyInfo: newTestGroupKeyBackup(group),
		}}, known)
		require.Empty(t, known)
		require.Empty(t, groups)
	})
}

// unspentChecker is a SpendChecker that never reports a spend, so every
// outpoint counts as unspent once the spend check times out.
type unspentChecker struct{}

func (unspentChecker) RegisterSpendNtfn(context.Context, *wire.OutPoint,
	[]byte, int32, ...lndclient.NotifierOption) (
	chan *chainntnfs.SpendDetail, chan error, error) {

	return make(chan *chainntnfs.SpendDetail), make(chan error), nil
}

// TestImportBackupBadFileLeavesNoGroups asserts that a backup whose entries
// describe a group correctly but whose proofs cannot be imported leaves no
// group behind in the wallet. The group is accepted for verification, but
// only a leaf that actually imports persists it.
func TestImportBackupBadFileLeavesNoGroups(t *testing.T) {
	// Not parallel, the spend check timeout is shortened globally.
	prev := spendCheckTimeout
	spendCheckTimeout = 50 * time.Millisecond
	t.Cleanup(func() { spendCheckTimeout = prev })

	ctx := context.Background()
	group := newTestGroup(t, asset.GroupKeyV1, noRoot)
	gkb := newTestGroupKeyBackup(group)

	// Two reissued leaves with a valid group record and garbage in place
	// of their proof files, the shape of a truncated or corrupted file.
	wb := &WalletBackup{Version: BackupVersionOriginal}
	for i := 0; i < 2; i++ {
		wb.Assets = append(wb.Assets, &AssetBackup{
			Asset:          newTestReissuance(t, group),
			AnchorOutpoint: randOutpoint(t),
			GroupKeyInfo:   gkb,
			ProofFileBlob:  []byte("not a proof file"),
		})
	}
	blob, err := EncodeWalletBackup(wb)
	require.NoError(t, err)

	registrar := &mockGroupRegistrar{}
	imported, skipped, err := ImportBackup(ctx, blob, &ImportConfig{
		SpendChecker:   unspentChecker{},
		WalletProofs:   &staticExporter{err: proof.ErrProofNotFound},
		GroupRegistrar: registrar,
	})
	require.NoError(t, err)
	require.Zero(t, imported)
	require.EqualValues(t, 2, skipped)

	// Nothing imported, so the group the file described was never
	// written to the wallet.
	require.Empty(t, registrar.groups)
}
