package backup

import (
	"context"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightningnetwork/lnd/keychain"
)

// GroupLookup resolves the asset group a tweaked group key belongs to.
type GroupLookup interface {
	// QueryAssetGroupByGroupKey fetches the asset group with a matching
	// tweaked key, including the genesis of the asset that created the
	// group. Returns address.ErrAssetGroupUnknown if the group is not
	// known.
	QueryAssetGroupByGroupKey(ctx context.Context,
		groupKey *btcec.PublicKey) (*asset.AssetGroup, error)
}

// GroupKeyBackup describes the asset group a backed up leaf belongs to. It
// carries what a fresh wallet needs to verify that the group key of the leaf
// is legitimate: the genesis of the group anchor and the group key parameters
// the tweaked key is derived from. A group key reveal only exists on the
// genesis proof of the group anchor, every later tranche minted into the group
// carries the group key without a reveal, so a wallet that only ever received
// such reissued leaves cannot learn the group from the proofs it holds.
type GroupKeyBackup struct {
	// AnchorGenesis is the genesis of the asset that created the group.
	// The tweaked group key commits to its asset ID.
	AnchorGenesis asset.Genesis

	// Version is the version of the group key construction.
	Version asset.GroupKeyVersion

	// RawKey is the untweaked internal key of the group.
	RawKey *btcec.PublicKey

	// TapscriptRoot is the root of the tapscript tree committed to by the
	// group key. Empty for a V0 group that only allows signature spends.
	TapscriptRoot []byte

	// CustomTapscriptRoot is the user provided subtree of a V1 group key.
	CustomTapscriptRoot fn.Option[chainhash.Hash]

	// Witness is the group witness of the group anchor's genesis.
	Witness wire.TxWitness
}

// GroupKey re-derives the full group key from the recorded parameters. The
// returned key's tweaked public key is computed from the raw key and the
// anchor genesis, so a caller can compare it against the group key a leaf
// claims to belong to.
func (g *GroupKeyBackup) GroupKey() (*asset.GroupKey, error) {
	if g.RawKey == nil {
		return nil, fmt.Errorf("group key backup without raw key")
	}

	groupKey := asset.GroupKey{
		Version:             g.Version,
		RawKey:              keychain.KeyDescriptor{PubKey: g.RawKey},
		TapscriptRoot:       g.TapscriptRoot,
		CustomTapscriptRoot: g.CustomTapscriptRoot,
		Witness:             g.Witness,
	}

	anchorID := g.AnchorGenesis.ID()
	reveal, err := asset.NewGroupKeyReveal(groupKey, anchorID)
	if err != nil {
		return nil, fmt.Errorf("unable to build group key reveal: %w",
			err)
	}

	tweakedKey, err := reveal.GroupPubKey(anchorID)
	if err != nil {
		return nil, fmt.Errorf("unable to derive group key: %w", err)
	}

	groupKey.GroupPubKey = *tweakedKey
	groupKey.TapscriptRoot = reveal.TapscriptRoot()

	return &groupKey, nil
}

// newGroupKeyBackup records the group of a leaf as known by the wallet. It
// returns nil without an error if the wallet cannot describe the group in a
// way a fresh wallet could verify, for example because the group was only
// ever seen through reissuance proofs and its raw key is unknown.
func newGroupKeyBackup(ctx context.Context, lookup GroupLookup,
	groupPubKey *btcec.PublicKey) (*GroupKeyBackup, error) {

	group, err := lookup.QueryAssetGroupByGroupKey(ctx, groupPubKey)
	switch {
	case errors.Is(err, address.ErrAssetGroupUnknown):
		log.Warnf("Group %x is not known to the wallet, its leaves "+
			"can only be restored on a wallet that knows the group",
			groupPubKey.SerializeCompressed())
		return nil, nil

	case err != nil:
		return nil, fmt.Errorf("unable to fetch group %x: %w",
			groupPubKey.SerializeCompressed(), err)
	}

	if group.Genesis == nil || group.GroupKey == nil ||
		group.GroupKey.RawKey.PubKey == nil {

		log.Warnf("Group %x has no anchor genesis or raw key, its "+
			"leaves can only be restored on a wallet that knows "+
			"the group", groupPubKey.SerializeCompressed())
		return nil, nil
	}

	gkb := &GroupKeyBackup{
		AnchorGenesis:       *group.Genesis,
		Version:             group.GroupKey.Version,
		RawKey:              group.GroupKey.RawKey.PubKey,
		TapscriptRoot:       group.GroupKey.TapscriptRoot,
		CustomTapscriptRoot: group.GroupKey.CustomTapscriptRoot,
		Witness:             group.GroupKey.Witness,
	}

	// The database learns a group from whatever proof first mentions it.
	// A group first seen through a reissuance has the tweaked key stored
	// in place of the raw key, and recording that would only make the
	// import reject the entry. Only record groups we can re-derive.
	derived, err := gkb.GroupKey()
	if err != nil {
		log.Warnf("Group %x cannot be re-derived from the wallet's "+
			"record of it: %v", groupPubKey.SerializeCompressed(),
			err)
		return nil, nil
	}
	if !derived.GroupPubKey.IsEqual(groupPubKey) {
		log.Warnf("Group %x does not derive from the wallet's record "+
			"of it (anchor %x), not recording it",
			groupPubKey.SerializeCompressed(),
			fn.ByteSlice(gkb.AnchorGenesis.ID()))
		return nil, nil
	}

	return gkb, nil
}

// groupBackups resolves and caches the group backup of each distinct group
// while a set of leaves is being collected.
type groupBackups struct {
	lookup GroupLookup
	groups map[asset.SerializedKey]*GroupKeyBackup
}

// newGroupBackups returns a cache in front of the given lookup. A nil lookup
// yields a cache that records no groups.
func newGroupBackups(lookup GroupLookup) *groupBackups {
	return &groupBackups{
		lookup: lookup,
		groups: make(map[asset.SerializedKey]*GroupKeyBackup),
	}
}

// forGroup returns the group backup for the given tweaked group key, nil if
// the group cannot be recorded.
func (g *groupBackups) forGroup(ctx context.Context,
	groupPubKey *btcec.PublicKey) (*GroupKeyBackup, error) {

	if g == nil || g.lookup == nil || groupPubKey == nil {
		return nil, nil
	}

	key := asset.ToSerialized(groupPubKey)
	if gkb, ok := g.groups[key]; ok {
		return gkb, nil
	}

	gkb, err := newGroupKeyBackup(ctx, g.lookup, groupPubKey)
	if err != nil {
		return nil, err
	}
	g.groups[key] = gkb

	return gkb, nil
}
