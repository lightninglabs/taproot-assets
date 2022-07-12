package tarodb

import (
	"bytes"
	"context"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/tarodb/sqlite"
	"github.com/lightningnetwork/lnd/keychain"
)

type (
	// ConfirmedAsset is an asset that has been fully confirmed on chain.
	ConfirmedAsset = sqlite.FetchAllAssetsRow
)

// ActiveAssetsStore is a sub-set of the main sqlite.Querier interface that
// contains methods related to querying the set of confirmed assets.
type ActiveAssetsStore interface {
	// FetchAllAssets fetches the set of fully confirmed assets.
	FetchAllAssets(ctx context.Context) ([]ConfirmedAsset, error)
}

// BatchedAssetStore combines the AssetStore interface with the BatchedTx
// interface, allowing for multiple queries to be executed in a single SQL
// transaction.
type BatchedAssetStore interface {
	ActiveAssetsStore

	BatchedTx[ActiveAssetsStore, TxOptions]
}

// AssetStore is used to query for the set of pending and confirmed assets.
type AssetStore struct {
	db BatchedAssetStore
}

// NewAssetStore creates a new AssetStore from the specified BatchedAssetStore
// interface.
func NewAssetStore(db BatchedAssetStore) *AssetStore {
	return &AssetStore{
		db: db,
	}
}

// ChainAsset is a wrapper around the base asset struct that includes
// information detailing where in the chain the asset is currently anchored.
type ChainAsset struct {
	*asset.Asset

	// AnchorTx is the transaction that anchors this chain asset.
	AnchorTx *wire.MsgTx

	// AnchorTxid is the TXID of the anchor tx.
	AnchorTxid chainhash.Hash

	// AnchorBlockHash is the blockhash that mined the anchor tx.
	AnchorBlockHash chainhash.Hash

	// AnchorOutpoint is the outpoint that commits to the asset.
	AnchorOutpoint wire.OutPoint
}

// FetchAllAssets fetches the set of confirmed assets stored on disk.
func (a *AssetStore) FetchAllAssets(ctx context.Context) ([]*ChainAsset, error) {

	dbAssets, err := a.db.FetchAllAssets(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to read db assets: %v", err)
	}

	chainAssets := make([]*ChainAsset, len(dbAssets))
	for i, sprout := range dbAssets {
		// First, we'll decode the script key which very asset must
		// specify, and populate the key locator information
		scriptKeyPub, err := btcec.ParsePubKey(sprout.ScriptKeyRaw)
		if err != nil {
			return nil, err
		}
		scriptKey := keychain.KeyDescriptor{
			PubKey: scriptKeyPub,
			KeyLocator: keychain.KeyLocator{
				Index:  uint32(sprout.ScriptKeyIndex),
				Family: keychain.KeyFamily(sprout.ScriptKeyFam),
			},
		}

		// Not all assets have a key family, so we only need to
		// populate this information for those that signalled the
		// requirement of on going emission.
		var familyKey *asset.FamilyKey
		if sprout.TweakedFamKey != nil {
			tweakedFamKey, err := btcec.ParsePubKey(
				sprout.TweakedFamKey,
			)
			if err != nil {
				return nil, err
			}
			rawFamKey, err := btcec.ParsePubKey(sprout.FamKeyRaw)
			if err != nil {
				return nil, err
			}
			famSig, err := schnorr.ParseSignature(sprout.GenesisSig)
			if err != nil {
				return nil, err
			}

			familyKey = &asset.FamilyKey{
				RawKey: keychain.KeyDescriptor{
					PubKey: rawFamKey,
					KeyLocator: keychain.KeyLocator{
						Index: extractSqlInt32[uint32](
							sprout.FamKeyIndex,
						),
						Family: extractSqlInt32[keychain.KeyFamily](
							sprout.FamKeyFamily,
						),
					},
				},
				FamKey: *tweakedFamKey,
				Sig:    *famSig,
			}
		}

		// Next, we'll populate the asset genesis information which
		// includes the genesis prev out, and the other information
		// needed to derive an asset ID.
		var genesisPrevOut wire.OutPoint
		if err := readOutPoint(
			bytes.NewReader(sprout.GenesisPrevOut), 0, 0,
			&genesisPrevOut,
		); err != nil {
			return nil, fmt.Errorf("unable to read "+
				"outpoint: %w", err)
		}
		assetGenesis := asset.Genesis{
			FirstPrevOut: genesisPrevOut,
			Tag:          sprout.AssetTag,
			Metadata:     sprout.MetaData,
			OutputIndex:  uint32(sprout.GenesisOutputIndex),
		}

		// With the base information extracted, we'll use that to
		// create either a normal asset or a collectible.
		var assetSprout *asset.Asset
		lockTime := extractSqlInt32[uint64](sprout.LockTime)
		relativeLocktime := extractSqlInt32[uint64](
			sprout.RelativeLockTime,
		)
		if asset.Type(sprout.AssetType) == asset.Normal {
			assetSprout = asset.New(
				&assetGenesis, uint64(sprout.Amount), lockTime,
				relativeLocktime, scriptKey, familyKey,
			)
		} else {
			assetSprout = asset.NewCollectible(
				&assetGenesis, lockTime, relativeLocktime,
				scriptKey, familyKey,
			)
		}

		anchorTx := wire.NewMsgTx(2)
		err = anchorTx.Deserialize(bytes.NewBuffer(sprout.AnchorTx))
		if err != nil {
			return nil, fmt.Errorf("unable to decode tx: %w", err)
		}

		// An asset will only have an anchor block hash once it has
		// confirmed, so we'll only parse this if it exists.
		var anchorBlockHash chainhash.Hash
		if sprout.AnchorBlockHash != nil {
			anchorHash, err := chainhash.NewHash(
				sprout.AnchorBlockHash,
			)
			if err != nil {
				return nil, fmt.Errorf("unable to extract block "+
					"hash: %w", err)
			}
			anchorBlockHash = *anchorHash
		}

		var anchorOutpoint wire.OutPoint
		err = readOutPoint(
			bytes.NewReader(sprout.AnchorOutpoint), 0, 0,
			&anchorOutpoint,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to decode "+
				"outpoint: %w", err)
		}

		chainAssets[i] = &ChainAsset{
			Asset:           assetSprout,
			AnchorTx:        anchorTx,
			AnchorTxid:      anchorTx.TxHash(),
			AnchorBlockHash: anchorBlockHash,
			AnchorOutpoint:  anchorOutpoint,
		}
	}

	return chainAssets, nil
}
