package address

import (
	"math/rand"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

// RandAddr creates a random address for testing.
func RandAddr(t testing.TB, params *ChainParams) *AddrWithKeyInfo {
	scriptKeyPriv, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	internalKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	genesis := asset.RandGenesis(t, asset.Type(rand.Int31n(2)))
	amount := uint64(rand.Int63())
	if genesis.Type == asset.Collectible {
		amount = 1
	}

	var famKey *btcec.PublicKey
	if rand.Int31()%2 == 0 {
		famKeyPriv, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		famKey = famKeyPriv.PubKey()
	}

	scriptKey := asset.NewScriptKeyBIP0086(keychain.KeyDescriptor{
		PubKey: scriptKeyPriv.PubKey(),
	})

	taprootOutputKey, _ := schnorr.ParsePubKey(schnorr.SerializePubKey(
		txscript.ComputeTaprootOutputKey(internalKey.PubKey(), nil),
	))

	return &AddrWithKeyInfo{
		Taro: &Taro{
			Version:     asset.Version(rand.Int31()),
			Genesis:     genesis,
			FamilyKey:   famKey,
			ScriptKey:   *scriptKey.PubKey,
			InternalKey: *internalKey.PubKey(),
			Amount:      amount,
			ChainParams: params,
		},
		ScriptKeyTweak: *scriptKey.TweakedScriptKey,
		InternalKeyDesc: keychain.KeyDescriptor{
			KeyLocator: keychain.KeyLocator{
				Family: keychain.KeyFamily(rand.Int31()),
				Index:  uint32(rand.Int31()),
			},
			PubKey: internalKey.PubKey(),
		},
		TaprootOutputKey: *taprootOutputKey,
		CreationTime:     time.Now(),
	}
}
