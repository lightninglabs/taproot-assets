package address

import (
	"math/rand"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/commitment"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

// RandAddr creates a random address for testing.
func RandAddr(t testing.TB, params *ChainParams) (*AddrWithKeyInfo,
	*asset.Genesis, *asset.GroupKey) {

	scriptKeyPriv, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	internalKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	genesis := asset.RandGenesis(t, asset.Type(rand.Int31n(2)))
	amount := uint64(rand.Int63())
	if genesis.Type == asset.Collectible {
		amount = 1
	}

	var (
		groupInfo        *asset.GroupKey
		groupPubKey      *btcec.PublicKey
		groupSig         *schnorr.Signature
		tapscriptSibling *commitment.TapscriptPreimage
	)
	if rand.Int31()%2 == 0 {
		groupInfo = asset.RandGroupKey(t, genesis)
		groupPubKey = &groupInfo.GroupPubKey
		groupSig = &groupInfo.Sig

		tapscriptSibling = commitment.NewPreimageFromLeaf(
			txscript.NewBaseTapLeaf([]byte("not a valid script")),
		)
	}

	scriptKey := asset.NewScriptKeyBip86(keychain.KeyDescriptor{
		PubKey: scriptKeyPriv.PubKey(),
		KeyLocator: keychain.KeyLocator{
			Family: keychain.KeyFamily(rand.Intn(255) + 1),
			Index:  uint32(rand.Intn(255)),
		},
	})

	taro, err := New(
		genesis, groupPubKey, groupSig, *scriptKey.PubKey,
		*internalKey.PubKey(), amount, tapscriptSibling, params,
	)
	require.NoError(t, err)

	taprootOutputKey, err := taro.TaprootOutputKey()
	require.NoError(t, err)

	return &AddrWithKeyInfo{
		Taro:           taro,
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
	}, &genesis, groupInfo
}
