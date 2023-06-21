package address

import (
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

// RandAddr creates a random address for testing.
func RandAddr(t testing.TB, params *ChainParams) (*AddrWithKeyInfo,
	*asset.Genesis, *asset.GroupKey) {

	scriptKeyPriv := test.RandPrivKey(t)

	internalKey := test.RandPrivKey(t)

	genesis := asset.RandGenesis(t, asset.Type(test.RandInt31n(2)))
	amount := test.RandInt[uint64]()
	if genesis.Type == asset.Collectible {
		amount = 1
	}

	var (
		groupInfo        *asset.GroupKey
		groupPubKey      *btcec.PublicKey
		groupSig         *schnorr.Signature
		tapscriptSibling *commitment.TapscriptPreimage
	)
	if test.RandInt[uint32]()%2 == 0 {
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
			Family: keychain.KeyFamily(test.RandIntn(255) + 1),
			Index:  uint32(test.RandIntn(255)),
		},
	})

	tapAddr, err := New(
		genesis, groupPubKey, groupSig, *scriptKey.PubKey,
		*internalKey.PubKey(), amount, tapscriptSibling, params,
	)
	require.NoError(t, err)

	taprootOutputKey, err := tapAddr.TaprootOutputKey()
	require.NoError(t, err)

	return &AddrWithKeyInfo{
		Tap:            tapAddr,
		ScriptKeyTweak: *scriptKey.TweakedScriptKey,
		InternalKeyDesc: keychain.KeyDescriptor{
			KeyLocator: keychain.KeyLocator{
				Family: keychain.KeyFamily(test.RandIntn(255)),
				Index:  test.RandInt[uint32](),
			},
			PubKey: internalKey.PubKey(),
		},
		TaprootOutputKey: *taprootOutputKey,
		CreationTime:     time.Now(),
	}, &genesis, groupInfo
}
