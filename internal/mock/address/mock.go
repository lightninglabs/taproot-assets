package address

import (
	"net/url"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	assetmock "github.com/lightninglabs/taproot-assets/internal/mock/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/json"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

// RandProofCourierAddr returns a proof courier address with fields populated
// with valid but random values.
func RandProofCourierAddr(t testing.TB) url.URL {
	// TODO(ffranr): Add more randomness to the address.
	addr, err := url.ParseRequestURI(
		"hashmail://rand.hashmail.proof.courier:443",
	)
	require.NoError(t, err)

	return *addr
}

// RandAddr creates a random address for testing.
func RandAddr(t testing.TB, params *address.ChainParams,
	proofCourierAddr url.URL) (*address.AddrWithKeyInfo,
	*asset.Genesis, *asset.GroupKey) {

	scriptKeyPriv := test.RandPrivKey(t)
	scriptKey := asset.NewScriptKeyBip86(keychain.KeyDescriptor{
		PubKey: scriptKeyPriv.PubKey(),
		KeyLocator: keychain.KeyLocator{
			Family: keychain.KeyFamily(test.RandIntn(255) + 1),
			Index:  uint32(test.RandIntn(255)),
		},
	})

	internalKey := test.RandPrivKey(t)

	genesis := assetmock.RandGenesis(t, asset.Type(test.RandInt31n(2)))
	amount := test.RandInt[uint64]()
	if genesis.Type == asset.Collectible {
		amount = 1
	}

	var (
		assetVersion     asset.Version
		addrVersion      address.Version
		groupInfo        *asset.GroupKey
		groupPubKey      *btcec.PublicKey
		groupWitness     wire.TxWitness
		tapscriptSibling *commitment.TapscriptPreimage
	)

	if test.RandBool() {
		assetVersion = asset.V1
	}

	if test.RandBool() {
		protoAsset := assetmock.NewAssetNoErr(
			t, genesis, amount, 0, 0, scriptKey, nil,
			asset.WithAssetVersion(assetVersion),
		)
		groupInfo = assetmock.RandGroupKey(t, genesis, protoAsset)
		groupPubKey = &groupInfo.GroupPubKey
		groupWitness = groupInfo.Witness

		var err error
		tapscriptSibling, err = commitment.NewPreimageFromLeaf(
			txscript.NewBaseTapLeaf([]byte("not a valid script")),
		)
		require.NoError(t, err)
	}

	addrVersion = test.RandFlip(address.V0, address.V1)
	tapAddr, err := address.New(
		addrVersion, genesis, groupPubKey, groupWitness,
		*scriptKey.PubKey, *internalKey.PubKey(), amount,
		tapscriptSibling, params, proofCourierAddr,
		address.WithAssetVersion(assetVersion),
	)
	require.NoError(t, err)

	taprootOutputKey, err := tapAddr.TaprootOutputKey()
	require.NoError(t, err)

	return &address.AddrWithKeyInfo{
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

type ValidTestCase struct {
	Address  *json.Address `json:"address"`
	Expected string        `json:"expected"`
	Comment  string        `json:"comment"`
}

type ErrorTestCase struct {
	Address *json.Address `json:"address"`
	Error   string        `json:"error"`
	Comment string        `json:"comment"`
}

type TestVectors struct {
	ValidTestCases []*ValidTestCase `json:"valid_test_cases"`
	ErrorTestCases []*ErrorTestCase `json:"error_test_cases"`
}
