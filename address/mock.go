package address

import (
	"net/url"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/internal/test"
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
func RandAddr(t testing.TB, params *ChainParams,
	proofCourierAddr url.URL) (*AddrWithKeyInfo,
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

	genesis := asset.RandGenesis(t, asset.Type(test.RandInt31n(2)))
	amount := test.RandInt[uint64]()
	if genesis.Type == asset.Collectible {
		amount = 1
	}

	var (
		assetVersion     asset.Version
		groupInfo        *asset.GroupKey
		groupPubKey      *btcec.PublicKey
		groupWitness     wire.TxWitness
		tapscriptSibling *commitment.TapscriptPreimage
	)

	if test.RandInt[uint32]()%2 == 0 {
		assetVersion = asset.V1
	}

	if test.RandInt[uint32]()%2 == 0 {
		protoAsset := asset.NewAssetNoErr(
			t, genesis, amount, 0, 0, scriptKey, nil,
			asset.WithAssetVersion(assetVersion),
		)
		groupInfo = asset.RandGroupKey(t, genesis, protoAsset)
		groupPubKey = &groupInfo.GroupPubKey
		groupWitness = groupInfo.Witness

		var err error
		tapscriptSibling, err = commitment.NewPreimageFromLeaf(
			txscript.NewBaseTapLeaf([]byte("not a valid script")),
		)
		require.NoError(t, err)
	}

	tapAddr, err := New(
		V0, genesis, groupPubKey, groupWitness, *scriptKey.PubKey,
		*internalKey.PubKey(), amount, tapscriptSibling, params,
		proofCourierAddr, WithAssetVersion(assetVersion),
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

type ValidTestCase struct {
	Address  *TestAddress `json:"address"`
	Expected string       `json:"expected"`
	Comment  string       `json:"comment"`
}

type ErrorTestCase struct {
	Address *TestAddress `json:"address"`
	Error   string       `json:"error"`
	Comment string       `json:"comment"`
}

type TestVectors struct {
	ValidTestCases []*ValidTestCase `json:"valid_test_cases"`
	ErrorTestCases []*ErrorTestCase `json:"error_test_cases"`
}

func NewTestFromAddress(t testing.TB, a *Tap) *TestAddress {
	t.Helper()

	ta := &TestAddress{
		Version:          uint8(a.Version),
		ChainParamsHRP:   a.ChainParams.TapHRP,
		AssetVersion:     uint8(a.AssetVersion),
		AssetID:          a.AssetID.String(),
		ScriptKey:        test.HexPubKey(&a.ScriptKey),
		InternalKey:      test.HexPubKey(&a.InternalKey),
		Amount:           a.Amount,
		ProofCourierAddr: a.ProofCourierAddr.String(),
	}

	if a.GroupKey != nil {
		ta.GroupKey = test.HexPubKey(a.GroupKey)
	}

	if a.TapscriptSibling != nil {
		ta.TapscriptSibling = commitment.HexTapscriptSibling(
			t, a.TapscriptSibling,
		)
	}

	return ta
}

type TestAddress struct {
	Version          uint8  `json:"version"`
	ChainParamsHRP   string `json:"chain_params_hrp"`
	AssetVersion     uint8  `json:"asset_version"`
	AssetID          string `json:"asset_id"`
	GroupKey         string `json:"group_key"`
	ScriptKey        string `json:"script_key"`
	InternalKey      string `json:"internal_key"`
	TapscriptSibling string `json:"tapscript_sibling"`
	Amount           uint64 `json:"amount"`
	ProofCourierAddr string `json:"proof_courier_addr"`
}

func (ta *TestAddress) ToAddress(t testing.TB) *Tap {
	t.Helper()

	// Validate minimum fields are set. We use panic, so we can actually
	// interpret the error message in the error test cases.
	if ta.ChainParamsHRP == "" {
		panic("missing chain params HRP")
	}
	if !IsBech32MTapPrefix(ta.ChainParamsHRP + "1") {
		panic("invalid chain params HRP")
	}

	if ta.AssetID == "" {
		panic("missing asset ID")
	}

	if ta.ScriptKey == "" {
		panic("missing script key")
	}
	if len(ta.ScriptKey) != test.HexCompressedPubKeyLen {
		panic("invalid script key length")
	}

	if ta.InternalKey == "" {
		panic("missing internal key")
	}
	if len(ta.InternalKey) != test.HexCompressedPubKeyLen {
		panic("invalid internal key length")
	}

	if ta.GroupKey != "" {
		if len(ta.GroupKey) != test.HexCompressedPubKeyLen {
			panic("invalid group key length")
		}
	}

	chainParams, err := Net(ta.ChainParamsHRP)
	if err != nil {
		panic(err)
	}

	proofCourierAddr, err := url.ParseRequestURI(ta.ProofCourierAddr)
	if err != nil {
		panic(err)
	}

	a := &Tap{
		Version:          Version(ta.Version),
		ChainParams:      chainParams,
		AssetVersion:     asset.Version(ta.AssetVersion),
		AssetID:          test.Parse32Byte(t, ta.AssetID),
		ScriptKey:        *test.ParsePubKey(t, ta.ScriptKey),
		InternalKey:      *test.ParsePubKey(t, ta.InternalKey),
		Amount:           ta.Amount,
		ProofCourierAddr: *proofCourierAddr,
	}

	if ta.GroupKey != "" {
		a.GroupKey = test.ParsePubKey(t, ta.GroupKey)
	}

	if ta.TapscriptSibling != "" {
		a.TapscriptSibling = commitment.ParseTapscriptSibling(
			t, ta.TapscriptSibling,
		)
	}

	return a
}
