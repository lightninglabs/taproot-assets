package address

import (
	"fmt"
	"math/rand"
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

// randomString returns a random string of given length.
func randomString(length int) string {
	rand.Seed(time.Now().UnixNano())

	letterBytes := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

	b := make([]byte, length)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

// RandProofCourierAddr returns a proof courier address with fields populated
// with valid but random values.
func RandProofCourierAddr() ProofCourierAddr {
	addr := fmt.Sprintf(
		"hashmail://rand.hashmail.proof.courier.%s:443",
		randomString(5),
	)

	return ProofCourierAddr(addr)
}

// RandAddr creates a random address for testing.
func RandAddr(t testing.TB, params *ChainParams,
	proofCourierAddr ProofCourierAddr) (*AddrWithKeyInfo,
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
		proofCourierAddr,
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
		ChainParamsHRP:   a.ChainParams.TapHRP,
		AssetVersion:     uint8(a.AssetVersion),
		AssetID:          a.AssetID.String(),
		ScriptKey:        test.HexPubKey(&a.ScriptKey),
		InternalKey:      test.HexPubKey(&a.InternalKey),
		Amount:           a.Amount,
		ProofCourierAddr: string(a.ProofCourierAddr),
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

	a := &Tap{
		ChainParams:      chainParams,
		AssetVersion:     asset.Version(ta.AssetVersion),
		AssetID:          test.Parse32Byte(t, ta.AssetID),
		ScriptKey:        *test.ParsePubKey(t, ta.ScriptKey),
		InternalKey:      *test.ParsePubKey(t, ta.InternalKey),
		Amount:           ta.Amount,
		ProofCourierAddr: ProofCourierAddr(ta.ProofCourierAddr),
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
