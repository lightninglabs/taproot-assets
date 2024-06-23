package json

import (
	"net/url"
	"testing"

	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
)

func NewAddress(a *address.Tap) (*Address, error) {
	ta := &Address{
		Version:          uint8(a.Version),
		ChainParamsHRP:   a.ChainParams.TapHRP,
		AssetVersion:     uint8(a.AssetVersion),
		AssetID:          a.AssetID.String(),
		ScriptKey:        test.HexPubKey(&a.ScriptKey),
		InternalKey:      test.HexPubKey(&a.InternalKey),
		GroupKey:         test.HexPubKey(a.GroupKey),
		Amount:           a.Amount,
		ProofCourierAddr: a.ProofCourierAddr.String(),
	}

	if a.TapscriptSibling != nil {
		var err error
		ta.TapscriptSibling, err = HexTapscriptSibling(
			a.TapscriptSibling,
		)
		if err != nil {
			return nil, err
		}
	}

	return ta, nil
}

type Address struct {
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

func (ta *Address) ToAddress(t testing.TB) *address.Tap {
	t.Helper()

	// Validate minimum fields are set. We use panic, so we can actually
	// interpret the error message in the error test cases.
	if ta.ChainParamsHRP == "" {
		panic("missing chain params HRP")
	}
	if !address.IsBech32MTapPrefix(ta.ChainParamsHRP + "1") {
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

	chainParams, err := address.Net(ta.ChainParamsHRP)
	if err != nil {
		panic(err)
	}

	proofCourierAddr, err := url.ParseRequestURI(ta.ProofCourierAddr)
	if err != nil {
		panic(err)
	}

	a := &address.Tap{
		Version:          address.Version(ta.Version),
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
		a.TapscriptSibling = ParseTapscriptSibling(
			t, ta.TapscriptSibling,
		)
	}

	return a
}
