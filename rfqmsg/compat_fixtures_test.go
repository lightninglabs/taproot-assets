package rfqmsg

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightningnetwork/lnd/tlv"
	"github.com/stretchr/testify/require"
)

const (
	// compatFixtureVersion is the current version string used for
	// organizing backward compatibility fixtures. Update this when
	// cutting a new release.
	compatFixtureVersion = "v0.8"

	// compatFixtureDir is the directory under testdata where versioned
	// compat fixtures are stored.
	compatFixtureDir = "compat"
)

// compatFixturePath returns the testdata-relative path for a compat fixture
// file.
func compatFixturePath(version, name string) string {
	return filepath.Join(compatFixtureDir, version, name)
}

// TestGenerateCompatFixtures generates deterministic wire format fixtures for
// the current version of the RFQ message types. These fixtures are committed
// to the repository and used by TestBackwardCompatFixtures to verify that
// future code changes don't break decoding of historical wire formats.
//
// Run with: make unit gen-test-vectors=true pkg=rfqmsg case=^TestGenerateCompatFixtures$
func TestGenerateCompatFixtures(t *testing.T) {
	t.Parallel()

	// Use deterministic test data so fixtures are reproducible.
	var (
		idBytes      [32]byte
		assetIDBytes [32]byte
	)
	copy(idBytes[:], bytes.Repeat([]byte{0xaa}, 32))
	copy(assetIDBytes[:], bytes.Repeat([]byte{0xbb}, 32))

	id := ID(idBytes)
	assetID := asset.ID(assetIDBytes)
	var zeroAssetID asset.ID

	// --- Request fixture ---
	req := requestWireMsgData{
		Version: tlv.NewPrimitiveRecord[tlv.TlvType0](V1),
		ID:      tlv.NewPrimitiveRecord[tlv.TlvType2](id),
		// Use a far-future timestamp so the fixture stays valid
		// across all test runs (year 2099).
		Expiry: tlv.NewPrimitiveRecord[tlv.TlvType6](
			uint64(4102444800),
		),
		InAssetID: tlv.SomeRecordT[tlv.TlvType9](
			tlv.NewPrimitiveRecord[tlv.TlvType9](assetID),
		),
		OutAssetID: tlv.SomeRecordT[tlv.TlvType13](
			tlv.NewPrimitiveRecord[tlv.TlvType13](zeroAssetID),
		),
		MaxInAsset: tlv.NewPrimitiveRecord[tlv.TlvType16](
			uint64(50000),
		),
	}
	reqBytes, err := req.Bytes()
	require.NoError(t, err)
	test.WriteTestFileHex(
		t, compatFixturePath(compatFixtureVersion, "request.hex"),
		reqBytes,
	)

	// --- Accept fixture ---
	var sig [64]byte
	copy(sig[:], bytes.Repeat([]byte{0xcc}, 64))

	inRate := NewTlvFixedPointFromUint64(42000, 2)
	outRate := NewTlvFixedPointFromUint64(1, 0)

	accept := acceptWireMsgData{
		Version:      tlv.NewPrimitiveRecord[tlv.TlvType0](V1),
		ID:           tlv.NewPrimitiveRecord[tlv.TlvType2](id),
		Expiry:       tlv.NewPrimitiveRecord[tlv.TlvType4](uint64(4102444800)),
		Sig:          tlv.NewPrimitiveRecord[tlv.TlvType6](sig),
		InAssetRate:  tlv.NewRecordT[tlv.TlvType8](inRate),
		OutAssetRate: tlv.NewRecordT[tlv.TlvType10](outRate),
	}
	acceptBytes, err := accept.Bytes()
	require.NoError(t, err)
	test.WriteTestFileHex(
		t, compatFixturePath(compatFixtureVersion, "accept.hex"),
		acceptBytes,
	)

	// --- Reject fixture ---
	reject := rejectWireMsgData{
		Version: tlv.NewPrimitiveRecord[tlv.TlvType0](V1),
		ID:      tlv.NewPrimitiveRecord[tlv.TlvType2](id),
		Err: tlv.NewRecordT[tlv.TlvType5](RejectErr{
			Code: PriceOracleUnavailableRejectCode,
			Msg:  "rates expired",
		}),
	}
	rejectBytes, err := reject.Bytes()
	require.NoError(t, err)
	test.WriteTestFileHex(
		t, compatFixturePath(compatFixtureVersion, "reject.hex"),
		rejectBytes,
	)

	// --- HTLC fixture ---
	htlc := NewHtlc(
		[]*AssetBalance{
			NewAssetBalance(assetID, 1000),
		},
		fn.Some(id),
		fn.None[[]ID](),
	)
	htlcBytes := htlc.Bytes()
	test.WriteTestFileHex(
		t, compatFixturePath(compatFixtureVersion, "htlc.hex"),
		htlcBytes,
	)
}
