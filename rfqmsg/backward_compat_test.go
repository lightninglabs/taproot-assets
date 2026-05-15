package rfqmsg

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// compatVersionsToTest lists all historical versions whose fixtures we
// validate against the current code. Add new entries as releases are cut.
var compatVersionsToTest = []string{
	"v0.8",
}

// readHexFixture reads a hex-encoded fixture file from the testdata/compat
// directory and returns the decoded bytes.
func readHexFixture(t *testing.T, version, name string) []byte {
	t.Helper()

	path := filepath.Join("testdata", compatFixtureDir, version, name)
	hexBytes, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		t.Skipf("fixture %s not found (run make gen-compat-fixtures "+
			"to generate)", path)
	}
	require.NoError(t, err)

	decoded, err := hex.DecodeString(string(hexBytes))
	require.NoError(t, err, "invalid hex in fixture %s", path)

	return decoded
}

// TestBackwardCompatFixtures verifies that all historical wire format fixtures
// can be successfully decoded by the current code and survive a round-trip
// encode/decode cycle. This test runs on every PR as part of normal CI.
func TestBackwardCompatFixtures(t *testing.T) {
	t.Parallel()

	for _, version := range compatVersionsToTest {
		version := version
		t.Run(version, func(t *testing.T) {
			t.Parallel()

			t.Run("request", func(t *testing.T) {
				testCompatRequest(t, version)
			})
			t.Run("accept", func(t *testing.T) {
				testCompatAccept(t, version)
			})
			t.Run("reject", func(t *testing.T) {
				testCompatReject(t, version)
			})
			t.Run("htlc", func(t *testing.T) {
				testCompatHtlc(t, version)
			})
		})
	}
}

// testCompatRequest tests that a historical request fixture can be decoded
// and re-encoded to produce identical bytes.
func testCompatRequest(t *testing.T, version string) {
	t.Helper()

	raw := readHexFixture(t, version, "request.hex")

	var req requestWireMsgData
	err := req.Decode(bytes.NewReader(raw))
	require.NoError(t, err, "failed to decode %s request fixture", version)

	// Re-encode and verify round-trip.
	reEncoded, err := req.Bytes()
	require.NoError(t, err, "failed to re-encode request")
	require.Equal(t, raw, reEncoded,
		"request round-trip mismatch for %s", version)
}

// testCompatAccept tests that a historical accept fixture can be decoded
// and re-encoded to produce identical bytes.
func testCompatAccept(t *testing.T, version string) {
	t.Helper()

	raw := readHexFixture(t, version, "accept.hex")

	var accept acceptWireMsgData
	err := accept.Decode(bytes.NewReader(raw))
	require.NoError(t, err, "failed to decode %s accept fixture", version)

	reEncoded, err := accept.Bytes()
	require.NoError(t, err, "failed to re-encode accept")
	require.Equal(t, raw, reEncoded,
		"accept round-trip mismatch for %s", version)
}

// testCompatReject tests that a historical reject fixture can be decoded
// and re-encoded to produce identical bytes.
func testCompatReject(t *testing.T, version string) {
	t.Helper()

	raw := readHexFixture(t, version, "reject.hex")

	var reject rejectWireMsgData
	err := reject.Decode(bytes.NewReader(raw))
	require.NoError(t, err, "failed to decode %s reject fixture", version)

	reEncoded, err := reject.Bytes()
	require.NoError(t, err, "failed to re-encode reject")
	require.Equal(t, raw, reEncoded,
		"reject round-trip mismatch for %s", version)
}

// testCompatHtlc tests that a historical HTLC fixture can be decoded
// and re-encoded to produce identical bytes.
func testCompatHtlc(t *testing.T, version string) {
	t.Helper()

	raw := readHexFixture(t, version, "htlc.hex")

	htlc, err := DecodeHtlc(raw)
	require.NoError(t, err, "failed to decode %s HTLC fixture", version)

	reEncoded := htlc.Bytes()
	require.Equal(t, raw, reEncoded,
		"HTLC round-trip mismatch for %s", version)
}
