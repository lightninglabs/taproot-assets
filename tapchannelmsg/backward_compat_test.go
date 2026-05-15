package tapchannelmsg

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/stretchr/testify/require"
)

// compatVersions lists all historical versions whose wire format fixtures we
// validate against the current code. Add new entries as releases are cut.
var compatVersions = []string{
	"v0.8",
}

// TestBackwardCompatFixtures verifies that all historical wire format fixtures
// for channel messages can be decoded by the current code. This test runs on
// every PR as part of normal CI.
//
// Unlike a full round-trip test, these fixtures are from real protocol
// interactions (captured from log hex dumps) so we only verify successful
// decode — the re-encoded form may differ due to optional field ordering
// changes.
func TestBackwardCompatFixtures(t *testing.T) {
	t.Parallel()

	for _, version := range compatVersions {
		version := version
		t.Run(version, func(t *testing.T) {
			t.Parallel()

			t.Run("funding blob", func(t *testing.T) {
				testCompatFundingBlob(t, version)
			})
			t.Run("commitment blob", func(t *testing.T) {
				testCompatCommitmentBlob(t, version)
			})
			t.Run("htlc blob", func(t *testing.T) {
				testCompatHtlcBlob(t, version)
			})
		})
	}
}

// testCompatFundingBlob tests that a historical funding blob can be decoded.
func testCompatFundingBlob(t *testing.T, version string) {
	t.Helper()

	path := filepath.Join(
		"testdata", "compat", version, "funding-blob.hexdump",
	)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		t.Skipf("fixture %s not found", path)
	}
	require.NoError(t, err)

	hexBytes, err := ExtractHexDump(string(data))
	require.NoError(t, err, "failed to extract hex from %s", path)

	openChan, err := DecodeOpenChannel(hexBytes)
	require.NoError(t, err, "failed to decode %s funding blob", version)
	require.NotEmpty(t, openChan.Assets(),
		"funding blob should contain assets")
}

// testCompatCommitmentBlob tests that a historical commitment blob can be
// decoded.
func testCompatCommitmentBlob(t *testing.T, version string) {
	t.Helper()

	path := filepath.Join(
		"testdata", "compat", version, "commitment-blob.hexdump",
	)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		t.Skipf("fixture %s not found", path)
	}
	require.NoError(t, err)

	hexBytes, err := ExtractHexDump(string(data))
	require.NoError(t, err, "failed to extract hex from %s", path)

	commit, err := DecodeCommitment(hexBytes)
	require.NoError(t, err,
		"failed to decode %s commitment blob", version)

	// Verify we can access the balance fields without panicking.
	_ = commit.LocalAssets.Val.Sum()
	_ = commit.RemoteAssets.Val.Sum()
}

// testCompatHtlcBlob tests that a historical HTLC blob can be decoded.
func testCompatHtlcBlob(t *testing.T, version string) {
	t.Helper()

	path := filepath.Join(
		"testdata", "compat", version, "htlc-blob.hexdump",
	)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		t.Skipf("fixture %s not found", path)
	}
	require.NoError(t, err)

	hexBytes, err := ExtractHexDump(string(data))
	require.NoError(t, err, "failed to extract hex from %s", path)

	htlc, err := rfqmsg.DecodeHtlc(hexBytes)
	require.NoError(t, err, "failed to decode %s HTLC blob", version)

	// Verify we can access the balances without panicking. The fixture
	// may have zero balances if it represents a no-op HTLC.
	_ = htlc.Balances()
}
