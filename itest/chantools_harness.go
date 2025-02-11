package itest

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/stretchr/testify/require"
)

// chantoolsCmdBuilder is a helper function that creates a new exec.Cmd instance
// for the chantools binary.
func chantoolsCmdBuilder(binPath string, workingDir string,
	args ...string) exec.Cmd {

	cmd := exec.Command(binPath, args...)

	// Set the working directory so that any log files are handled
	// gracefully.
	cmd.Dir = workingDir

	// Set the wallet password.
	cmd.Env = append(os.Environ(), "WALLET_PASSWORD=-")

	// Set the seed generation passphrase.
	cmd.Env = append(cmd.Env, "AEZEED_PASSPHRASE=-")

	return *cmd
}

// ChantoolsHarness is a helper struct that provides a way to interact with
// the chantools binary.
type ChantoolsHarness struct {
	// path is the path to the chantools binary.
	path string

	// workingDir is the chantools harness working directory.
	workingDir string

	// walletDbPath is the path to the wallet.db file created by chantools.
	walletDbPath string
}

// NewChantoolsHarness creates a new instance of the ChantoolsHarness struct.
func NewChantoolsHarness(t *testing.T) ChantoolsHarness {
	wd, err := os.Getwd()
	require.NoError(t, err)
	path := fmt.Sprintf("%s/chantools/chantools", wd)

	t.Logf("Using chantools binary at: %v", path)

	// Create a temporary directory to store the log file and wallet.db
	// file.
	workingDir, err := os.MkdirTemp("", "itest-tapd-chantools")
	require.NoError(t, err, "failed to create chantools working directory")

	// Assert that the version of chantools is as expected.
	cmd := chantoolsCmdBuilder(path, workingDir, "--version")
	versionOut, err := cmd.CombinedOutput()
	require.NoError(t, err, "failed to get chantools version")

	versionOutStr := string(versionOut)
	if !strings.Contains(versionOutStr, "chantools version v0.13.5") {
		t.Fatalf("unexpected chantools version: %v", versionOutStr)
	}

	return ChantoolsHarness{
		path:         path,
		workingDir:   workingDir,
		walletDbPath: filepath.Join(workingDir, "wallet.db"),
	}
}

// buildCmd is a helper method that creates a new exec.Cmd instance for the
// chantools binary.
func (c *ChantoolsHarness) buildCmd(args ...string) exec.Cmd {
	return chantoolsCmdBuilder(c.path, c.workingDir, args...)
}

// CreateWallet creates a new wallet using the chantools binary.
func (c *ChantoolsHarness) CreateWallet(t *testing.T) {
	cmd := c.buildCmd(
		"--regtest", "createwallet", "--bip39",
		"--generateseed", "--walletdbdir", c.workingDir,
	)

	cmdOut, err := cmd.CombinedOutput()
	require.NoError(t, err)

	t.Logf("Chantools createwallet output: %v", string(cmdOut))
}

// DeriveKey derives a new key using the chantools binary.
func (c *ChantoolsHarness) DeriveKey(t *testing.T) (string, string) {
	cmd := c.buildCmd(
		"--regtest", "derivekey", "--walletdb", c.walletDbPath,
		"--path", "m/86'/1'/0'", "--neuter",
	)

	cmdOut, err := cmd.CombinedOutput()
	require.NoError(t, err)

	cmdOutStr := string(cmdOut)
	t.Logf("Chantools derivekey output: %v", cmdOutStr)

	// Parsing for xpub.
	xpubPattern := `Extended public key \(xpub\):\s+([a-zA-Z0-9]+)`
	xpubRegex := regexp.MustCompile(xpubPattern)
	matches := xpubRegex.FindStringSubmatch(cmdOutStr)
	require.Len(t, matches, 2)

	xpub := matches[1]
	require.NotEmpty(t, xpub)

	// Parsing for master fingerprint.
	fingerprintPattern := `Master Fingerprint:\s+([a-f0-9]+)`
	fingerprintRegex := regexp.MustCompile(fingerprintPattern)
	matches = fingerprintRegex.FindStringSubmatch(cmdOutStr)
	require.Len(t, matches, 2)

	masterFingerprint := matches[1]
	require.Len(t, masterFingerprint, 8)

	return xpub, masterFingerprint
}

// SignPsbt signs a PSBT using the chantools binary.
func (c *ChantoolsHarness) SignPsbt(t *testing.T, psbtStr string) psbt.Packet {
	cmd := c.buildCmd(
		"--regtest", "signpsbt", "--walletdb", c.walletDbPath,
		"--psbt", psbtStr,
	)

	cmdOut, err := cmd.CombinedOutput()
	require.NoError(t, err)

	cmdOutStr := string(cmdOut)
	t.Logf("Chantools signpsbt output: %v", cmdOutStr)

	// Extract the signed PSBT.
	psbtPattern := `Successfully signed PSBT:\n\n([a-zA-Z0-9+/=]+)`
	psbtRegex := regexp.MustCompile(psbtPattern)
	matches := psbtRegex.FindStringSubmatch(cmdOutStr)
	require.Len(t, matches, 2)

	signedPsbtStr := matches[1]
	require.NotEmpty(t, signedPsbtStr)

	// Parse the signed PSBT.
	signedPsbt, err := psbt.NewFromRawBytes(bytes.NewReader(
		[]byte(signedPsbtStr)), true,
	)
	require.NoError(t, err)

	return *signedPsbt
}
