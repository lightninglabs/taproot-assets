package commands

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/urfave/cli"
)

// TestCommandShortNamesUnique ensures that all command short names are unique
// within their respective command groups at the same level to avoid conflicts.
func TestCommandShortNamesUnique(t *testing.T) {
	// Create a new app to get all commands.
	app := NewApp()

	// Helper function to check short names within a group of commands at
	// the same level.
	//
	// Note that we define using var here to avoid recursion issues.
	var checkLevel func(commands []cli.Command, groupPath string)
	checkLevel = func(commands []cli.Command, groupPath string) {
		shortNames := make(map[string][]string)

		// Check short names only at this level (not recursively).
		for _, cmd := range commands {
			// Check if command has a short name.
			if cmd.ShortName == "" {
				continue
			}

			// Command has a short name, so we add it to the map.
			commandPath := groupPath
			if commandPath != "" {
				commandPath += " "
			}

			commandPath += cmd.Name
			shortNames[cmd.ShortName] = append(
				shortNames[cmd.ShortName], commandPath,
			)
		}

		// Check for duplicates at this level.
		var duplicates []string
		for shortName, paths := range shortNames {
			if len(paths) > 1 {
				duplicates = append(duplicates, shortName)
			}
		}

		// Fail the test if any duplicates were found at this level.
		require.Empty(t, duplicates, "Found duplicate short names at "+
			"command level '%s'", groupPath)

		// Log all short names for reference (only in verbose mode).
		if testing.Verbose() {
			t.Logf("Level '%s' has %d unique short names:",
				groupPath, len(shortNames))
			for shortName, paths := range shortNames {
				t.Logf("  %s -> %s", shortName, paths[0])
			}
		}

		// Recursively check subcommands at their respective levels.
		for _, cmd := range commands {
			if len(cmd.Subcommands) > 0 {
				// Formulate subgroup path.
				subGroupPath := groupPath
				if subGroupPath != "" {
					subGroupPath += " "
				}
				subGroupPath += cmd.Name

				// Recursively check subcommands.
				checkLevel(cmd.Subcommands, subGroupPath)
			}
		}
	}

	// Check top-level commands.
	checkLevel(app.Commands, "")
}

// TestDetectNodeNetwork tests the detectNodeNetwork function with various
// config file scenarios.
func TestDetectNodeNetwork(t *testing.T) {
	tests := []struct {
		name         string
		configContent string
		expectedNetwork string
	}{
		{
			name: "mainnet config",
			configContent: `network=mainnet
tlscertpath=/path/to/cert
`,
			expectedNetwork: "mainnet",
		},
		{
			name: "testnet config",
			configContent: `# Comment line
network=testnet
; Another comment
tlscertpath=/path/to/cert
`,
			expectedNetwork: "testnet",
		},
		{
			name: "testnet4 config",
			configContent: `network=testnet4
debuglevel=info
`,
			expectedNetwork: "testnet4",
		},
		{
			name: "no network setting",
			configContent: `tlscertpath=/path/to/cert
debuglevel=info
`,
			expectedNetwork: "",
		},
		{
			name: "invalid network",
			configContent: `network=invalid
tlscertpath=/path/to/cert
`,
			expectedNetwork: "",
		},
		{
			name: "empty config",
			configContent: "",
			expectedNetwork: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tempDir, err := os.MkdirTemp("", "tapd-config-test")
			require.NoError(t, err)
			defer os.RemoveAll(tempDir)

			configPath := filepath.Join(tempDir, "tapd.conf")
			err = os.WriteFile(configPath, []byte(test.configContent), 0644)
			require.NoError(t, err)

			// Test the function
			detectedNetwork := detectNodeNetwork(tempDir)
			require.Equal(t, test.expectedNetwork, detectedNetwork)
		})
	}

	t.Run("config file does not exist", func(t *testing.T) {
		tempDir, err := os.MkdirTemp("", "tapd-config-test")
		require.NoError(t, err)
		defer os.RemoveAll(tempDir)

		// Test with non-existent config file
		detectedNetwork := detectNodeNetwork(tempDir)
		require.Equal(t, "", detectedNetwork)
	})
}

// TestNetworkMismatchError tests that network mismatch errors provide helpful
// suggestions with corrected command arguments.
func TestNetworkMismatchError(t *testing.T) {
	tests := []struct {
		name             string
		requestedNetwork string
		configNetwork    string
		originalArgs     []string
		expectedErrorContains []string
	}{
		{
			name:             "testnet to mainnet with --network flag",
			requestedNetwork: "testnet",
			configNetwork:    "mainnet",
			originalArgs:     []string{"tapcli", "--network=testnet", "universe", "roots"},
			expectedErrorContains: []string{
				"[ERR] Network mismatch detected!",
				"Requested network: testnet",
				"Node configured for: mainnet",
				"--network=mainnet",
			},
		},
		{
			name:             "mainnet to testnet with -n flag",
			requestedNetwork: "mainnet",
			configNetwork:    "testnet",
			originalArgs:     []string{"tapcli", "-n", "mainnet", "universe", "info"},
			expectedErrorContains: []string{
				"[ERR] Network mismatch detected!",
				"Requested network: mainnet",
				"Node configured for: testnet",
				"-n testnet",
			},
		},
		{
			name:             "regtest to signet without explicit network flag",
			requestedNetwork: "regtest",
			configNetwork:    "signet",
			originalArgs:     []string{"tapcli", "universe", "federation", "sync"},
			expectedErrorContains: []string{
				"[ERR] Network mismatch detected!",
				"Requested network: regtest",
				"Node configured for: signet",
				"--network=signet",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tempDir, err := os.MkdirTemp("", "tapd-network-test")
			require.NoError(t, err)
			defer os.RemoveAll(tempDir)

			// Create tapd.conf with the configured network
			configContent := fmt.Sprintf("network=%s\n", test.configNetwork)
			configPath := filepath.Join(tempDir, "tapd.conf")
			err = os.WriteFile(configPath, []byte(configContent), 0644)
			require.NoError(t, err)

			// Set up the CLI context
			app := cli.NewApp()
			set := flag.NewFlagSet("test", flag.ContinueOnError)
			set.String("network", test.requestedNetwork, "")
			set.String("tapddir", tempDir, "")
			set.String("macaroonpath", "", "")

			ctx := cli.NewContext(app, set, nil)

			// Mock os.Args for the test
			oldArgs := os.Args
			os.Args = test.originalArgs
			defer func() { os.Args = oldArgs }()

			// Call profileFromContext - it should fail with network mismatch
			_, err = profileFromContext(ctx, false, false)

			// Verify the error contains expected elements
			require.Error(t, err)
			errorMsg := err.Error()
			for _, expected := range test.expectedErrorContains {
				require.Contains(t, errorMsg, expected,
					"Error message should contain: %s", expected)
			}
		})
	}
}
