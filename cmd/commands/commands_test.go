package commands

import (
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
