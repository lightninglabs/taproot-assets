package lncfg

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"
)

// CleanAndExpandPath expands environment variables and leading ~ in the passed
// path, cleans the result, and returns it.
func CleanAndExpandPath(path string) string {
	if path == "" {
		return ""
	}

	if strings.HasPrefix(path, "~") {
		var homeDir string
		u, err := user.Current()
		if err == nil {
			homeDir = u.HomeDir
		} else {
			homeDir = os.Getenv("HOME")
		}

		path = strings.Replace(path, "~", homeDir, 1)
	}

	return filepath.Clean(os.ExpandEnv(path))
}

// NormalizeNetwork returns the common name of a network type used to create
// file paths.
func NormalizeNetwork(network string) string {
	if network == "testnet4" {
		return network
	}

	if strings.HasPrefix(network, "testnet") {
		return "testnet"
	}

	return network
}
