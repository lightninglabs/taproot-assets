package scenario

import (
	"encoding/hex"
	"os"
	"strings"
)

// readHexFile reads a hex-encoded blob from disk and returns the decoded
// bytes, trimming surrounding whitespace.
func readHexFile(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(strings.TrimSpace(string(raw)))
}
