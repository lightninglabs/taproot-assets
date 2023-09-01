//go:build gen_test_vectors

package test

import (
	"encoding/hex"
	"encoding/json"
	prand "math/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	// rand is a global instance of a pseudo random generator. It is seeded
	// with a static value to allow generating deterministic test vectors.
	rand = prand.New(prand.NewSource(1))
)

func ParseTestVectors(t testing.TB, fileName string, target any) {
	fileBytes, err := os.ReadFile(filepath.Join("testdata", fileName))
	require.NoError(t, err)

	err = json.Unmarshal(fileBytes, target)
	require.NoError(t, err)
}

func WriteTestVectors(t testing.TB, fileName string, target any) {
	fileBytes, err := json.MarshalIndent(target, "", "  ")
	require.NoError(t, err)

	filePath := filepath.Join("testdata", fileName)
	err = os.WriteFile(filePath, fileBytes, 0644)
	require.NoError(t, err)
}

func WriteTestFileHex(t testing.TB, fileName string, content []byte) {
	filePath := filepath.Join("testdata", fileName)
	contentHex := hex.EncodeToString(content)
	err := os.WriteFile(filePath, []byte(contentHex), 0644)
	require.NoError(t, err)
}
