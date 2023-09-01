//go:build !gen_test_vectors

package test

import (
	"encoding/json"
	prand "math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var (
	// rand is a global instance of a pseudo random generator. It is seeded
	// with the current time when the package is loaded when we don't
	// require deterministic test vectors.
	rand = prand.New(prand.NewSource(time.Now().Unix()))
)

func ParseTestVectors(t testing.TB, fileName string, target any) {
	fileBytes, err := os.ReadFile(filepath.Join("testdata", fileName))
	require.NoError(t, err)

	err = json.Unmarshal(fileBytes, target)
	require.NoError(t, err)
}

func WriteTestVectors(t testing.TB, fileName string, target any) {
	// Nothing to do here, the build tag to enable generating test vectors
	// is turned off.
}

func WriteTestFileHex(t testing.TB, fileName string, content []byte) {
	// Nothing to do here, the build tag to enable generating test vectors
	// is turned off.
}
