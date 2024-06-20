package tapchannelmsg

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	// This is the channel custom data which could not be decoded by the
	// previous version of the code due to size limitations.
	channelCustomDataHexFileName = filepath.Join(
		testDataFileName, "channel-custom-data.hex",
	)
)

func TestReadChannelCustomData(t *testing.T) {
	t.Parallel()

	// Read the custom data from the file and decode it.
	cdHex, err := os.ReadFile(channelCustomDataHexFileName)
	require.NoError(t, err)

	chanDataBytes, err := hex.DecodeString(
		strings.Trim(string(cdHex), "\n"),
	)
	require.NoError(t, err)

	chanData, err := ReadChannelCustomData(chanDataBytes)
	require.NoError(t, err)

	chanData = chanData
}
