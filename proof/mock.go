package proof

import (
	"context"
	"io"
	"testing"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/internal/test"
)

type MockVerifier struct {
	t *testing.T
}

func NewMockVerifier(t *testing.T) *MockVerifier {
	return &MockVerifier{
		t: t,
	}
}

func (m *MockVerifier) Verify(_ context.Context, _ io.Reader,
	headerVerifier HeaderVerifier) (*AssetSnapshot, error) {

	return &AssetSnapshot{
		Asset: &asset.Asset{

			GroupKey: &asset.GroupKey{
				GroupPubKey: *test.RandPubKey(m.t),
			},
			ScriptKey: asset.NewScriptKey(test.RandPubKey(m.t)),
		},
	}, nil
}

// MockHeaderVerifier is a mock verifier which approves of all block headers.
//
// Header verification usually involves cross-referencing with chain data.
// Chain data is not available in unit tests. This function is useful for unit
// tests which are not primarily concerned with block header verification.
func MockHeaderVerifier(blockHeader wire.BlockHeader) error {
	return nil
}
