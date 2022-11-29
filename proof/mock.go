package proof

import (
	"context"
	"io"
	"testing"

	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/internal/test"
)

type MockVerifier struct {
	t   *testing.T
	loc Locator
}

func NewMockVerifier(t *testing.T) *MockVerifier {
	return &MockVerifier{
		t: t,
	}
}

func (m *MockVerifier) feedLocator(loc *Locator) {
	m.loc = *loc
}

func (m *MockVerifier) Verify(_ context.Context, _ io.Reader) (*AssetSnapshot,
	error) {

	return &AssetSnapshot{
		Asset: &asset.Asset{

			GroupKey: &asset.GroupKey{
				GroupPubKey: *test.RandPubKey(m.t),
			},
			ScriptKey: asset.NewScriptKey(test.RandPubKey(m.t)),
		},
	}, nil
}
