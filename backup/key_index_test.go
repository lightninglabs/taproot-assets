package backup

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

type testKeyRing struct {
	next  map[keychain.KeyFamily]uint32
	calls map[keychain.KeyFamily]uint32
}

func newTestKeyRing() *testKeyRing {
	return &testKeyRing{
		next:  make(map[keychain.KeyFamily]uint32),
		calls: make(map[keychain.KeyFamily]uint32),
	}
}

func testKeyDesc(family keychain.KeyFamily,
	index uint32) keychain.KeyDescriptor {

	var keyMaterial [8]byte
	binary.BigEndian.PutUint32(keyMaterial[:4], uint32(family))
	binary.BigEndian.PutUint32(keyMaterial[4:], index)
	digest := sha256.Sum256(keyMaterial[:])
	_, pubKey := btcec.PrivKeyFromBytes(digest[:])

	return keychain.KeyDescriptor{
		PubKey: pubKey,
		KeyLocator: keychain.KeyLocator{
			Family: family,
			Index:  index,
		},
	}
}

func (t *testKeyRing) DeriveNextKey(_ context.Context,
	family keychain.KeyFamily) (keychain.KeyDescriptor, error) {

	index := t.next[family]
	t.next[family]++
	t.calls[family]++

	return testKeyDesc(family, index), nil
}

func (t *testKeyRing) IsLocalKey(_ context.Context,
	desc keychain.KeyDescriptor) bool {

	if desc.PubKey == nil {
		return false
	}

	expected := testKeyDesc(desc.Family, desc.Index)
	return expected.PubKey.IsEqual(desc.PubKey)
}

func keyMarker(family keychain.KeyFamily,
	index uint32) *KeyDescriptorBackup {

	desc := testKeyDesc(family, index)
	return &KeyDescriptorBackup{
		PubKey:     desc.PubKey,
		KeyLocator: desc.KeyLocator,
	}
}

// TestAdvanceKeyFamilyIndexes verifies marker restoration, monotonicity,
// legacy locator fallback, seed validation, and the resource bound.
func TestAdvanceKeyFamilyIndexes(t *testing.T) {
	t.Parallel()

	const family = keychain.KeyFamily(212)

	t.Run("explicit marker", func(t *testing.T) {
		ring := newTestKeyRing()
		wallet := &WalletBackup{
			KeyFamilyMarkers: []*KeyDescriptorBackup{
				keyMarker(family, 5),
			},
		}

		err := advanceKeyFamilyIndexes(
			context.Background(), wallet, ring,
		)
		require.NoError(t, err)
		require.Equal(t, uint32(6), ring.next[family])
		require.Equal(t, uint32(6), ring.calls[family])
	})

	t.Run("never rewinds", func(t *testing.T) {
		ring := newTestKeyRing()
		ring.next[family] = 8
		wallet := &WalletBackup{
			KeyFamilyMarkers: []*KeyDescriptorBackup{
				keyMarker(family, 5),
			},
		}

		err := advanceKeyFamilyIndexes(
			context.Background(), wallet, ring,
		)
		require.NoError(t, err)
		require.Equal(t, uint32(9), ring.next[family])
		require.Equal(t, uint32(1), ring.calls[family])
	})

	t.Run("legacy asset locator", func(t *testing.T) {
		ring := newTestKeyRing()
		desc := testKeyDesc(family, 4)
		wallet := &WalletBackup{
			Assets: []*AssetBackup{{
				ScriptKeyInfo: &ScriptKeyBackup{
					RawKey: desc,
				},
			}},
		}

		err := advanceKeyFamilyIndexes(
			context.Background(), wallet, ring,
		)
		require.NoError(t, err)
		require.Equal(t, uint32(5), ring.next[family])
	})

	t.Run("wrong seed", func(t *testing.T) {
		ring := newTestKeyRing()
		marker := keyMarker(family, 5)
		marker.PubKey = randPubKey(t)
		wallet := &WalletBackup{
			KeyFamilyMarkers: []*KeyDescriptorBackup{marker},
		}

		err := advanceKeyFamilyIndexes(
			context.Background(), wallet, ring,
		)
		require.NoError(t, err)
		require.Zero(t, ring.calls[family])
	})

	t.Run("advance limit", func(t *testing.T) {
		ring := newTestKeyRing()
		wallet := &WalletBackup{
			KeyFamilyMarkers: []*KeyDescriptorBackup{
				keyMarker(family, maxKeyIndexAdvance+1),
			},
		}

		err := advanceKeyFamilyIndexes(
			context.Background(), wallet, ring,
		)
		require.ErrorContains(t, err, "requires advancing")
		require.Equal(t, uint32(1), ring.calls[family])
	})
}
