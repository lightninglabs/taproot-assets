package backup

import (
	"bytes"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

// randPubKey generates a random public key for testing.
func randPubKey(t *testing.T) *btcec.PublicKey {
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	return privKey.PubKey()
}

// randOutpoint generates a random outpoint for testing.
func randOutpoint(t *testing.T) wire.OutPoint {
	const hashStr = "00000000000000000000000000000000" +
		"00000000000000000000000000000001"

	hash, err := chainhash.NewHashFromStr(hashStr)
	require.NoError(t, err)
	return wire.OutPoint{Hash: *hash, Index: 0}
}

// newTestGenesis creates a test genesis for an asset.
func newTestGenesis(t *testing.T) asset.Genesis {
	return asset.Genesis{
		FirstPrevOut: randOutpoint(t),
		Tag:          "test-asset",
		OutputIndex:  0,
		Type:         asset.Normal,
	}
}

// newTestAsset creates a test asset for backup testing.
func newTestAsset(t *testing.T) *asset.Asset {
	genesis := newTestGenesis(t)
	scriptKey := asset.NewScriptKey(randPubKey(t))

	a, err := asset.New(
		genesis,
		1000, // amount
		0,    // locktime
		0,    // relative locktime
		scriptKey,
		nil, // group key
	)
	require.NoError(t, err)
	return a
}

// newTestScriptKeyBackup creates a test script key backup.
func newTestScriptKeyBackup(t *testing.T) *ScriptKeyBackup {
	return &ScriptKeyBackup{
		PubKey: randPubKey(t),
		RawKey: keychain.KeyDescriptor{
			PubKey: randPubKey(t),
			KeyLocator: keychain.KeyLocator{
				Family: 123,
				Index:  456,
			},
		},
		Tweak: []byte("test-tweak-data"),
	}
}

// newTestKeyDescriptorBackup creates a test key descriptor backup.
func newTestKeyDescriptorBackup(t *testing.T) *KeyDescriptorBackup {
	return &KeyDescriptorBackup{
		PubKey: randPubKey(t),
		KeyLocator: keychain.KeyLocator{
			Family: 789,
			Index:  101112,
		},
	}
}

// newTestAssetBackup creates a complete test v1 asset backup with a full
// proof blob.
func newTestAssetBackup(t *testing.T) *AssetBackup {
	// Create a mock proof blob (in real usage this would be a
	// full proof file).
	mockProofBlob := []byte("mock-proof-file-blob-data-for-testing")

	return &AssetBackup{
		Asset:                 newTestAsset(t),
		AnchorOutpoint:        randOutpoint(t),
		AnchorBlockHeight:     100000,
		ScriptKeyInfo:         newTestScriptKeyBackup(t),
		AnchorInternalKeyInfo: newTestKeyDescriptorBackup(t),
		ProofFileBlob:         mockProofBlob,
	}
}

// newTestAssetBackupV2 creates a complete test v2 asset backup with stripped
// proof and rehydration hints.
func newTestAssetBackupV2(t *testing.T) *AssetBackup {
	mockStrippedBlob := []byte("mock-stripped-proof-data")
	mockHintsBlob := []byte("mock-rehydration-hints-data")

	return &AssetBackup{
		Asset:                 newTestAsset(t),
		AnchorOutpoint:        randOutpoint(t),
		AnchorBlockHeight:     100000,
		ScriptKeyInfo:         newTestScriptKeyBackup(t),
		AnchorInternalKeyInfo: newTestKeyDescriptorBackup(t),
		StrippedProofFileBlob: mockStrippedBlob,
		RehydrationHintsBlob:  mockHintsBlob,
	}
}

// TestScriptKeyBackupRoundtrip tests encode/decode roundtrip for
// ScriptKeyBackup.
func TestScriptKeyBackupRoundtrip(t *testing.T) {
	t.Parallel()

	original := newTestScriptKeyBackup(t)

	// Encode.
	var buf bytes.Buffer
	err := original.Encode(&buf)
	require.NoError(t, err)

	// Decode.
	decoded := &ScriptKeyBackup{}
	err = decoded.Decode(&buf)
	require.NoError(t, err)

	// Verify.
	require.True(t, original.PubKey.IsEqual(decoded.PubKey))
	require.True(t, original.RawKey.PubKey.IsEqual(decoded.RawKey.PubKey))
	require.Equal(t, original.RawKey.Family, decoded.RawKey.Family)
	require.Equal(t, original.RawKey.Index, decoded.RawKey.Index)
	require.Equal(t, original.Tweak, decoded.Tweak)
}

// TestKeyDescriptorBackupRoundtrip tests encode/decode roundtrip for
// KeyDescriptorBackup.
func TestKeyDescriptorBackupRoundtrip(t *testing.T) {
	t.Parallel()

	original := newTestKeyDescriptorBackup(t)

	// Encode.
	var buf bytes.Buffer
	err := original.Encode(&buf)
	require.NoError(t, err)

	// Decode.
	decoded := &KeyDescriptorBackup{}
	err = decoded.Decode(&buf)
	require.NoError(t, err)

	// Verify.
	require.True(t, original.PubKey.IsEqual(decoded.PubKey))
	require.Equal(t, original.KeyLocator.Family, decoded.KeyLocator.Family)
	require.Equal(t, original.KeyLocator.Index, decoded.KeyLocator.Index)
}

// TestAssetBackupRoundtrip tests encode/decode roundtrip for AssetBackup.
func TestAssetBackupRoundtrip(t *testing.T) {
	t.Parallel()

	original := newTestAssetBackup(t)

	// Encode.
	var buf bytes.Buffer
	err := original.Encode(&buf)
	require.NoError(t, err)

	t.Logf("Encoded backup size: %d bytes", buf.Len())

	// Decode.
	decoded := &AssetBackup{}
	err = decoded.Decode(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)

	// Verify asset fields.
	require.Equal(t, original.Asset.Amount, decoded.Asset.Amount)
	require.Equal(t, original.Asset.Type, decoded.Asset.Type)
	require.Equal(t, original.Asset.Version, decoded.Asset.Version)
	require.True(t, original.Asset.ScriptKey.PubKey.IsEqual(
		decoded.Asset.ScriptKey.PubKey))

	// Verify anchor fields.
	require.Equal(t, original.AnchorOutpoint, decoded.AnchorOutpoint)
	require.Equal(t, original.AnchorBlockHeight, decoded.AnchorBlockHeight)

	// Verify script key info.
	require.NotNil(t, decoded.ScriptKeyInfo)
	require.True(t, original.ScriptKeyInfo.PubKey.IsEqual(
		decoded.ScriptKeyInfo.PubKey))
	require.Equal(t, original.ScriptKeyInfo.RawKey.Family,
		decoded.ScriptKeyInfo.RawKey.Family)
	require.Equal(t, original.ScriptKeyInfo.RawKey.Index,
		decoded.ScriptKeyInfo.RawKey.Index)
	require.Equal(t, original.ScriptKeyInfo.Tweak,
		decoded.ScriptKeyInfo.Tweak)

	// Verify anchor internal key info.
	require.NotNil(t, decoded.AnchorInternalKeyInfo)
	require.True(t, original.AnchorInternalKeyInfo.PubKey.IsEqual(
		decoded.AnchorInternalKeyInfo.PubKey))
	require.Equal(t, original.AnchorInternalKeyInfo.KeyLocator.Family,
		decoded.AnchorInternalKeyInfo.KeyLocator.Family)
	require.Equal(t, original.AnchorInternalKeyInfo.KeyLocator.Index,
		decoded.AnchorInternalKeyInfo.KeyLocator.Index)

	// Verify proof file blob.
	require.Equal(t, original.ProofFileBlob, decoded.ProofFileBlob)
}

// TestWalletBackupRoundtripV1 tests encode/decode roundtrip for a v1
// WalletBackup with full proof blobs.
func TestWalletBackupRoundtripV1(t *testing.T) {
	t.Parallel()

	original := &WalletBackup{
		Version: BackupVersionOriginal,
		Assets: []*AssetBackup{
			newTestAssetBackup(t),
			newTestAssetBackup(t),
			newTestAssetBackup(t),
		},
	}

	// Encode using helper.
	encoded, err := EncodeWalletBackup(original)
	require.NoError(t, err)

	t.Logf("Encoded v1 wallet backup size: %d bytes for %d assets",
		len(encoded), len(original.Assets))

	// Decode using helper.
	decoded, err := DecodeWalletBackup(encoded)
	require.NoError(t, err)

	// Verify.
	require.Equal(t, original.Version, decoded.Version)
	require.Len(t, decoded.Assets, len(original.Assets))

	for i := range original.Assets {
		require.Equal(t, original.Assets[i].Asset.Amount,
			decoded.Assets[i].Asset.Amount)
		require.Equal(t, original.Assets[i].AnchorBlockHeight,
			decoded.Assets[i].AnchorBlockHeight)
		require.Equal(t, original.Assets[i].ProofFileBlob,
			decoded.Assets[i].ProofFileBlob)
	}
}

// TestWalletBackupRoundtripV2 tests encode/decode roundtrip for a v2
// WalletBackup with stripped proofs and rehydration hints.
func TestWalletBackupRoundtripV2(t *testing.T) {
	t.Parallel()

	original := &WalletBackup{
		Version: BackupVersionStripped,
		Assets: []*AssetBackup{
			newTestAssetBackupV2(t),
			newTestAssetBackupV2(t),
		},
	}

	// Encode using helper.
	encoded, err := EncodeWalletBackup(original)
	require.NoError(t, err)

	t.Logf("Encoded v2 wallet backup size: %d bytes for %d assets",
		len(encoded), len(original.Assets))

	// Decode using helper.
	decoded, err := DecodeWalletBackup(encoded)
	require.NoError(t, err)

	// Verify.
	require.Equal(t, original.Version, decoded.Version)
	require.Len(t, decoded.Assets, len(original.Assets))

	for i := range original.Assets {
		require.Equal(t, original.Assets[i].Asset.Amount,
			decoded.Assets[i].Asset.Amount)
		require.Equal(t, original.Assets[i].AnchorBlockHeight,
			decoded.Assets[i].AnchorBlockHeight)
		require.Equal(t, original.Assets[i].StrippedProofFileBlob,
			decoded.Assets[i].StrippedProofFileBlob)
		require.Equal(t, original.Assets[i].RehydrationHintsBlob,
			decoded.Assets[i].RehydrationHintsBlob)
		// V2 should not have the full proof blob.
		require.Empty(t, decoded.Assets[i].ProofFileBlob)
	}
}

// newTestAssetBackupV3 creates a test v3 asset backup with no proof data.
func newTestAssetBackupV3(t *testing.T) *AssetBackup {
	return &AssetBackup{
		Asset:                 newTestAsset(t),
		AnchorOutpoint:        randOutpoint(t),
		AnchorBlockHeight:     100000,
		ScriptKeyInfo:         newTestScriptKeyBackup(t),
		AnchorInternalKeyInfo: newTestKeyDescriptorBackup(t),
		AnchorOutputPkScript:  []byte("mock-pkscript"),
	}
}

// TestWalletBackupRoundtripV3 tests encode/decode roundtrip for a v3
// WalletBackup with no proofs and federation URLs.
func TestWalletBackupRoundtripV3(t *testing.T) {
	t.Parallel()

	original := &WalletBackup{
		Version: BackupVersionOptimistic,
		FederationURLs: []string{
			"universe.example.com:10029",
			"backup.example.org:443",
		},
		Assets: []*AssetBackup{
			newTestAssetBackupV3(t),
			newTestAssetBackupV3(t),
		},
	}

	// Encode using helper.
	encoded, err := EncodeWalletBackup(original)
	require.NoError(t, err)

	t.Logf("Encoded v3 wallet backup size: %d bytes for %d assets",
		len(encoded), len(original.Assets))

	// Decode using helper.
	decoded, err := DecodeWalletBackup(encoded)
	require.NoError(t, err)

	// Verify version and federation URLs.
	require.Equal(t, original.Version, decoded.Version)
	require.Equal(t, original.FederationURLs, decoded.FederationURLs)
	require.Len(t, decoded.Assets, len(original.Assets))

	for i := range original.Assets {
		require.Equal(t, original.Assets[i].Asset.Amount,
			decoded.Assets[i].Asset.Amount)
		require.Equal(t, original.Assets[i].AnchorBlockHeight,
			decoded.Assets[i].AnchorBlockHeight)
		require.Equal(t, original.Assets[i].AnchorOutputPkScript,
			decoded.Assets[i].AnchorOutputPkScript)

		// V3 should have no proof data.
		require.Empty(t, decoded.Assets[i].ProofFileBlob)
		require.Empty(t, decoded.Assets[i].StrippedProofFileBlob)
		require.Empty(t, decoded.Assets[i].RehydrationHintsBlob)
	}
}

// TestFederationURLEncoding tests edge cases for federation URL encoding.
func TestFederationURLEncoding(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		urls []string
	}{
		{
			name: "empty list",
			urls: []string{},
		},
		{
			name: "single URL",
			urls: []string{"universe.example.com:10029"},
		},
		{
			name: "multiple URLs",
			urls: []string{
				"server1.example.com:10029",
				"server2.example.org:443",
				"192.168.1.1:10029",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Encode/decode via a full wallet backup.
			original := &WalletBackup{
				Version:        BackupVersionOptimistic,
				FederationURLs: tc.urls,
				Assets:         []*AssetBackup{},
			}

			encoded, err := EncodeWalletBackup(original)
			require.NoError(t, err)

			decoded, err := DecodeWalletBackup(encoded)
			require.NoError(t, err)

			require.Equal(t, tc.urls, decoded.FederationURLs)
		})
	}
}

// TestWalletBackupEmpty tests encoding/decoding an empty wallet backup.
func TestWalletBackupEmpty(t *testing.T) {
	t.Parallel()

	original := &WalletBackup{
		Version: BackupVersion,
		Assets:  []*AssetBackup{},
	}

	// Encode.
	encoded, err := EncodeWalletBackup(original)
	require.NoError(t, err)

	// Should have magic bytes + version + count.
	require.Greater(t, len(encoded), 10)

	// Decode.
	decoded, err := DecodeWalletBackup(encoded)
	require.NoError(t, err)

	require.Equal(t, original.Version, decoded.Version)
	require.Len(t, decoded.Assets, 0)
}

// TestWalletBackupInvalidMagic tests that invalid magic bytes are
// rejected.
func TestWalletBackupInvalidMagic(t *testing.T) {
	t.Parallel()

	// Create data with wrong magic but valid length (needs 32
	// byte checksum).
	invalidData := make([]byte, 50)
	copy(invalidData, "BADMAG")

	_, err := DecodeWalletBackup(invalidData)
	require.Error(t, err)
	// Will fail checksum first since we have garbage data.
	require.Contains(t, err.Error(), "checksum mismatch")
}

// TestWalletBackupChecksumTampered tests that tampered data is detected.
func TestWalletBackupChecksumTampered(t *testing.T) {
	t.Parallel()

	original := &WalletBackup{
		Version: BackupVersion,
		Assets:  []*AssetBackup{newTestAssetBackup(t)},
	}

	// Encode valid backup.
	encoded, err := EncodeWalletBackup(original)
	require.NoError(t, err)

	// Tamper with a byte in the middle of the payload (not the checksum).
	tampered := make([]byte, len(encoded))
	copy(tampered, encoded)
	tampered[len(tampered)/2] ^= 0xFF // Flip all bits of one byte

	// Decode should fail with checksum error.
	_, err = DecodeWalletBackup(tampered)
	require.Error(t, err)
	require.Contains(t, err.Error(), "checksum mismatch")
}

// TestWalletBackupTooShort tests that data shorter than checksum is rejected.
func TestWalletBackupTooShort(t *testing.T) {
	t.Parallel()

	shortData := []byte("short")
	_, err := DecodeWalletBackup(shortData)
	require.Error(t, err)
	require.Contains(t, err.Error(), "too short")
}
