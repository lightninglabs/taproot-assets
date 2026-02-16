package backup

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/tlv"
)

const (
	// BackupVersionOriginal is the first version of the backup format
	// which stores the complete proof file blob.
	BackupVersionOriginal uint32 = 1

	// BackupVersionStripped is the second version of the backup format
	// which stores stripped proof files with rehydration hints, reducing
	// backup size by omitting blockchain-derivable fields.
	BackupVersionStripped uint32 = 2

	// BackupVersionOptimistic is the third version of the backup format
	// which stores no proof data at all. Proofs are fetched from a
	// universe server on import. This is the smallest backup format but
	// requires a reachable universe server during restore.
	BackupVersionOptimistic uint32 = 3

	// BackupVersion is the current (latest) version of the backup format.
	BackupVersion = BackupVersionOptimistic

	// backupMagicBytes are the magic bytes that identify a backup file.
	backupMagicBytes = "TAPBAK"

	// checksumSize is the size of the SHA256 checksum appended to backups.
	checksumSize = sha256.Size

	// maxBackupAssets is the maximum number of assets a single backup can
	// contain. This prevents OOM from malformed input.
	maxBackupAssets = 1_000_000

	// maxTLVSize is the maximum size in bytes of a single asset's TLV
	// payload. This prevents OOM from malformed input.
	maxTLVSize = 100 * 1024 * 1024 // 100 MB

	// maxFederationURLs is the maximum number of federation URLs that
	// can be stored in a v3 backup. This prevents OOM from malformed
	// input.
	maxFederationURLs = 100

	// maxFederationURLLen is the maximum length of a single federation
	// URL in bytes.
	maxFederationURLLen = 2048
)

// TLV type constants for AssetBackup fields.
const (
	// AssetBackupAssetType is the TLV type for the asset field.
	AssetBackupAssetType tlv.Type = 0

	// AssetBackupOutpointType is the TLV type for the anchor outpoint.
	AssetBackupOutpointType tlv.Type = 1

	// AssetBackupBlockHeightType is the TLV type for the anchor block
	// height.
	AssetBackupBlockHeightType tlv.Type = 2

	// AssetBackupScriptKeyType is the TLV type for the script key info.
	AssetBackupScriptKeyType tlv.Type = 3

	// AssetBackupAnchorKeyType is the TLV type for the anchor internal key
	// info.
	AssetBackupAnchorKeyType tlv.Type = 4

	// AssetBackupProofBlobType is the TLV type for the complete proof file
	// blob. Used in v1 backups.
	AssetBackupProofBlobType tlv.Type = 5

	// AssetBackupAnchorPkScriptType is the TLV type for the anchor
	// output's pk_script, used for spend detection on import.
	AssetBackupAnchorPkScriptType tlv.Type = 6

	// AssetBackupStrippedProofBlobType is the TLV type for the stripped
	// proof file blob (blockchain-derivable fields removed). Used in v2+
	// backups. Odd type so older decoders can safely skip it.
	AssetBackupStrippedProofBlobType tlv.Type = 7

	// AssetBackupRehydrationHintsType is the TLV type for the serialized
	// rehydration hints needed to reconstruct stripped fields. Used in v2+
	// backups. Odd type so older decoders can safely skip it.
	AssetBackupRehydrationHintsType tlv.Type = 9
)

// TLV type constants for ScriptKeyBackup fields.
// Note: Types must be in ascending order when encoded.
const (
	ScriptKeyPubKeyType    tlv.Type = 0
	ScriptKeyFamilyType    tlv.Type = 1
	ScriptKeyIndexType     tlv.Type = 2
	ScriptKeyRawPubKeyType tlv.Type = 3
	ScriptKeyTweakType     tlv.Type = 4
)

// TLV type constants for KeyDescriptorBackup fields.
const (
	KeyDescPubKeyType tlv.Type = 0
	KeyDescFamilyType tlv.Type = 1
	KeyDescIndexType  tlv.Type = 2
)

// encodeFederationURLs writes federation URLs to a writer using the format:
// num_urls(varint) | [url_len(varint) | url_bytes(UTF-8)]...
func encodeFederationURLs(w io.Writer, urls []string) error {
	var tlvBuf [8]byte

	numURLs := uint64(len(urls))
	if numURLs > maxFederationURLs {
		return fmt.Errorf("URL count %d exceeds maximum %d",
			numURLs, maxFederationURLs)
	}

	if err := tlv.WriteVarInt(w, numURLs, &tlvBuf); err != nil {
		return fmt.Errorf("failed to write URL count: %w", err)
	}

	for i, u := range urls {
		urlBytes := []byte(u)
		urlLen := uint64(len(urlBytes))

		if urlLen > maxFederationURLLen {
			return fmt.Errorf("URL %d length %d exceeds "+
				"maximum %d", i, urlLen,
				maxFederationURLLen)
		}

		err := tlv.WriteVarInt(w, urlLen, &tlvBuf)
		if err != nil {
			return fmt.Errorf("failed to write URL %d "+
				"length: %w", i, err)
		}

		if _, err := w.Write(urlBytes); err != nil {
			return fmt.Errorf("failed to write URL %d: %w",
				i, err)
		}
	}

	return nil
}

// decodeFederationURLs reads federation URLs from a reader.
func decodeFederationURLs(r io.Reader) ([]string, error) {
	var tlvBuf [8]byte

	numURLs, err := tlv.ReadVarInt(r, &tlvBuf)
	if err != nil {
		return nil, fmt.Errorf("failed to read URL count: %w", err)
	}

	if numURLs > maxFederationURLs {
		return nil, fmt.Errorf("URL count %d exceeds maximum %d",
			numURLs, maxFederationURLs)
	}

	urls := make([]string, numURLs)
	for i := uint64(0); i < numURLs; i++ {
		urlLen, err := tlv.ReadVarInt(r, &tlvBuf)
		if err != nil {
			return nil, fmt.Errorf("failed to read URL %d "+
				"length: %w", i, err)
		}

		if urlLen > maxFederationURLLen {
			return nil, fmt.Errorf("URL %d length %d exceeds "+
				"maximum %d", i, urlLen,
				maxFederationURLLen)
		}

		urlBytes := make([]byte, urlLen)
		if _, err := io.ReadFull(r, urlBytes); err != nil {
			return nil, fmt.Errorf("failed to read URL "+
				"%d: %w", i, err)
		}

		urls[i] = string(urlBytes)
	}

	return urls, nil
}

// Encode serializes a WalletBackup to a writer.
func (w *WalletBackup) Encode(writer io.Writer) error {
	// Write magic bytes.
	if _, err := writer.Write([]byte(backupMagicBytes)); err != nil {
		return fmt.Errorf("failed to write magic bytes: %w", err)
	}

	// Write version.
	err := binary.Write(writer, binary.BigEndian, w.Version)
	if err != nil {
		return fmt.Errorf("failed to write version: %w", err)
	}

	// For v3+ backups, write federation URLs after the version.
	if w.Version >= BackupVersionOptimistic {
		err = encodeFederationURLs(writer, w.FederationURLs)
		if err != nil {
			return fmt.Errorf("failed to write federation "+
				"URLs: %w", err)
		}
	}

	// Write number of assets.
	var tlvBuf [8]byte
	numAssets := uint64(len(w.Assets))
	err = tlv.WriteVarInt(writer, numAssets, &tlvBuf)
	if err != nil {
		return fmt.Errorf("failed to write asset count: %w",
			err)
	}

	// Write each asset backup.
	for i, ab := range w.Assets {
		if err := ab.Encode(writer); err != nil {
			return fmt.Errorf("failed to encode "+
				"asset %d: %w", i, err)
		}
	}

	return nil
}

// Decode deserializes a WalletBackup from a reader.
func (w *WalletBackup) Decode(reader io.Reader) error {
	// Read and verify magic bytes.
	magic := make([]byte, len(backupMagicBytes))
	if _, err := io.ReadFull(reader, magic); err != nil {
		return fmt.Errorf("failed to read magic bytes: %w", err)
	}
	if string(magic) != backupMagicBytes {
		return fmt.Errorf("invalid magic bytes: got %s, want %s",
			string(magic), backupMagicBytes)
	}

	// Read version.
	err := binary.Read(reader, binary.BigEndian, &w.Version)
	if err != nil {
		return fmt.Errorf("failed to read version: %w", err)
	}

	if w.Version == 0 || w.Version > BackupVersion {
		return fmt.Errorf("unsupported backup version %d "+
			"(max supported: %d)", w.Version,
			BackupVersion)
	}

	// For v3+ backups, read federation URLs after the version.
	if w.Version >= BackupVersionOptimistic {
		w.FederationURLs, err = decodeFederationURLs(reader)
		if err != nil {
			return fmt.Errorf("failed to read federation "+
				"URLs: %w", err)
		}
	}

	// Read number of assets.
	var tlvBuf [8]byte
	numAssets, err := tlv.ReadVarInt(reader, &tlvBuf)
	if err != nil {
		return fmt.Errorf("failed to read asset count: %w", err)
	}

	if numAssets > maxBackupAssets {
		return fmt.Errorf("asset count %d exceeds maximum %d",
			numAssets, maxBackupAssets)
	}

	// Read each asset backup.
	w.Assets = make([]*AssetBackup, numAssets)
	for i := uint64(0); i < numAssets; i++ {
		ab := &AssetBackup{}
		if err := ab.Decode(reader); err != nil {
			return fmt.Errorf("failed to decode "+
				"asset %d: %w", i, err)
		}
		w.Assets[i] = ab
	}

	return nil
}

// Encode serializes an AssetBackup to a writer using TLV format.
func (ab *AssetBackup) Encode(w io.Writer) error {
	// Encode the asset to a buffer first.
	var assetBuf bytes.Buffer
	if err := ab.Asset.Encode(&assetBuf); err != nil {
		return fmt.Errorf("failed to encode asset: %w", err)
	}

	// Encode the outpoint.
	var outpointBuf bytes.Buffer
	var encBuf [8]byte
	err := asset.OutPointEncoder(
		&outpointBuf, &ab.AnchorOutpoint, &encBuf,
	)
	if err != nil {
		return fmt.Errorf("failed to encode outpoint: %w",
			err)
	}

	// Build the TLV records. Records must be in ascending type order.
	assetBytes := assetBuf.Bytes()
	outpointBytes := outpointBuf.Bytes()

	// Start with required fields in type order (0, 1, 2).
	records := []tlv.Record{
		tlv.MakePrimitiveRecord(
			AssetBackupAssetType, &assetBytes,
		),
		tlv.MakePrimitiveRecord(
			AssetBackupOutpointType, &outpointBytes,
		),
		tlv.MakePrimitiveRecord(
			AssetBackupBlockHeightType,
			&ab.AnchorBlockHeight,
		),
	}

	// Add optional script key info (type 3).
	if ab.ScriptKeyInfo != nil {
		var scriptKeyBuf bytes.Buffer
		err := ab.ScriptKeyInfo.Encode(&scriptKeyBuf)
		if err != nil {
			return fmt.Errorf("failed to encode "+
				"script key: %w", err)
		}
		scriptKeyBytes := scriptKeyBuf.Bytes()
		records = append(records, tlv.MakePrimitiveRecord(
			AssetBackupScriptKeyType, &scriptKeyBytes))
	}

	// Add optional anchor internal key info (type 4).
	if ab.AnchorInternalKeyInfo != nil {
		var anchorKeyBuf bytes.Buffer
		err := ab.AnchorInternalKeyInfo.Encode(&anchorKeyBuf)
		if err != nil {
			return fmt.Errorf("failed to encode "+
				"anchor key: %w", err)
		}
		anchorKeyBytes := anchorKeyBuf.Bytes()
		records = append(records, tlv.MakePrimitiveRecord(
			AssetBackupAnchorKeyType, &anchorKeyBytes))
	}

	// Add proof data and optional pk_script. Records must remain in
	// ascending type order: 5 (full proof), 6 (pk_script), 7 (stripped
	// proof), 9 (hints).
	switch {
	case len(ab.StrippedProofFileBlob) > 0:
		// v2: types 6, 7, 9.
		if len(ab.AnchorOutputPkScript) > 0 {
			records = append(records, tlv.MakePrimitiveRecord(
				AssetBackupAnchorPkScriptType,
				&ab.AnchorOutputPkScript))
		}
		records = append(records, tlv.MakePrimitiveRecord(
			AssetBackupStrippedProofBlobType,
			&ab.StrippedProofFileBlob))
		records = append(records, tlv.MakePrimitiveRecord(
			AssetBackupRehydrationHintsType,
			&ab.RehydrationHintsBlob))

	case len(ab.ProofFileBlob) > 0:
		// v1: types 5, 6.
		records = append(records, tlv.MakePrimitiveRecord(
			AssetBackupProofBlobType, &ab.ProofFileBlob))
		if len(ab.AnchorOutputPkScript) > 0 {
			records = append(records, tlv.MakePrimitiveRecord(
				AssetBackupAnchorPkScriptType,
				&ab.AnchorOutputPkScript))
		}

	case len(ab.AnchorOutputPkScript) > 0:
		// No proof data but pk_script present.
		records = append(records, tlv.MakePrimitiveRecord(
			AssetBackupAnchorPkScriptType,
			&ab.AnchorOutputPkScript))
	}

	// Write the TLV stream with a length prefix.
	var tlvBuf bytes.Buffer
	stream, err := tlv.NewStream(records...)
	if err != nil {
		return fmt.Errorf("failed to create TLV stream: %w", err)
	}
	if err := stream.Encode(&tlvBuf); err != nil {
		return fmt.Errorf("failed to encode TLV stream: %w", err)
	}

	// Write length-prefixed TLV data.
	var lenBuf [8]byte
	tlvSize := uint64(tlvBuf.Len())
	if err := tlv.WriteVarInt(w, tlvSize, &lenBuf); err != nil {
		return fmt.Errorf("failed to write TLV length: %w", err)
	}
	if _, err := w.Write(tlvBuf.Bytes()); err != nil {
		return fmt.Errorf("failed to write TLV data: %w", err)
	}

	return nil
}

// Decode deserializes an AssetBackup from a reader.
func (ab *AssetBackup) Decode(r io.Reader) error {
	// Read length-prefixed TLV data.
	var lenBuf [8]byte
	tlvLen, err := tlv.ReadVarInt(r, &lenBuf)
	if err != nil {
		return fmt.Errorf("failed to read TLV length: %w", err)
	}

	if tlvLen > maxTLVSize {
		return fmt.Errorf("TLV payload size %d exceeds "+
			"maximum %d", tlvLen, maxTLVSize)
	}

	tlvData := make([]byte, tlvLen)
	if _, err := io.ReadFull(r, tlvData); err != nil {
		return fmt.Errorf("failed to read TLV data: %w", err)
	}

	// Prepare variables for decoding.
	var (
		assetBytes            []byte
		outpointBytes         []byte
		scriptKeyBytes        []byte
		anchorKeyBytes        []byte
		anchorPkScriptBytes   []byte
		proofBlobBytes        []byte
		strippedBlobBytes     []byte
		rehydrationHintsBytes []byte
	)

	// Create decode records. Include all known types (v1 and v2) so
	// we can decode either format.
	records := []tlv.Record{
		tlv.MakePrimitiveRecord(
			AssetBackupAssetType, &assetBytes,
		),
		tlv.MakePrimitiveRecord(
			AssetBackupOutpointType, &outpointBytes,
		),
		tlv.MakePrimitiveRecord(
			AssetBackupBlockHeightType,
			&ab.AnchorBlockHeight,
		),
		tlv.MakePrimitiveRecord(AssetBackupScriptKeyType,
			&scriptKeyBytes),
		tlv.MakePrimitiveRecord(AssetBackupAnchorKeyType,
			&anchorKeyBytes),
		tlv.MakePrimitiveRecord(AssetBackupProofBlobType,
			&proofBlobBytes),
		tlv.MakePrimitiveRecord(AssetBackupAnchorPkScriptType,
			&anchorPkScriptBytes),
		tlv.MakePrimitiveRecord(
			AssetBackupStrippedProofBlobType,
			&strippedBlobBytes),
		tlv.MakePrimitiveRecord(
			AssetBackupRehydrationHintsType,
			&rehydrationHintsBytes),
	}

	stream, err := tlv.NewStream(records...)
	if err != nil {
		return fmt.Errorf("failed to create TLV stream: %w", err)
	}

	parsedTypes, err := stream.DecodeWithParsedTypes(
		bytes.NewReader(tlvData),
	)
	if err != nil {
		return fmt.Errorf("failed to decode TLV stream: %w", err)
	}

	// Decode asset.
	if _, ok := parsedTypes[AssetBackupAssetType]; ok {
		ab.Asset = &asset.Asset{}
		err := ab.Asset.Decode(bytes.NewReader(assetBytes))
		if err != nil {
			return fmt.Errorf("failed to decode asset: "+
				"%w", err)
		}
	}

	// Decode outpoint.
	if _, ok := parsedTypes[AssetBackupOutpointType]; ok {
		var buf [8]byte
		err := asset.OutPointDecoder(
			bytes.NewReader(outpointBytes),
			&ab.AnchorOutpoint, &buf, 0,
		)
		if err != nil {
			return fmt.Errorf("failed to decode "+
				"outpoint: %w", err)
		}
	}

	// Decode optional script key info.
	if _, ok := parsedTypes[AssetBackupScriptKeyType]; ok {
		ab.ScriptKeyInfo = &ScriptKeyBackup{}
		err := ab.ScriptKeyInfo.Decode(
			bytes.NewReader(scriptKeyBytes),
		)
		if err != nil {
			return fmt.Errorf("failed to decode "+
				"script key: %w", err)
		}
	}

	// Decode optional anchor internal key info.
	if _, ok := parsedTypes[AssetBackupAnchorKeyType]; ok {
		ab.AnchorInternalKeyInfo = &KeyDescriptorBackup{}
		err := ab.AnchorInternalKeyInfo.Decode(
			bytes.NewReader(anchorKeyBytes),
		)
		if err != nil {
			return fmt.Errorf("failed to decode "+
				"anchor key: %w", err)
		}
	}

	// Store the anchor output pk_script.
	if _, ok := parsedTypes[AssetBackupAnchorPkScriptType]; ok {
		ab.AnchorOutputPkScript = anchorPkScriptBytes
	}

	// Store the proof file blob (v1).
	if _, ok := parsedTypes[AssetBackupProofBlobType]; ok {
		ab.ProofFileBlob = proofBlobBytes
	}

	// Store the stripped proof blob and hints (v2+).
	if _, ok := parsedTypes[AssetBackupStrippedProofBlobType]; ok {
		ab.StrippedProofFileBlob = strippedBlobBytes
	}
	if _, ok := parsedTypes[AssetBackupRehydrationHintsType]; ok {
		ab.RehydrationHintsBlob = rehydrationHintsBytes
	}

	// Validate required fields are present.
	if ab.Asset == nil {
		return fmt.Errorf("missing required asset field")
	}

	return nil
}

// Encode serializes a ScriptKeyBackup to a writer.
func (sk *ScriptKeyBackup) Encode(w io.Writer) error {
	pubKeyBytes := sk.PubKey.SerializeCompressed()
	family := uint32(sk.RawKey.Family)
	index := sk.RawKey.Index

	records := []tlv.Record{
		tlv.MakePrimitiveRecord(ScriptKeyPubKeyType, &pubKeyBytes),
		tlv.MakePrimitiveRecord(ScriptKeyFamilyType, &family),
		tlv.MakePrimitiveRecord(ScriptKeyIndexType, &index),
	}

	// Add raw key pubkey if present.
	if sk.RawKey.PubKey != nil {
		rawPubKeyBytes := sk.RawKey.PubKey.SerializeCompressed()
		records = append(records, tlv.MakePrimitiveRecord(
			ScriptKeyRawPubKeyType, &rawPubKeyBytes))
	}

	// Add tweak if present.
	if len(sk.Tweak) > 0 {
		records = append(records, tlv.MakePrimitiveRecord(
			ScriptKeyTweakType, &sk.Tweak))
	}

	stream, err := tlv.NewStream(records...)
	if err != nil {
		return err
	}

	return stream.Encode(w)
}

// Decode deserializes a ScriptKeyBackup from a reader.
func (sk *ScriptKeyBackup) Decode(r io.Reader) error {
	var (
		pubKeyBytes    []byte
		rawPubKeyBytes []byte
		family         uint32
		index          uint32
		tweak          []byte
	)

	// Records must be in ascending type order.
	records := []tlv.Record{
		tlv.MakePrimitiveRecord(ScriptKeyPubKeyType, &pubKeyBytes),
		tlv.MakePrimitiveRecord(ScriptKeyFamilyType, &family),
		tlv.MakePrimitiveRecord(ScriptKeyIndexType, &index),
		tlv.MakePrimitiveRecord(
			ScriptKeyRawPubKeyType, &rawPubKeyBytes,
		),
		tlv.MakePrimitiveRecord(ScriptKeyTweakType, &tweak),
	}

	stream, err := tlv.NewStream(records...)
	if err != nil {
		return err
	}

	parsedTypes, err := stream.DecodeWithParsedTypes(r)
	if err != nil {
		return err
	}

	// Decode public key.
	if _, ok := parsedTypes[ScriptKeyPubKeyType]; ok {
		sk.PubKey, err = btcec.ParsePubKey(pubKeyBytes)
		if err != nil {
			return fmt.Errorf("failed to parse pubkey: %w", err)
		}
	}

	// Decode key locator.
	if _, ok := parsedTypes[ScriptKeyFamilyType]; ok {
		sk.RawKey.Family = keychain.KeyFamily(family)
	}
	if _, ok := parsedTypes[ScriptKeyIndexType]; ok {
		sk.RawKey.Index = index
	}

	// Decode raw key pubkey if present.
	if _, ok := parsedTypes[ScriptKeyRawPubKeyType]; ok {
		sk.RawKey.PubKey, err = btcec.ParsePubKey(rawPubKeyBytes)
		if err != nil {
			return fmt.Errorf("failed to parse raw pubkey: %w", err)
		}
	}

	// Decode tweak if present.
	if _, ok := parsedTypes[ScriptKeyTweakType]; ok {
		sk.Tweak = tweak
	}

	return nil
}

// Encode serializes a KeyDescriptorBackup to a writer.
func (kd *KeyDescriptorBackup) Encode(w io.Writer) error {
	pubKeyBytes := kd.PubKey.SerializeCompressed()
	family := uint32(kd.KeyLocator.Family)
	index := kd.KeyLocator.Index

	records := []tlv.Record{
		tlv.MakePrimitiveRecord(KeyDescPubKeyType, &pubKeyBytes),
		tlv.MakePrimitiveRecord(KeyDescFamilyType, &family),
		tlv.MakePrimitiveRecord(KeyDescIndexType, &index),
	}

	stream, err := tlv.NewStream(records...)
	if err != nil {
		return err
	}

	return stream.Encode(w)
}

// Decode deserializes a KeyDescriptorBackup from a reader.
func (kd *KeyDescriptorBackup) Decode(r io.Reader) error {
	var (
		pubKeyBytes []byte
		family      uint32
		index       uint32
	)

	records := []tlv.Record{
		tlv.MakePrimitiveRecord(KeyDescPubKeyType, &pubKeyBytes),
		tlv.MakePrimitiveRecord(KeyDescFamilyType, &family),
		tlv.MakePrimitiveRecord(KeyDescIndexType, &index),
	}

	stream, err := tlv.NewStream(records...)
	if err != nil {
		return err
	}

	parsedTypes, err := stream.DecodeWithParsedTypes(r)
	if err != nil {
		return err
	}

	// Decode public key.
	if _, ok := parsedTypes[KeyDescPubKeyType]; ok {
		kd.PubKey, err = btcec.ParsePubKey(pubKeyBytes)
		if err != nil {
			return fmt.Errorf("failed to parse pubkey: %w", err)
		}
	}

	// Decode key locator.
	if _, ok := parsedTypes[KeyDescFamilyType]; ok {
		kd.KeyLocator.Family = keychain.KeyFamily(family)
	}
	if _, ok := parsedTypes[KeyDescIndexType]; ok {
		kd.KeyLocator.Index = index
	}

	return nil
}

// EncodeWalletBackup encodes a WalletBackup to a byte slice with a SHA256
// checksum appended at the end for integrity verification.
func EncodeWalletBackup(backup *WalletBackup) ([]byte, error) {
	var buf bytes.Buffer
	if err := backup.Encode(&buf); err != nil {
		return nil, err
	}

	// Compute SHA256 checksum of the encoded data.
	checksum := sha256.Sum256(buf.Bytes())

	// Append checksum to the end.
	buf.Write(checksum[:])

	return buf.Bytes(), nil
}

// DecodeWalletBackup decodes a WalletBackup from a byte slice after verifying
// the SHA256 checksum.
func DecodeWalletBackup(data []byte) (*WalletBackup, error) {
	// Verify we have enough data for at least the checksum.
	if len(data) < checksumSize {
		return nil, fmt.Errorf("backup data too short: "+
			"%d bytes", len(data))
	}

	// Split data and checksum.
	payloadLen := len(data) - checksumSize
	payload := data[:payloadLen]
	storedChecksum := data[payloadLen:]

	// Verify checksum.
	computedChecksum := sha256.Sum256(payload)
	if !bytes.Equal(storedChecksum, computedChecksum[:]) {
		return nil, fmt.Errorf("backup checksum mismatch: " +
			"data may be corrupted or tampered with")
	}

	// Decode the verified payload.
	backup := &WalletBackup{}
	if err := backup.Decode(bytes.NewReader(payload)); err != nil {
		return nil, err
	}
	return backup, nil
}
