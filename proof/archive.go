package proof

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/lightninglabs/taro/asset"
)

const (
	// TaroFileSuffix is the main file suffix for the Taro proof files stored
	// on disk.
	TaroFileSuffix = ".taro"

	// ProofDirName is the name of the directory we'll use to store our
	// proofs.
	ProofDirName = "proofs"
)

var (
	// ErrProofNotFound is returned when a user attempts to look up a proof
	// based on a Locator, but we can't find it on disk.
	ErrProofNotFound = fmt.Errorf("unable to find proof")
)

// Loactor is able to uniquely identify a proof in the extended Taro Universe
// by a combination of the: top-level asset ID, the family key, and also the
// script key.
type Locator struct {
	// AssetID the asset ID of the proof to fetch. This is an optional field.
	AssetID *asset.ID

	// FamilyKey the family key of the asset to fetch. This is an optional
	// field.
	FamilyKey *btcec.PublicKey

	// ScriptKey specifies the script key of the asset to fetch/store. This
	// field MUST be specified.
	ScriptKey btcec.PublicKey
}

// AnnotatedProof an annotated proof contains the raw proof blob along with a
// locator that may convey additional information related to the proof.
type AnnotatedProof struct {
	Locator

	Blob
}

// Archiver is the main storage backend the ProofArchiver uses to store and
// query for proof files.
//
// TODO(roasbeef): other queries like fetching all proofs for a given asset?
type Archiver interface {
	// FetchProof fetches a proof for an asset uniquely identified by the
	// passed ProofIdentifier.
	//
	// If a proof cannot be found, then ErrProofNotFound should be
	// returned.
	FetchProof(ctx context.Context, id Locator) (Blob, error)

	// StoreProofs attempts to store fully populated proofs on disk. The
	// previous outpoint of the first state transition will be used as the
	// Genesis point. The final resting place of the asset will be used as
	// the script key itself.
	StoreProofs(ctx context.Context, proofs ...AnnotatedProof) error
}

// FileArchive implements proof Archiver backed by an on-disk file system. The
// archiver takes a single root directory then creates the following overlap
// mapping:
//
// proofs/
// ├─ asset_id1/
// │  ├─ script_key1
// │  ├─ script_key2
type FileArchiver struct {
	// proofPath is the directory name that we'll use as the roof for all our files.
	proofPath string
}

// NewFileArchiver creates a new file arc
//
// TODO(roasbeef): use fs.FS instead?
func NewFileArchiver(dirName string) (*FileArchiver, error) {

	// First, we'll make sure our main proof directory has already been
	// created.
	proofPath := filepath.Join(dirName, ProofDirName)
	if err := os.Mkdir(proofPath, 0750); err != nil && !os.IsExist(err) {
		return nil, fmt.Errorf("unable to create proof dir: %w", err)
	}

	return &FileArchiver{
		proofPath: proofPath,
	}, nil
}

// genProofFilePath generates the full proof file path based on a rootPath and
// a valid locator. The final path is: root/assetID/scriptKey.taro
func genProofFilePath(rootPath string, loc Locator) (string, error) {
	if loc.AssetID == nil {
		return "", fmt.Errorf("asset ID of locator must be populated")
	}

	assetID := hex.EncodeToString(loc.AssetID[:])
	scriptKey := hex.EncodeToString(schnorr.SerializePubKey(&loc.ScriptKey))

	return filepath.Join(rootPath, assetID, scriptKey+TaroFileSuffix), nil
}

// FetchProof fetches a proof for an asset uniquely identified by the
// passed ProofIdentifier.
//
// If a proof cannot be found, then ErrProofNotFound should be
// returned.
//
// NOTE: This implements the Archiver interface.
func (f *FileArchiver) FetchProof(ctx context.Context, id Locator) (Blob, error) {
	// All our on-disk storage is based on asset IDs, so to look up a path,
	// we just need to compute the full file path and see if it exists on
	// disk.
	proofPath, err := genProofFilePath(f.proofPath, id)
	if err != nil {
		return nil, err
	}

	proofFile, err := os.ReadFile(proofPath)
	switch {
	case os.IsNotExist(err):
		return nil, ErrProofNotFound
	case err != nil:
		return nil, fmt.Errorf("unable to find proof: %w", err)
	}

	return proofFile, nil
}

// StoreProofs attempts to store fully populated proofs on disk. The previous
// outpoint of the first state transition will be used as the Genesis point.
// The final resting place of the asset will be used as the script key itself.
//
// NOTE: This implements the Archiver interface.
func (f *FileArchiver) StoreProofs(ctx context.Context, proofs ...AnnotatedProof) error {
	for _, proof := range proofs {
		proofPath, err := genProofFilePath(f.proofPath, proof.Locator)
		if err != nil {
			return err
		}

		err = os.WriteFile(proofPath, proof.Blob, 0666)
		if err != nil {
			return fmt.Errorf("unable to store proof: %v", err)
		}
	}

	return nil
}

// A compile-time interface to ensure FileArchiver meets the Archiver
// interface.
var _ Archiver = (*FileArchiver)(nil)
