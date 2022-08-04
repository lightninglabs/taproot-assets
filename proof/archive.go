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
