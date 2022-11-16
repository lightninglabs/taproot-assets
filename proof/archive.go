package proof

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/chanutils"
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

	// ErrInvalidLocatorID is returned when a specified has an invalid
	// asset ID.
	ErrInvalidLocatorID = fmt.Errorf("invalid asset ID locator")

	// ErrInvalidLocatorKey is returned when a specified locator script key
	// is invalid.
	ErrInvalidLocatorKey = fmt.Errorf("invalid script key locator")
)

// Locator is able to uniquely identify a proof in the extended Taro Universe
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

	*AssetSnapshot
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

	// ImportProofs attempts to store fully populated proofs on disk. The
	// previous outpoint of the first state transition will be used as the
	// Genesis point. The final resting place of the asset will be used as
	// the script key itself.
	ImportProofs(ctx context.Context, proofs ...*AnnotatedProof) error
}

// FileArchiver implements proof Archiver backed by an on-disk file system. The
// archiver takes a single root directory then creates the following overlap
// mapping:
//
// proofs/
// ├─ asset_id1/
// │  ├─ script_key1
// │  ├─ script_key2
type FileArchiver struct {
	// proofPath is the directory name that we'll use as the roof for all
	// our files.
	proofPath string
}

// NewFileArchiver creates a new file archive rooted at the passed specified
// directory.
//
// TODO(roasbeef): use fs.FS instead?
//
// TODO(roasbeef): option to memory map these instead? then don't need to lug
// around large blobs in user space as much
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
	var emptyKey btcec.PublicKey

	switch {
	case loc.AssetID == nil:
		return "", ErrInvalidLocatorID

	case loc.ScriptKey.IsEqual(&emptyKey):
		return "", ErrInvalidLocatorKey
	}

	assetID := hex.EncodeToString(loc.AssetID[:])
	scriptKey := hex.EncodeToString(loc.ScriptKey.SerializeCompressed())

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
		return nil, fmt.Errorf("unable to make proof file path: %w",
			err)
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

// ImportProofs attempts to store fully populated proofs on disk. The previous
// outpoint of the first state transition will be used as the Genesis point.
// The final resting place of the asset will be used as the script key itself.
//
// NOTE: This implements the Archiver interface.
func (f *FileArchiver) ImportProofs(ctx context.Context,
	proofs ...*AnnotatedProof) error {

	for _, proof := range proofs {
		proofPath, err := genProofFilePath(f.proofPath, proof.Locator)
		if err != nil {
			return err
		}

		if err := os.MkdirAll(path.Dir(proofPath), 0750); err != nil {
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

// MultiArchiver is an archive of archives. It contains several archives and
// attempts to use them either as a look-aside cache, or a write through cache
// for all incoming requests.
type MultiArchiver struct {
	proofVerifier Verifier
	backends      []Archiver

	// archiveTimeout is the default timeout to use for any archive
	// interaction.
	archiveTimeout time.Duration

	// subscribers is a map of components that want to be notified on new
	// proofs, keyed by their subscription ID.
	subscribers map[uint64]*chanutils.EventReceiver[Blob]

	// subscriberMtx guards the subscribers map and access to the
	// subscriptionID.
	subscriberMtx sync.Mutex
}

// NewMultiArchiver creates a new MultiArchiver based on the set of specified
// backends.
func NewMultiArchiver(verifier Verifier, archiveTimeout time.Duration,
	backends ...Archiver) *MultiArchiver {

	return &MultiArchiver{
		proofVerifier:  verifier,
		backends:       backends,
		archiveTimeout: archiveTimeout,
		subscribers: make(
			map[uint64]*chanutils.EventReceiver[Blob],
		),
	}
}

// FetchProof fetches a proof for an asset uniquely identified by the passed
// ProofIdentifier.
func (m *MultiArchiver) FetchProof(ctx context.Context,
	loc Locator) (Blob, error) {

	// Iterate through all our active backends and try to see if at least
	// one of them contains the proof. Either one of them will have the
	// proof, or we'll return an error back to the user.
	//
	// TODO(roasbeef): fire all requests off and take the one that responds
	// first?
	for _, archive := range m.backends {
		proof, err := archive.FetchProof(ctx, loc)
		switch {
		case errors.Is(err, ErrProofNotFound):
			continue
		case err != nil:
			return nil, err
		}

		return proof, nil
	}

	return nil, ErrProofNotFound
}

// ImportProofs attempts to store fully populated proofs on disk. The previous
// outpoint of the first state transition will be used as the Genesis point.
// The final resting place of the asset will be used as the script key itself.
func (m *MultiArchiver) ImportProofs(ctx context.Context,
	proofs ...*AnnotatedProof) error {

	// Before we import the proofs into the archive, we want to make sure
	// that they're all valid. Along the way, we may augment the locator
	// for each proof accordingly.
	f := func(c context.Context, proof *AnnotatedProof) error {
		// First, we'll decode and then also verify the proof.
		finalStateTransition, err := m.proofVerifier.Verify(
			c, bytes.NewReader(proof.Blob),
		)
		if err != nil {
			return fmt.Errorf("unable to verify proof: %w", err)
		}

		proof.AssetSnapshot = finalStateTransition

		// TODO(roasbeef): actually want the split commit info here?
		//  * or need to pass in alongside the proof?

		finalAsset := finalStateTransition.Asset

		// Now that the proof has been fully verified, we'll use the
		// final resting place of the asset (result of the last state
		// transition) to create a proper annotated proof. We only need
		// to do this if it wasn't specified though.
		if proof.AssetID == nil {
			assetID := finalAsset.ID()
			proof.AssetID = &assetID

			if finalAsset.FamilyKey != nil {
				proof.FamilyKey = &finalAsset.FamilyKey.FamKey
			}

			proof.ScriptKey = *finalAsset.ScriptKey.PubKey
		}

		return nil
	}

	if err := chanutils.ErrGroup(ctx, proofs, f); err != nil {
		return err
	}

	// Now that we know all the proofs are valid, and have tacked on some
	// additional supplementary information into the locator, we'll attempt
	// to import each proof our archive backends.
	for _, archive := range m.backends {
		err := archive.ImportProofs(ctx, proofs...)
		if err != nil {
			return err
		}
	}

	// Deliver each new proof to the new item queue of the subscribers.
	m.subscriberMtx.Lock()
	for i := range proofs {
		for id := range m.subscribers {
			receiver := m.subscribers[id]
			receiver.NewItemCreated.ChanIn() <- proofs[i].Blob
		}
	}
	m.subscriberMtx.Unlock()

	return nil
}

// RegisterSubscriber adds a new subscriber for receiving events. The
// deliverExisting boolean indicates whether already existing items should be
// sent to the NewItemCreated channel when the subscription is started. An
// optional deliverFrom can be specified to indicate from which timestamp/index/
// marker onward existing items should be delivered on startup. If deliverFrom
// is nil/zero/empty then all existing items will be delivered.
func (m *MultiArchiver) RegisterSubscriber(
	receiver *chanutils.EventReceiver[Blob],
	deliverExisting bool, deliverFrom []*Locator) error {

	m.subscriberMtx.Lock()
	defer m.subscriberMtx.Unlock()

	m.subscribers[receiver.ID()] = receiver

	// No delivery of existing items requested, we're done here.
	if !deliverExisting {
		return nil
	}

	ctxt, cancel := context.WithTimeout(
		context.Background(), m.archiveTimeout,
	)
	defer cancel()

	for _, loc := range deliverFrom {
		blob, err := m.FetchProof(ctxt, *loc)
		if err != nil {
			return err
		}

		// Deliver the found proof to the new item queue of the
		// subscriber.
		receiver.NewItemCreated.ChanIn() <- blob
	}

	return nil
}

// RemoveSubscriber removes the given subscriber and also stops it from
// processing events.
func (m *MultiArchiver) RemoveSubscriber(
	subscriber *chanutils.EventReceiver[Blob]) error {

	m.subscriberMtx.Lock()
	defer m.subscriberMtx.Unlock()

	_, ok := m.subscribers[subscriber.ID()]
	if !ok {
		return fmt.Errorf("subscriber with ID %d not found",
			subscriber.ID())
	}

	subscriber.Stop()
	delete(m.subscribers, subscriber.ID())

	return nil
}

// A compile-time assertion to make sure MultiArchiver satisfies the
// chanutils.EventPublisher interface.
var _ chanutils.EventPublisher[Blob, []*Locator] = (*MultiArchiver)(nil)
