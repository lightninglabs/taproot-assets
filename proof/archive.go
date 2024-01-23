package proof

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnwire"
)

const (
	// TaprootAssetsFileSuffix is the main file suffix for the Taproot Asset
	// proof files stored on disk.
	TaprootAssetsFileSuffix = ".assetproof"

	// ProofDirName is the name of the directory we'll use to store our
	// proofs.
	ProofDirName = "proofs"

	// outpointTruncateLength is the number of hex characters we use to
	// represent the outpoint hash in the file name. This is to avoid
	// problems with long file names on some operating systems.
	outpointTruncateLength = 32
)

var (
	// emptyKey is an empty public key that we use to check if a script key
	// is valid.
	emptyKey btcec.PublicKey

	// ErrProofNotFound is returned when a user attempts to look up a proof
	// based on a Locator, but we can't find it on disk.
	ErrProofNotFound = fmt.Errorf("unable to find proof")

	// ErrInvalidLocatorID is returned when a specified has an invalid
	// asset ID.
	ErrInvalidLocatorID = fmt.Errorf("invalid asset ID locator")

	// ErrInvalidLocatorKey is returned when a specified locator script key
	// is invalid.
	ErrInvalidLocatorKey = fmt.Errorf("invalid script key locator")

	// ErrOutPointMissing is returned when a specified locator does not
	// contain an outpoint. The outpoint is required when storing a proof.
	ErrOutPointMissing = fmt.Errorf("outpoint missing in key locator")

	// ErrMultipleProofs is returned if looking up a proof with only the
	// asset ID and script key results in multiple proofs being found.
	ErrMultipleProofs = fmt.Errorf(
		"multiple proofs found with asset ID and script key, specify " +
			"outpoint to disambiguate",
	)
)

// Locator is able to uniquely identify a proof in the extended Taproot Asset
// Universe by a combination of the: top-level asset ID, the group key, and also
// the script key.
type Locator struct {
	// AssetID the asset ID of the proof to fetch. This is an optional field.
	AssetID *asset.ID

	// GroupKey the group key of the asset to fetch. This is an optional
	// field.
	GroupKey *btcec.PublicKey

	// ScriptKey specifies the script key of the asset to fetch/store. This
	// field MUST be specified.
	ScriptKey btcec.PublicKey

	// OutPoint is the outpoint of the associated asset. This field is
	// optional.
	OutPoint *wire.OutPoint
}

// Hash returns a SHA256 hash of the bytes serialized locator.
func (l *Locator) Hash() ([32]byte, error) {
	var buf bytes.Buffer
	if l.AssetID != nil {
		buf.Write(l.AssetID[:])
	}
	if l.GroupKey != nil {
		buf.Write(l.GroupKey.SerializeCompressed())
	}
	buf.Write(l.ScriptKey.SerializeCompressed())

	if l.OutPoint != nil {
		err := lnwire.WriteOutPoint(&buf, *l.OutPoint)
		if err != nil {
			return [32]byte{}, fmt.Errorf("unable to write "+
				"outpoint: %w", err)
		}
	}

	// Hash the buffer.
	return sha256.Sum256(buf.Bytes()), nil
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
type Archiver interface {
	// FetchProof fetches a proof for an asset uniquely identified by the
	// passed ProofIdentifier.
	//
	// If a proof cannot be found, then ErrProofNotFound should be
	// returned.
	FetchProof(ctx context.Context, id Locator) (Blob, error)

	// HasProof returns true if the proof for the given locator exists. This
	// is intended to be a performance optimized lookup compared to fetching
	// a proof and checking for ErrProofNotFound.
	HasProof(ctx context.Context, id Locator) (bool, error)

	// FetchProofs fetches all proofs for assets uniquely identified by the
	// passed asset ID.
	FetchProofs(ctx context.Context, id asset.ID) ([]*AnnotatedProof, error)

	// ImportProofs attempts to store fully populated proofs on disk. The
	// previous outpoint of the first state transition will be used as the
	// Genesis point. The final resting place of the asset will be used as
	// the script key itself. If replace is specified, we expect a proof to
	// already be present, and we just update (replace) it with the new
	// proof.
	ImportProofs(ctx context.Context, headerVerifier HeaderVerifier,
		groupVerifier GroupVerifier, replace bool,
		proofs ...*AnnotatedProof) error
}

// NotifyArchiver is an Archiver that also allows callers to subscribe to
// notifications about new proofs being added to the archiver.
type NotifyArchiver interface {
	// FetchProof fetches a proof for an asset uniquely identified by the
	// passed Identifier. The returned blob is expected to be the encoded
	// full proof file, containing the complete provenance of the asset.
	//
	// If a proof cannot be found, then ErrProofNotFound should be returned.
	FetchProof(ctx context.Context, id Locator) (Blob, error)

	fn.EventPublisher[Blob, []*Locator]
}

// MultiArchiveNotifier is a NotifyArchiver that wraps several other archives
// and notifies subscribers about new proofs that are added to any of the
// archives.
type MultiArchiveNotifier struct {
	archives []NotifyArchiver
}

// NewMultiArchiveNotifier creates a new MultiArchiveNotifier based on the set
// of specified backends.
func NewMultiArchiveNotifier(archives ...NotifyArchiver) *MultiArchiveNotifier {
	return &MultiArchiveNotifier{
		archives: archives,
	}
}

// FetchProof fetches a proof for an asset uniquely identified by the passed
// Identifier. The returned proof can either be a full proof file or just a
// single proof.
//
// If a proof cannot be found, then ErrProofNotFound should be returned.
//
// NOTE: This is part of the NotifyArchiver interface.
func (m *MultiArchiveNotifier) FetchProof(ctx context.Context,
	id Locator) (Blob, error) {

	for idx := range m.archives {
		a := m.archives[idx]

		proofBlob, err := a.FetchProof(ctx, id)
		if errors.Is(err, ErrProofNotFound) {
			// Try the next archive.
			continue
		} else if err != nil {
			return nil, fmt.Errorf("error fetching proof "+
				"from archive: %w", err)
		}

		return proofBlob, nil
	}

	return nil, ErrProofNotFound
}

// RegisterSubscriber adds a new subscriber for receiving events. The
// registration request is forwarded to all registered archives.
func (m *MultiArchiveNotifier) RegisterSubscriber(
	receiver *fn.EventReceiver[Blob], deliverExisting bool,
	deliverFrom []*Locator) error {

	for idx := range m.archives {
		a := m.archives[idx]

		err := a.RegisterSubscriber(
			receiver, deliverExisting, deliverFrom,
		)
		if err != nil {
			return fmt.Errorf("error registering subscriber: %w",
				err)
		}
	}

	return nil
}

// RemoveSubscriber removes the given subscriber and also stops it from
// processing events. The removal request is forwarded to all registered
// archives.
func (m *MultiArchiveNotifier) RemoveSubscriber(
	subscriber *fn.EventReceiver[Blob]) error {

	for idx := range m.archives {
		a := m.archives[idx]

		err := a.RemoveSubscriber(subscriber)
		if err != nil {
			return fmt.Errorf("error removing subscriber: "+
				"%w", err)
		}
	}

	return nil
}

// A compile-time interface to ensure MultiArchiveNotifier meets the
// NotifyArchiver interface.
var _ NotifyArchiver = (*MultiArchiveNotifier)(nil)

// FileArchiver implements proof Archiver backed by an on-disk file system. The
// archiver takes a single root directory then creates the following overlap
// mapping:
//
//	proofs/
//	├─ asset_id1/
//	│  ├─ script_key1-outpoint.assetproof
//	│  ├─ script_key2-outpoint.assetproof
type FileArchiver struct {
	// proofPath is the directory name that we'll use as the roof for all
	// our files.
	proofPath string

	// eventDistributor is an event distributor that will be used to notify
	// subscribers about new proofs that are added to the archiver.
	eventDistributor *fn.EventDistributor[Blob]
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
		proofPath:        proofPath,
		eventDistributor: fn.NewEventDistributor[Blob](),
	}, nil
}

// genProofFileStoragePath generates the full proof file path for storing a
// proof based on a rootPath and a valid locator.
// The final path is: root/assetID/scriptKey-outpoint.assetproof.
//
// NOTE: Because some operating systems have issues with paths longer than 256
// characters, we don't use the full outpoint in the file name, but only the
// first 16 bytes (32 hex characters) of the hash. That should be enough to
// avoid collisions but saves us a full 32 characters (we already use 130 for
// the hex encoded asset ID and script key).
func genProofFileStoragePath(rootPath string, loc Locator) (string, error) {
	switch {
	case loc.AssetID == nil:
		return "", ErrInvalidLocatorID

	case loc.ScriptKey.IsEqual(&emptyKey):
		return "", ErrInvalidLocatorKey

	case loc.OutPoint == nil:
		return "", ErrOutPointMissing
	}

	assetID := hex.EncodeToString(loc.AssetID[:])

	truncatedHash := loc.OutPoint.Hash.String()[:outpointTruncateLength]
	fileName := fmt.Sprintf("%x-%s-%d%s", loc.ScriptKey.SerializeCompressed(),
		truncatedHash, loc.OutPoint.Index, TaprootAssetsFileSuffix)

	return filepath.Join(rootPath, assetID, fileName), nil
}

// lookupProofFilePath returns the full path for reading a proof file, based on
// the given locator. If the locator does not contain an outpoint, we'll check
// if there is just a single proof available on disk. If there is, we return
// that. If there are multiple, then the user needs to also specify the outpoint
// and we return ErrMultipleProofs.
func lookupProofFilePath(rootPath string, loc Locator) (string, error) {
	// If an outpoint is specified, we want to look up a very specific file
	// on disk.
	if loc.OutPoint != nil {
		fullName, err := genProofFileStoragePath(rootPath, loc)
		if err != nil {
			return "", err
		}

		// If the file doesn't exist under the full name, we know there
		// just isn't a proof file for that asset yet.
		if !lnrpc.FileExists(fullName) {
			return "", ErrProofNotFound
		}

		return fullName, nil
	}

	// If the user didn't specify an outpoint, we look up all proof files
	// that start with the script key given. If there is exactly one, we
	// return it.
	switch {
	case loc.AssetID == nil:
		return "", ErrInvalidLocatorID

	case loc.ScriptKey.IsEqual(&emptyKey):
		return "", ErrInvalidLocatorKey
	}
	assetID := hex.EncodeToString(loc.AssetID[:])
	scriptKey := hex.EncodeToString(loc.ScriptKey.SerializeCompressed())

	searchPattern := filepath.Join(rootPath, assetID, scriptKey+"*")
	matches, err := filepath.Glob(searchPattern)
	if err != nil {
		return "", fmt.Errorf("error listing proof files: %w", err)
	}

	switch {
	// We have no proof for this script key.
	case len(matches) == 0:
		return "", ErrProofNotFound

	// Exactly one proof for this script key, we'll return it.
	case len(matches) == 1:
		return matches[0], nil

	// User needs to specify the outpoint as well, since we have multiple
	// proofs for this script key.
	default:
		return "", ErrMultipleProofs
	}
}

// FetchProof fetches a proof for an asset uniquely identified by the passed
// ProofIdentifier.
//
// If a proof cannot be found, then ErrProofNotFound should be returned.
//
// NOTE: This implements the Archiver interface.
func (f *FileArchiver) FetchProof(_ context.Context, id Locator) (Blob, error) {
	// All our on-disk storage is based on asset IDs, so to look up a path,
	// we just need to compute the full file path and see if it exists on
	// disk.
	proofPath, err := lookupProofFilePath(f.proofPath, id)
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

// HasProof returns true if the proof for the given locator exists. This is
// intended to be a performance optimized lookup compared to fetching a proof
// and checking for ErrProofNotFound.
func (f *FileArchiver) HasProof(_ context.Context, id Locator) (bool, error) {
	// All our on-disk storage is based on asset IDs, so to look up a path,
	// we just need to compute the full file path and see if it exists on
	// disk.
	proofPath, err := lookupProofFilePath(f.proofPath, id)
	if err != nil {
		return false, fmt.Errorf("unable to make proof file path: %w",
			err)
	}

	return lnrpc.FileExists(proofPath), nil
}

// FetchProofs fetches all proofs for assets uniquely identified by the passed
// asset ID.
func (f *FileArchiver) FetchProofs(_ context.Context,
	id asset.ID) ([]*AnnotatedProof, error) {

	assetID := hex.EncodeToString(id[:])
	assetPath := filepath.Join(f.proofPath, assetID)
	entries, err := os.ReadDir(assetPath)
	if err != nil {
		return nil, fmt.Errorf("unable to read dir %s: %w", assetPath,
			err)
	}

	proofs := make([]*AnnotatedProof, len(entries))
	for idx := range entries {
		// We'll skip any files that don't end with our suffix, this
		// will include directories as well, so we don't need to check
		// for those.
		fileName := entries[idx].Name()
		if !strings.HasSuffix(fileName, TaprootAssetsFileSuffix) {
			continue
		}

		parts := strings.Split(strings.ReplaceAll(
			fileName, TaprootAssetsFileSuffix, "",
		), "-")
		if len(parts) != 2 {
			return nil, fmt.Errorf("malformed proof file name "+
				"'%s', expected two parts, got %d", fileName,
				len(parts))
		}

		scriptKeyBytes, err := hex.DecodeString(parts[0])
		if err != nil {
			return nil, fmt.Errorf("malformed proof file name, "+
				"unable to decode script key: %w", err)
		}

		scriptKey, err := btcec.ParsePubKey(scriptKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("malformed proof file name, "+
				"unable to parse script key: %w", err)
		}

		outPoint, err := ParseOutPoint(parts[1])
		if err != nil {
			return nil, fmt.Errorf("malformed proof file name, "+
				"unable to parse outpoint: %w", err)
		}

		fullPath := filepath.Join(assetPath, fileName)
		proofFile, err := os.ReadFile(fullPath)
		if err != nil {
			return nil, fmt.Errorf("unable to read proof: %w", err)
		}

		proofs[idx] = &AnnotatedProof{
			Locator: Locator{
				AssetID:   &id,
				ScriptKey: *scriptKey,
				OutPoint:  outPoint,
			},
			Blob: proofFile,
		}
	}

	return proofs, nil
}

// ImportProofs attempts to store fully populated proofs on disk. The previous
// outpoint of the first state transition will be used as the Genesis point.
// The final resting place of the asset will be used as the script key itself.
// If replace is specified, we expect a proof to already be present, and we just
// update (replace) it with the new proof.
//
// NOTE: This implements the Archiver interface.
func (f *FileArchiver) ImportProofs(_ context.Context,
	_ HeaderVerifier, _ GroupVerifier, replace bool,
	proofs ...*AnnotatedProof) error {

	for _, proof := range proofs {
		proofPath, err := genProofFileStoragePath(
			f.proofPath, proof.Locator,
		)
		if err != nil {
			return err
		}

		if err := os.MkdirAll(filepath.Dir(proofPath), 0750); err != nil {
			return err
		}

		// Can't replace a file that doesn't exist yet.
		if replace && !lnrpc.FileExists(proofPath) {
			return fmt.Errorf("cannot replace proof because file "+
				"%s does not exist", proofPath)
		}

		err = os.WriteFile(proofPath, proof.Blob, 0666)
		if err != nil {
			return fmt.Errorf("unable to store proof: %v", err)
		}

		f.eventDistributor.NotifySubscribers(proof.Blob)
	}

	return nil
}

// RegisterSubscriber adds a new subscriber for receiving events. The
// deliverExisting boolean indicates whether already existing items should be
// sent to the NewItemCreated channel when the subscription is started. An
// optional deliverFrom can be specified to indicate from which timestamp/index/
// marker onward existing items should be delivered on startup. If deliverFrom
// is nil/zero/empty then all existing items will be delivered.
func (f *FileArchiver) RegisterSubscriber(
	receiver *fn.EventReceiver[Blob],
	deliverExisting bool, deliverFrom []*Locator) error {

	f.eventDistributor.RegisterSubscriber(receiver)

	// No delivery of existing items requested, we're done here.
	if !deliverExisting {
		return nil
	}

	for _, loc := range deliverFrom {
		blob, err := f.FetchProof(nil, *loc)
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
func (f *FileArchiver) RemoveSubscriber(
	subscriber *fn.EventReceiver[Blob]) error {

	return f.eventDistributor.RemoveSubscriber(subscriber)
}

// A compile-time interface to ensure FileArchiver meets the NotifyArchiver
// interface.
var _ NotifyArchiver = (*FileArchiver)(nil)

// MultiArchiver is an archive of archives. It contains several archives and
// attempts to use them either as a look-aside cache, or a write through cache
// for all incoming requests.
type MultiArchiver struct {
	proofVerifier Verifier
	backends      []Archiver

	// archiveTimeout is the default timeout to use for any archive
	// interaction.
	archiveTimeout time.Duration

	// eventDistributor is an event distributor that will be used to notify
	// subscribers about new proofs that are added to the archiver.
	eventDistributor *fn.EventDistributor[Blob]
}

// NewMultiArchiver creates a new MultiArchiver based on the set of specified
// backends.
func NewMultiArchiver(verifier Verifier, archiveTimeout time.Duration,
	backends ...Archiver) *MultiArchiver {

	return &MultiArchiver{
		proofVerifier:    verifier,
		backends:         backends,
		archiveTimeout:   archiveTimeout,
		eventDistributor: fn.NewEventDistributor[Blob](),
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

// HasProof returns true if the proof for the given locator exists. This is
// intended to be a performance optimized lookup compared to fetching a proof
// and checking for ErrProofNotFound. The multi archiver only considers a proof
// to be present if all backends have it.
func (m *MultiArchiver) HasProof(ctx context.Context, id Locator) (bool, error) {
	for _, archive := range m.backends {
		ok, err := archive.HasProof(ctx, id)
		if err != nil {
			return false, err
		}

		// We are expecting all backends to have the proof, otherwise we
		// consider the proof not to be found.
		if !ok {
			return false, nil
		}
	}

	return true, nil
}

// FetchProofs fetches all proofs for assets uniquely identified by the passed
// asset ID.
func (m *MultiArchiver) FetchProofs(ctx context.Context,
	id asset.ID) ([]*AnnotatedProof, error) {

	// We are listing proofs, so it shouldn't matter which backend we use.
	return m.backends[0].FetchProofs(ctx, id)
}

// ImportProofs attempts to store fully populated proofs on disk. The previous
// outpoint of the first state transition will be used as the Genesis point.
// The final resting place of the asset will be used as the script key itself.
func (m *MultiArchiver) ImportProofs(ctx context.Context,
	headerVerifier HeaderVerifier, groupVerifier GroupVerifier,
	replace bool, proofs ...*AnnotatedProof) error {

	// Before we import the proofs into the archive, we want to make sure
	// that they're all valid. Along the way, we may augment the locator
	// for each proof accordingly.
	f := func(c context.Context, proof *AnnotatedProof) error {
		// First, we'll decode and then also verify the proof.
		finalStateTransition, err := m.proofVerifier.Verify(
			c, bytes.NewReader(proof.Blob), headerVerifier,
			groupVerifier,
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

			if finalAsset.GroupKey != nil {
				proof.GroupKey = &finalAsset.GroupKey.GroupPubKey
			}

			proof.ScriptKey = *finalAsset.ScriptKey.PubKey
		}

		return nil
	}

	if err := fn.ParSlice(ctx, proofs, f); err != nil {
		return err
	}

	// Now that we know all the proofs are valid, and have tacked on some
	// additional supplementary information into the locator, we'll attempt
	// to import each proof our archive backends.
	for _, archive := range m.backends {
		err := archive.ImportProofs(
			ctx, headerVerifier, groupVerifier, replace, proofs...,
		)
		if err != nil {
			return err
		}
	}

	// Deliver each new proof to the new item queue of the subscribers.
	blobs := fn.Map(proofs, func(p *AnnotatedProof) Blob {
		return p.Blob
	})
	m.eventDistributor.NotifySubscribers(blobs...)

	return nil
}

// RegisterSubscriber adds a new subscriber for receiving events. The
// deliverExisting boolean indicates whether already existing items should be
// sent to the NewItemCreated channel when the subscription is started. An
// optional deliverFrom can be specified to indicate from which timestamp/index/
// marker onward existing items should be delivered on startup. If deliverFrom
// is nil/zero/empty then all existing items will be delivered.
func (m *MultiArchiver) RegisterSubscriber(receiver *fn.EventReceiver[Blob],
	deliverExisting bool, deliverFrom []*Locator) error {

	m.eventDistributor.RegisterSubscriber(receiver)

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
	subscriber *fn.EventReceiver[Blob]) error {

	return m.eventDistributor.RemoveSubscriber(subscriber)
}

// A compile-time assertion to make sure MultiArchiver satisfies the
// NotifyArchiver interface.
var _ NotifyArchiver = (*MultiArchiver)(nil)

// ReplaceProofInBlob attempts to replace a proof in all proof files we have for
// assets of the same ID. This is useful when we want to update the proof with a
// new one after a re-org.
func ReplaceProofInBlob(ctx context.Context, p *Proof, archive Archiver,
	headerVerifier HeaderVerifier, groupVerifier GroupVerifier) error {

	// This is a bit of a hacky part. If we have a chain of transactions
	// that were re-organized, we can't verify the whole chain until all of
	// the transactions were confirmed and all proofs were updated with the
	// new blocks and merkle roots. So we'll skip the verification here
	// since we don't know if the whole chain has been updated yet (the
	// confirmations might come in out of order).
	// TODO(guggero): Find a better way to do this.
	headerVerifier = func(wire.BlockHeader, uint32) error {
		return nil
	}

	assetID := p.Asset.ID()
	scriptPubKeyOfUpdate := p.Asset.ScriptKey.PubKey

	// We now fetch all proofs of that same asset ID and filter out those
	// that need updating.
	proofs, err := archive.FetchProofs(ctx, assetID)
	if err != nil {
		return fmt.Errorf("unable to fetch all proofs for asset ID "+
			"%x: %w", assetID[:], err)
	}

	for idx := range proofs {
		existingProof := proofs[idx]

		f := &File{}
		err := f.Decode(bytes.NewReader(existingProof.Blob))
		if err != nil {
			return fmt.Errorf("unable to decode current proof: %w",
				err)
		}

		// We only need to update proofs that contain this asset in the
		// chain and haven't been updated yet (i.e. the block hash of
		// the proof is different from the block hash of the proof we
		// want to update).
		_, indexToUpdate, err := f.LocateProof(func(fp *Proof) bool {
			fileScriptKey := fp.Asset.ScriptKey.PubKey
			fileTxHash := fp.AnchorTx.TxHash()
			fileBlockHash := fp.BlockHeader.BlockHash()
			return fileScriptKey.IsEqual(scriptPubKeyOfUpdate) &&
				fileTxHash == p.AnchorTx.TxHash() &&
				fileBlockHash != p.BlockHeader.BlockHash()
		})
		if err != nil {
			// Either we failed to decode the proof for some reason,
			// or we didn't find a proof that needs updating. In
			// either case, we can skip this file.
			continue
		}

		log.Debugf("Updating descendant proof at index %d "+
			"(script_key=%x) in file with %d proofs", indexToUpdate,
			scriptPubKeyOfUpdate.SerializeCompressed(),
			f.NumProofs())

		// All good, we can now replace the proof in the file with the
		// new one.
		err = f.ReplaceProofAt(indexToUpdate, *p)
		if err != nil {
			return fmt.Errorf("unable to replace proof at index "+
				"%d with updated one: %w", indexToUpdate, err)
		}

		var buf bytes.Buffer
		if err := f.Encode(&buf); err != nil {
			return fmt.Errorf("unable to encode updated proof: %w",
				err)
		}

		// We now update this direct proof in the archive.
		directProof := &AnnotatedProof{
			Locator: existingProof.Locator,
			Blob:    buf.Bytes(),
		}
		err = archive.ImportProofs(
			ctx, headerVerifier, groupVerifier, true, directProof,
		)
		if err != nil {
			return fmt.Errorf("unable to import updated proof: %w",
				err)
		}
	}

	return nil
}
