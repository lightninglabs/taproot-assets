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
)

const (
	// TaprootAssetsFileSuffix is the main file suffix for the Taproot Asset
	// proof files stored on disk.
	TaprootAssetsFileSuffix = ".assetproof"

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
}

// Hash returns a SHA256 hash of the bytes serialized locator.
func (l *Locator) Hash() [32]byte {
	var buf bytes.Buffer
	if l.AssetID != nil {
		buf.Write(l.AssetID[:])
	}
	if l.GroupKey != nil {
		buf.Write(l.GroupKey.SerializeCompressed())
	}
	buf.Write(l.ScriptKey.SerializeCompressed())

	// Hash the buffer.
	return sha256.Sum256(buf.Bytes())
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
	Archiver

	fn.EventPublisher[Blob, []*Locator]
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

// genProofFilePath generates the full proof file path based on a rootPath and
// a valid locator. The final path is: root/assetID/scriptKey.assetproof
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

	return filepath.Join(rootPath, assetID, scriptKey+TaprootAssetsFileSuffix), nil
}

// FetchProof fetches a proof for an asset uniquely identified by the
// passed ProofIdentifier.
//
// If a proof cannot be found, then ErrProofNotFound should be
// returned.
//
// NOTE: This implements the Archiver interface.
func (f *FileArchiver) FetchProof(_ context.Context, id Locator) (Blob, error) {
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

		scriptKeyBytes, err := hex.DecodeString(strings.ReplaceAll(
			fileName, TaprootAssetsFileSuffix, "",
		))
		if err != nil {
			return nil, fmt.Errorf("malformed proof file name, "+
				"unable to decode script key: %w", err)
		}

		scriptKey, err := btcec.ParsePubKey(scriptKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("malformed proof file name, "+
				"unable to parse script key: %w", err)
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
		proofPath, err := genProofFilePath(f.proofPath, proof.Locator)
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
