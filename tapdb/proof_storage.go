package tapdb

import (
	"bytes"
	"context"
	"fmt"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
)

// AssetProofStore is the narrow database interface needed to atomically store
// a proof file together with its reverse provenance index.
type AssetProofStore interface {
	UpsertAssetProofByID(context.Context, ProofUpdateByID) error
	FetchAssetProofID(context.Context, int64) (int64, error)
	FetchAssetProofFileByProofID(context.Context, int64) ([]byte, error)
	DeleteAssetProofAnchors(context.Context, int64) error
	InsertAssetProofAnchor(context.Context,
		sqlc.InsertAssetProofAnchorParams) error
	MarkAssetProofProvenanceIndexed(context.Context, int64) error
}

// IndexedProofFile is a decoded proof file bound to the complete set of its
// anchor transactions. The interface is sealed so a raw blob and a stale or
// partial provenance index can't be paired by callers.
type IndexedProofFile interface {
	proofBlob() proof.Blob
	anchorTxIDs() []chainhash.Hash
	isIndexedProofFile()
}

type indexedProofFile struct {
	blob  proof.Blob
	txIDs []chainhash.Hash
}

// NewIndexedProofFile decodes a proof blob and derives its complete set of
// anchor transactions from the full proof DAG. A historical single-proof blob
// is read as a one-proof file, the same way every consumer of the index reads
// it back; the stored bytes stay as written.
func NewIndexedProofFile(blob proof.Blob) (IndexedProofFile, error) {
	proofFile, err := blob.AsFile()
	if err != nil {
		return nil, fmt.Errorf("decoding proof blob: %w", err)
	}

	return indexedProofFileFromDecoded(blob, proofFile)
}

// NewIndexedProofFileFromFile binds a decoded proof file to its complete
// provenance index without decoding it a second time.
func NewIndexedProofFileFromFile(
	proofFile *proof.File) (IndexedProofFile, error) {

	if proofFile == nil {
		return nil, fmt.Errorf("proof file is nil")
	}

	var encoded bytes.Buffer
	if err := proofFile.Encode(&encoded); err != nil {
		return nil, fmt.Errorf("encoding proof file: %w", err)
	}

	return indexedProofFileFromDecoded(encoded.Bytes(), proofFile)
}

// NewIndexedProofFileFromRestamp binds a restamped file to the anchors its
// own traversal visited, sparing the second traversal
// NewIndexedProofFileFromFile would make. Only proof.RestampAnchor can
// produce the argument, so the pairing is the traversal's.
func NewIndexedProofFileFromRestamp(
	restamped *proof.Restamped) (IndexedProofFile, error) {

	if restamped == nil {
		return nil, fmt.Errorf("restamped proof file is nil")
	}
	blob := restamped.Blob()
	if len(blob) == 0 {
		return nil, fmt.Errorf("restamped proof file is empty")
	}

	return &indexedProofFile{
		blob: append(proof.Blob(nil), blob...),
		txIDs: append(
			[]chainhash.Hash(nil), restamped.AnchorTxIDs()...,
		),
	}, nil
}

func indexedProofFileFromDecoded(blob proof.Blob,
	proofFile *proof.File) (IndexedProofFile, error) {

	txIDs, err := proofFile.AnchorTxIDs()
	if err != nil {
		return nil, fmt.Errorf("indexing proof DAG: %w", err)
	}

	return &indexedProofFile{
		blob:  append(proof.Blob(nil), blob...),
		txIDs: txIDs,
	}, nil
}

func (f *indexedProofFile) proofBlob() proof.Blob {
	return f.blob
}

func (f *indexedProofFile) anchorTxIDs() []chainhash.Hash {
	return f.txIDs
}

func (f *indexedProofFile) isIndexedProofFile() {}

// StoreIndexedAssetProof replaces a proof blob and its reverse provenance
// index. The store must be an active write transaction so all operations
// commit or roll back together.
func StoreIndexedAssetProof(ctx context.Context, store AssetProofStore,
	assetID int64, proofFile IndexedProofFile) error {

	if proofFile == nil {
		return fmt.Errorf("indexed proof file is nil")
	}

	err := store.UpsertAssetProofByID(ctx, ProofUpdateByID{
		AssetID:   assetID,
		ProofFile: proofFile.proofBlob(),
	})
	if err != nil {
		return fmt.Errorf("upserting asset proof: %w", err)
	}

	proofID, err := store.FetchAssetProofID(ctx, assetID)
	if err != nil {
		return fmt.Errorf("fetching asset proof ID: %w", err)
	}

	return IndexStoredAssetProof(ctx, store, proofID, proofFile)
}

// IndexStoredAssetProof replaces the provenance index for an already stored
// proof. The store must be an active write transaction, and the stored blob
// must match the indexed file's bytes: the pairing is verified here so
// provenance is never marked trusted for bytes it was not derived from.
func IndexStoredAssetProof(ctx context.Context, store AssetProofStore,
	proofID int64, proofFile IndexedProofFile) error {

	if proofFile == nil {
		return fmt.Errorf("indexed proof file is nil")
	}

	storedBlob, err := store.FetchAssetProofFileByProofID(ctx, proofID)
	if err != nil {
		return fmt.Errorf("fetching stored proof file: %w", err)
	}
	if !bytes.Equal(storedBlob, proofFile.proofBlob()) {
		return fmt.Errorf("stored proof %d does not match indexed "+
			"proof file", proofID)
	}

	err = store.DeleteAssetProofAnchors(ctx, proofID)
	if err != nil {
		return fmt.Errorf("clearing proof provenance: %w", err)
	}

	for _, txID := range proofFile.anchorTxIDs() {
		err := store.InsertAssetProofAnchor(
			ctx, sqlc.InsertAssetProofAnchorParams{
				ProofID:    proofID,
				AnchorTxid: txID[:],
			},
		)
		if err != nil {
			return fmt.Errorf("inserting proof provenance: %w", err)
		}
	}

	err = store.MarkAssetProofProvenanceIndexed(ctx, proofID)
	if err != nil {
		return fmt.Errorf("marking proof provenance indexed: %w", err)
	}

	return nil
}
