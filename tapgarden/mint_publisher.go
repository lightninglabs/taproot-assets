package tapgarden

import (
	"context"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/proof"
)

// MintProofPublisher ships freshly-minted (or re-organized) assets and
// their proofs to a downstream proof distributor (e.g. a local or remote
// universe). tapgarden owns this interface as the consumer; the
// implementation lives in another package because the act of publishing
// proofs out is extrinsic to tapgarden's end (a verifiable asset in the
// local store).
type MintProofPublisher interface {
	// PublishMintBatch publishes the proofs for a confirmed minting
	// batch. The publisher is responsible for any batching, ordering,
	// or retry semantics it requires.
	PublishMintBatch(ctx context.Context,
		params MintBatchPublishParams) error

	// PublishMintProofUpdates publishes proof updates emitted after a
	// chain re-org affected previously-minted assets. Each proof is the
	// updated, fully-encoded minting proof.
	PublishMintProofUpdates(ctx context.Context,
		proofs []*proof.Proof) error
}

// MintBatchPublishParams carries the data needed by a MintProofPublisher
// to publish the proofs for a confirmed minting batch.
type MintBatchPublishParams struct {
	// Assets is the set of newly-minted assets in the batch, in the
	// order they should be inserted (group anchors first).
	Assets []*asset.Asset

	// Proofs is the per-asset minting proof, keyed by the asset's
	// serialized script key.
	Proofs map[asset.SerializedKey]*proof.Proof

	// MintTxHash is the hash of the genesis transaction that anchors
	// the batch.
	MintTxHash chainhash.Hash

	// AnchorOutIdx is the output index of the asset anchor in the
	// genesis transaction.
	AnchorOutIdx uint32
}

// NoOpMintProofPublisher is a publisher that does nothing. It is
// intended for tests and configurations that have no universe to ship
// proofs to.
type NoOpMintProofPublisher struct{}

// PublishMintBatch is a no-op.
func (NoOpMintProofPublisher) PublishMintBatch(_ context.Context,
	_ MintBatchPublishParams) error {

	return nil
}

// PublishMintProofUpdates is a no-op.
func (NoOpMintProofPublisher) PublishMintProofUpdates(_ context.Context,
	_ []*proof.Proof) error {

	return nil
}

// Compile-time assertion that NoOpMintProofPublisher implements the
// MintProofPublisher interface.
var _ MintProofPublisher = NoOpMintProofPublisher{}
