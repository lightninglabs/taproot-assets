package tapgarden

import (
	"context"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapsend"
)

// GenesisTxAugmenter is the interface that tapgarden invokes at
// well-defined lifecycle moments to let an external substance
// participate in batch minting without tapgarden having to know
// what the substance is doing. The augmenter's outputs ride on
// the genesis tx, its persistence rides on the BatchStore's
// binding tx, and its post-confirmation events fire once the
// batch is durably anchored.
//
// The canonical use case is the supply-commitment subsystem,
// which contributes a pre-commitment output to the genesis tx
// and emits a mint event after confirmation. Other subsystems
// could implement the same interface without tapgarden needing
// to learn anything about them.
//
// A nil GenesisTxAugmenter on GardenKit means no augmenter is
// active. All planter call sites tolerate a nil pointer (via
// the planter's internal helper) so callers may leave it unset
// for tests or for tapd instances that do not run a
// supply-commit substance.
type GenesisTxAugmenter interface {
	// PrepareSeedling runs at seedling intake before
	// validation. The hook may mutate req to populate
	// augmenter-managed fields (e.g. delegation keys derived
	// from the batch's existing seedlings or from external
	// state). An error here aborts the seedling intake.
	PrepareSeedling(ctx context.Context, batch *MintingBatch,
		req *Seedling) error

	// ValidateSeedling gates seedling-into-batch admission by
	// augmenter-owned invariants (e.g. homogeneity of the
	// SupplyCommitments flag within a batch). Called from the
	// planter after the batch's own validation has passed.
	ValidateSeedling(batch *MintingBatch, req Seedling) error

	// ExtraOutputs returns the extra outputs (if any) that
	// should be spliced into the unfunded anchor PSBT for this
	// batch. Each output's PkScript must be deterministic from
	// the batch's contents so the augmenter can locate the same
	// output in the funded PSBT.
	ExtraOutputs(ctx context.Context,
		batch *MintingBatch) ([]wire.TxOut, error)

	// PostFund is called once the wallet has funded the anchor
	// PSBT. The hook locates its own outputs by matching against
	// the result of ExtraOutputs and stamps any required
	// metadata (e.g. BIP32 derivation paths) on the
	// corresponding PSBT outputs.
	PostFund(ctx context.Context, batch *MintingBatch,
		funded *tapsend.FundedPsbt) error

	// BindData returns the typed persistence payload that the
	// BatchStore should write for the augmenter's outputs (if
	// any). Called by tapgarden immediately after funding (so
	// the row lands atomically with the batch chain update)
	// and again at seal time (so the row picks up newly
	// available group-key info). The implementation reads from
	// the batch's current state.
	BindData(ctx context.Context,
		batch *MintingBatch) (fn.Option[PreCommitBindData], error)

	// OnBatchConfirmed runs once the batch has confirmed on
	// chain and the cultivator has archived its proofs locally.
	// The hook may emit downstream events (e.g. supply-commit
	// notifications). An error is logged but does not unwind
	// the confirmation.
	OnBatchConfirmed(ctx context.Context, batch *MintingBatch,
		anchorAssets, nonAnchorAssets []*asset.Asset,
		mintingProofs proof.AssetProofs) error
}

// NoOpAugmenter is a GenesisTxAugmenter that does nothing. The
// planter substitutes it whenever GardenKit.GenesisTxAugmenter
// is nil, so internal call sites never need to check.
type NoOpAugmenter struct{}

// PrepareSeedling is a no-op.
func (NoOpAugmenter) PrepareSeedling(_ context.Context,
	_ *MintingBatch, _ *Seedling) error {

	return nil
}

// ValidateSeedling is a no-op.
func (NoOpAugmenter) ValidateSeedling(_ *MintingBatch, _ Seedling) error {
	return nil
}

// ExtraOutputs returns no extra outputs.
func (NoOpAugmenter) ExtraOutputs(_ context.Context,
	_ *MintingBatch) ([]wire.TxOut, error) {

	return nil, nil
}

// PostFund is a no-op.
func (NoOpAugmenter) PostFund(_ context.Context, _ *MintingBatch,
	_ *tapsend.FundedPsbt) error {

	return nil
}

// BindData returns no persistence payload.
func (NoOpAugmenter) BindData(_ context.Context,
	_ *MintingBatch) (fn.Option[PreCommitBindData], error) {

	return fn.None[PreCommitBindData](), nil
}

// OnBatchConfirmed is a no-op.
func (NoOpAugmenter) OnBatchConfirmed(_ context.Context, _ *MintingBatch,
	_, _ []*asset.Asset, _ proof.AssetProofs) error {

	return nil
}

// A compile-time assertion to ensure NoOpAugmenter satisfies the
// GenesisTxAugmenter interface.
var _ GenesisTxAugmenter = NoOpAugmenter{}
