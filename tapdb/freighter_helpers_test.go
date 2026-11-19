package tapdb

import (
	"context"
	"fmt"
	"time"

	"github.com/lightninglabs/taproot-assets/tapfreighter"
)

// LogPendingParcel stakes an outbound parcel in a transaction of its own.
// Production stakes a parcel inside the anchoring watcher's registration
// transaction through ApplyPendingParcel; tests use this to build a
// pending transfer directly. The final lease owner and expiry are the
// lease parameters set on the input UTXOs: the parcel is assumed to be
// broadcast after this call, so the inputs are leased far into the
// future.
func (a *AssetStore) LogPendingParcel(ctx context.Context,
	spend *tapfreighter.OutboundParcel, finalLeaseOwner [32]byte,
	finalLeaseExpiry time.Time) error {

	var writeTxOpts AssetStoreTxOptions
	return a.db.ExecTx(ctx, &writeTxOpts, func(q ActiveAssetsStore) error {
		return a.applyPendingParcel(
			ctx, q, spend, finalLeaseOwner, finalLeaseExpiry,
		)
	})
}

// LogAnchorTxConfirm applies an anchor transaction's confirmation in a
// transaction of its own and announces the resulting proofs. Production
// applies a confirmation inside the anchoring watcher's delivery
// transaction through ApplyAnchorTxConfirm; tests use this to confirm a
// transfer directly.
func (a *AssetStore) LogAnchorTxConfirm(ctx context.Context,
	conf *tapfreighter.AssetConfirmEvent,
	burns []*tapfreighter.AssetBurn) error {

	var (
		writeTxOpts    AssetStoreTxOptions
		localProofKeys []tapfreighter.OutputIdentifier
	)
	err := a.db.ExecTx(ctx, &writeTxOpts, func(q ActiveAssetsStore) error {
		var err error
		localProofKeys, err = a.applyAnchorTxConfirm(
			ctx, q, conf, burns,
		)

		return err
	})
	if err != nil {
		return fmt.Errorf("failed to confirm transfer: %w", err)
	}

	// Notify any event subscribers that there are new proofs. We do this
	// outside of the transaction to avoid the subscribers trying to look up
	// the proofs before they are committed.
	for idx := range localProofKeys {
		localKey := localProofKeys[idx]
		finalProof := conf.FinalProofs[localKey]
		a.eventDistributor.NotifySubscribers(finalProof.Blob)
	}
	for assetID := range conf.PassiveAssetProofFiles {
		passiveProofs := conf.PassiveAssetProofFiles[assetID]
		for idx := range passiveProofs {
			passiveProof := passiveProofs[idx]
			a.eventDistributor.NotifySubscribers(passiveProof.Blob)
		}
	}

	return nil
}
