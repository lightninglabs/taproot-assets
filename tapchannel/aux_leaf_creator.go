package tapchannel

import (
	"bytes"
	"fmt"
	"sync"
	"time"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/fn"
	cmsg "github.com/lightninglabs/taproot-assets/tapchannelmsg"
	"github.com/lightningnetwork/lnd/channeldb"
	lfn "github.com/lightningnetwork/lnd/fn"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/tlv"
)

const (
	// DefaultTimeout is the default timeout we use for RPC and database
	// operations.
	DefaultTimeout = 30 * time.Second
)

// LeafCreatorConfig defines the configuration for the auxiliary leaf creator.
type LeafCreatorConfig struct {
	ChainParams *address.ChainParams
}

// AuxLeafCreator is a Taproot Asset auxiliary leaf creator that can be used to
// create auxiliary leaves for Taproot Asset channels.
type AuxLeafCreator struct {
	startOnce sync.Once
	stopOnce  sync.Once

	cfg *LeafCreatorConfig

	// ContextGuard provides a wait group and main quit channel that can be
	// used to create guarded contexts.
	*fn.ContextGuard
}

// NewAuxLeafCreator creates a new Taproot Asset auxiliary leaf creator based on
// the passed config.
func NewAuxLeafCreator(cfg *LeafCreatorConfig) *AuxLeafCreator {
	return &AuxLeafCreator{
		cfg: cfg,
		ContextGuard: &fn.ContextGuard{
			DefaultTimeout: DefaultTimeout,
			Quit:           make(chan struct{}),
		},
	}
}

// Start attempts to start a new aux leaf creator.
func (c *AuxLeafCreator) Start() error {
	var startErr error
	c.startOnce.Do(func() {
		log.Info("Starting aux leaf creator")
	})
	return startErr
}

// Stop signals for a custodian to gracefully exit.
func (c *AuxLeafCreator) Stop() error {
	var stopErr error
	c.stopOnce.Do(func() {
		log.Info("Stopping aux leaf creator")

		close(c.Quit)
		c.Wg.Wait()
	})

	return stopErr
}

// A compile-time check to ensure that AuxLeafCreator fully implements the
// lnwallet.AuxLeafStore interface.
var _ lnwallet.AuxLeafStore = (*AuxLeafCreator)(nil)

// FetchLeavesFromView attempts to fetch the auxiliary leaves that correspond to
// the passed aux blob, and pending fully evaluated HTLC view.
func (c *AuxLeafCreator) FetchLeavesFromView(chanState *channeldb.OpenChannel,
	prevBlob tlv.Blob, originalView *lnwallet.HtlcView, isOurCommit bool,
	ourBalance, theirBalance lnwire.MilliSatoshi,
	keys lnwallet.CommitmentKeyRing) (lfn.Option[lnwallet.CommitAuxLeaves],
	lnwallet.CommitSortFunc, error) {

	none := lfn.None[lnwallet.CommitAuxLeaves]()

	// If the channel has no custom blob, we don't need to do anything.
	if chanState.CustomBlob.IsNone() {
		return none, nil, nil
	}

	chanAssetState, err := cmsg.DecodeOpenChannel(
		chanState.CustomBlob.UnsafeFromSome(),
	)
	if err != nil {
		return none, nil, fmt.Errorf("unable to decode channel asset "+
			"state: %w", err)
	}

	prevState, err := cmsg.DecodeCommitment(prevBlob)
	if err != nil {
		return none, nil, fmt.Errorf("unable to decode prev commit "+
			"state: %w", err)
	}

	allocations, newCommitment, err := GenerateCommitmentAllocations(
		prevState, chanState, chanAssetState, isOurCommit, ourBalance,
		theirBalance, originalView, c.cfg.ChainParams, keys,
	)
	if err != nil {
		return none, nil, fmt.Errorf("unable to generate allocations: "+
			"%w", err)
	}

	customCommitSort := func(tx *wire.MsgTx, cltvs []uint32,
		htlcIndexes []input.HtlcIndex) error {

		return InPlaceCustomCommitSort(
			tx, cltvs, htlcIndexes, allocations,
		)
	}

	return lfn.Some(newCommitment.Leaves()), customCommitSort, nil
}

// FetchLeavesFromCommit attempts to fetch the auxiliary leaves that correspond
// to the passed aux blob, and an existing channel commitment.
func (c *AuxLeafCreator) FetchLeavesFromCommit(chanState *channeldb.OpenChannel,
	com channeldb.ChannelCommitment,
	keys lnwallet.CommitmentKeyRing) (lfn.Option[lnwallet.CommitAuxLeaves],
	error) {

	none := lfn.None[lnwallet.CommitAuxLeaves]()

	// If the commitment has no custom blob, we don't need to do anything.
	if com.CustomBlob.IsNone() {
		return none, nil
	}

	commitment, err := cmsg.DecodeCommitment(
		com.CustomBlob.UnsafeFromSome(),
	)
	if err != nil {
		return none, fmt.Errorf("unable to decode commitment: %w", err)
	}

	incomingHtlcs := commitment.IncomingHtlcAssets.Val.HtlcOutputs
	incomingHtlcLeaves := commitment.AuxLeaves.Val.IncomingHtlcLeaves.
		Val.HtlcAuxLeaves
	outgoingHtlcs := commitment.OutgoingHtlcAssets.Val.HtlcOutputs
	outgoingHtlcLeaves := commitment.AuxLeaves.Val.
		OutgoingHtlcLeaves.Val.HtlcAuxLeaves
	for idx := range com.Htlcs {
		htlc := com.Htlcs[idx]
		htlcIdx := htlc.HtlcIndex

		if htlc.Incoming {
			htlcOutputs := incomingHtlcs[htlcIdx].Outputs
			auxLeaf := incomingHtlcLeaves[htlcIdx].AuxLeaf

			// If this HTLC doesn't have any auxiliary leaves, it's
			// not an asset HTLC, so we can skip it.
			if len(htlcOutputs) == 0 {
				continue
			}

			leaf, err := CreateSecondLevelHtlcTx(
				chanState, com.CommitTx, htlc.Amt.ToSatoshis(),
				keys, c.cfg.ChainParams, htlcOutputs,
			)
			if err != nil {
				return none, fmt.Errorf("unable to create "+
					"second level HTLC leaf: %w", err)
			}

			existingLeaf := lfn.MapOption(
				func(l cmsg.TapLeafRecord) txscript.TapLeaf {
					return l.Leaf
				},
			)(auxLeaf.ValOpt())

			incomingHtlcLeaves[htlcIdx] = cmsg.NewHtlcAuxLeaf(
				input.HtlcAuxLeaf{
					AuxTapLeaf:      existingLeaf,
					SecondLevelLeaf: leaf,
				},
			)
		} else {
			htlcOutputs := outgoingHtlcs[htlcIdx].Outputs
			auxLeaf := outgoingHtlcLeaves[htlcIdx].AuxLeaf

			// If this HTLC doesn't have any auxiliary leaves, it's
			// not an asset HTLC, so we can skip it.
			if len(htlcOutputs) == 0 {
				continue
			}

			leaf, err := CreateSecondLevelHtlcTx(
				chanState, com.CommitTx, htlc.Amt.ToSatoshis(),
				keys, c.cfg.ChainParams, htlcOutputs,
			)
			if err != nil {
				return none, fmt.Errorf("unable to create "+
					"second level HTLC leaf: %w", err)
			}

			existingLeaf := lfn.MapOption(
				func(l cmsg.TapLeafRecord) txscript.TapLeaf {
					return l.Leaf
				},
			)(auxLeaf.ValOpt())

			outgoingHtlcLeaves[htlcIdx] = cmsg.NewHtlcAuxLeaf(
				input.HtlcAuxLeaf{
					AuxTapLeaf:      existingLeaf,
					SecondLevelLeaf: leaf,
				},
			)
		}
	}

	return lfn.Some(commitment.Leaves()), nil
}

// FetchLeavesFromRevocation attempts to fetch the auxiliary leaves
// from a channel revocation that stores balance + blob information.
func (c *AuxLeafCreator) FetchLeavesFromRevocation(
	rev *channeldb.RevocationLog) (lfn.Option[lnwallet.CommitAuxLeaves],
	error) {

	none := lfn.None[lnwallet.CommitAuxLeaves]()

	// If the revocation has no custom blob, we don't need to do anything.
	if rev.CustomBlob.ValOpt().IsNone() {
		return none, nil
	}

	commitment, err := cmsg.DecodeCommitment(
		rev.CustomBlob.ValOpt().UnsafeFromSome(),
	)
	if err != nil {
		return none, fmt.Errorf("unable to decode commitment: %w", err)
	}

	return lfn.Some(commitment.Leaves()), nil
}

// ApplyHtlcView serves as the state transition function for the custom
// channel's blob. Given the old blob, and an HTLC view, then a new
// blob should be returned that reflects the pending updates.
func (c *AuxLeafCreator) ApplyHtlcView(chanState *channeldb.OpenChannel,
	prevBlob tlv.Blob, originalView *lnwallet.HtlcView, isOurCommit bool,
	ourBalance, theirBalance lnwire.MilliSatoshi,
	keys lnwallet.CommitmentKeyRing) (lfn.Option[tlv.Blob], error) {

	none := lfn.None[tlv.Blob]()

	// If the channel has no custom blob, we don't need to do anything.
	if chanState.CustomBlob.IsNone() {
		return none, nil
	}

	chanAssetState, err := cmsg.DecodeOpenChannel(
		chanState.CustomBlob.UnsafeFromSome(),
	)
	if err != nil {
		return none, fmt.Errorf("unable to decode channel asset "+
			"state: %w", err)
	}

	prevState, err := cmsg.DecodeCommitment(prevBlob)
	if err != nil {
		return none, fmt.Errorf("unable to decode prev commit state: "+
			"%w", err)
	}

	_, newCommitment, err := GenerateCommitmentAllocations(
		prevState, chanState, chanAssetState, isOurCommit, ourBalance,
		theirBalance, originalView, c.cfg.ChainParams, keys,
	)
	if err != nil {
		return none, fmt.Errorf("unable to generate allocations: %w",
			err)
	}

	var buf bytes.Buffer
	err = newCommitment.Encode(&buf)
	if err != nil {
		return none, fmt.Errorf("unable to encode commitment: %w", err)
	}

	return lfn.Some(buf.Bytes()), nil
}
