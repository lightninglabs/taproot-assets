package tapchannel

import (
	"bytes"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/address"
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

// FetchLeavesFromView attempts to fetch the auxiliary leaves that correspond to
// the passed aux blob, and pending fully evaluated HTLC view.
func FetchLeavesFromView(chainParams *address.ChainParams,
	chanState *channeldb.OpenChannel, prevBlob tlv.Blob,
	originalView *lnwallet.HtlcView, isOurCommit bool, ourBalance,
	theirBalance lnwire.MilliSatoshi,
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
		theirBalance, originalView, chainParams, keys,
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
func FetchLeavesFromCommit(chainParams *address.ChainParams,
	chanState *channeldb.OpenChannel, com channeldb.ChannelCommitment,
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
				keys, chainParams, htlcOutputs,
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
				keys, chainParams, htlcOutputs,
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
func FetchLeavesFromRevocation(
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
func ApplyHtlcView(chainParams *address.ChainParams,
	chanState *channeldb.OpenChannel, prevBlob tlv.Blob,
	originalView *lnwallet.HtlcView, isOurCommit bool,
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
		theirBalance, originalView, chainParams, keys,
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
