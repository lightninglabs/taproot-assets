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
	lnwl "github.com/lightningnetwork/lnd/lnwallet"
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
	in lnwl.CommitDiffAuxInput) lfn.Result[lnwl.CommitDiffAuxResult] {

	type returnType = lnwl.CommitDiffAuxResult

	// If the channel has no custom blob, we don't need to do anything.
	if in.ChannelState.CustomBlob.IsNone() {
		return lfn.Ok(lnwl.CommitDiffAuxResult{})
	}

	chanAssetState, err := cmsg.DecodeOpenChannel(
		in.ChannelState.CustomBlob.UnsafeFromSome(),
	)
	if err != nil {
		return lfn.Err[returnType](fmt.Errorf("unable to decode "+
			"channel asset state: %w", err))
	}

	prevState, err := cmsg.DecodeCommitment(in.PrevBlob)
	if err != nil {
		return lfn.Err[returnType](fmt.Errorf("unable to decode prev "+
			"commit state: %w", err))
	}

	allocations, newCommitment, err := GenerateCommitmentAllocations(
		prevState, in.ChannelState, chanAssetState, in.WhoseCommit,
		in.OurBalance, in.TheirBalance, in.UnfilteredView, chainParams,
		in.KeyRing,
	)
	if err != nil {
		return lfn.Err[returnType](fmt.Errorf("unable to generate "+
			"allocations: %w", err))
	}

	customCommitSort := func(tx *wire.MsgTx, cltvs []uint32,
		htlcIndexes []input.HtlcIndex) error {

		return InPlaceCustomCommitSort(
			tx, cltvs, htlcIndexes, allocations,
		)
	}

	return lfn.Ok(lnwl.CommitDiffAuxResult{
		AuxLeaves: lfn.Some(newCommitment.Leaves()),
		CommitSortFunc: lfn.Some[lnwl.CommitSortFunc](
			customCommitSort,
		),
	})
}

// FetchLeavesFromCommit attempts to fetch the auxiliary leaves that correspond
// to the passed aux blob, and an existing channel commitment.
func FetchLeavesFromCommit(chainParams *address.ChainParams,
	chanState lnwl.AuxChanState, com channeldb.ChannelCommitment,
	keys lnwl.CommitmentKeyRing) lfn.Result[lnwl.CommitDiffAuxResult] {

	type returnType = lnwl.CommitDiffAuxResult

	// If the commitment has no custom blob, we don't need to do anything.
	if com.CustomBlob.IsNone() {
		return lfn.Ok(lnwl.CommitDiffAuxResult{})
	}

	commitment, err := cmsg.DecodeCommitment(
		com.CustomBlob.UnsafeFromSome(),
	)
	if err != nil {
		return lfn.Err[returnType](fmt.Errorf("unable to decode "+
			"commitment: %w", err))
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
				return lfn.Err[returnType](fmt.Errorf("unable "+
					"to create second level HTLC leaf: %w",
					err))
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
				return lfn.Err[returnType](fmt.Errorf("unable "+
					"to create second level HTLC leaf: %w",
					err))
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

	return lfn.Ok(lnwl.CommitDiffAuxResult{
		AuxLeaves: lfn.Some(commitment.Leaves()),
	})
}

// FetchLeavesFromRevocation attempts to fetch the auxiliary leaves
// from a channel revocation that stores balance + blob information.
func FetchLeavesFromRevocation(
	r *channeldb.RevocationLog) lfn.Result[lnwl.CommitDiffAuxResult] {

	type returnType = lnwl.CommitDiffAuxResult

	return lfn.MapOptionZ(
		r.CustomBlob.ValOpt(),
		func(blob tlv.Blob) lfn.Result[lnwl.CommitDiffAuxResult] {
			commitment, err := cmsg.DecodeCommitment(blob)
			if err != nil {
				return lfn.Err[returnType](fmt.Errorf("unable "+
					"to decode commitment: %w", err))
			}

			return lfn.Ok(lnwl.CommitDiffAuxResult{
				AuxLeaves: lfn.Some(commitment.Leaves()),
			})
		},
	)
}

// ApplyHtlcView serves as the state transition function for the custom
// channel's blob. Given the old blob, and an HTLC view, then a new
// blob should be returned that reflects the pending updates.
func ApplyHtlcView(chainParams *address.ChainParams,
	in lnwl.CommitDiffAuxInput) lfn.Result[lfn.Option[tlv.Blob]] {

	type returnType = lfn.Option[tlv.Blob]

	// If the channel has no custom blob, we don't need to do anything.
	if in.ChannelState.CustomBlob.IsNone() {
		return lfn.Ok(lfn.None[tlv.Blob]())
	}

	chanAssetState, err := cmsg.DecodeOpenChannel(
		in.ChannelState.CustomBlob.UnsafeFromSome(),
	)
	if err != nil {
		return lfn.Err[returnType](fmt.Errorf("unable to decode "+
			"channel asset state: %w", err))
	}

	prevState, err := cmsg.DecodeCommitment(in.PrevBlob)
	if err != nil {
		return lfn.Err[returnType](fmt.Errorf("unable to decode prev "+
			"commit state: %w", err))
	}

	_, newCommitment, err := GenerateCommitmentAllocations(
		prevState, in.ChannelState, chanAssetState, in.WhoseCommit,
		in.OurBalance, in.TheirBalance, in.UnfilteredView, chainParams,
		in.KeyRing,
	)
	if err != nil {
		return lfn.Err[returnType](fmt.Errorf("unable to generate "+
			"allocations: %w", err))
	}

	var buf bytes.Buffer
	err = newCommitment.Encode(&buf)
	if err != nil {
		return lfn.Err[returnType](fmt.Errorf("unable to encode "+
			"commitment: %w", err))
	}

	return lfn.Ok(lfn.Some(buf.Bytes()))
}
