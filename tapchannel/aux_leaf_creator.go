package tapchannel

import (
	"bytes"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/fn"
	cmsg "github.com/lightninglabs/taproot-assets/tapchannelmsg"
	"github.com/lightninglabs/taproot-assets/tapfeatures"
	"github.com/lightningnetwork/lnd/channeldb"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lntypes"
	lnwl "github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/tlv"
)

const (
	// DefaultTimeout is the default timeout we use for RPC and database
	// operations.
	DefaultTimeout = 30 * time.Second
)

// FeatureBitFetcher is responsible for fetching feature bits by referencing a
// channel ID.
type FeatureBitFetcher interface {
	// GetChannelFeatures returns the negotiated features that are active
	// over the channel identifier by the provided channelID.
	GetChannelFeatures(cid lnwire.ChannelID) lnwire.FeatureVector
}

// FetchLeavesFromView attempts to fetch the auxiliary leaves that correspond to
// the passed aux blob, and pending fully evaluated HTLC view.
func FetchLeavesFromView(chainParams *address.ChainParams,
	in lnwl.CommitDiffAuxInput,
	bitFetcher FeatureBitFetcher) lfn.Result[lnwl.CommitDiffAuxResult] {

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

	features := bitFetcher.GetChannelFeatures(
		lnwire.NewChanIDFromOutPoint(
			in.ChannelState.FundingOutpoint,
		),
	)

	supportsSTXO := features.HasFeature(tapfeatures.STXOOptional)
	sigHashDefault := features.HasFeature(
		tapfeatures.SigHashDefaultHTLCsOptional,
	)

	allocations, newCommitment, err := GenerateCommitmentAllocations(
		prevState, in.ChannelState, chanAssetState, in.WhoseCommit,
		in.OurBalance, in.TheirBalance, in.UnfilteredView, chainParams,
		in.KeyRing, supportsSTXO, sigHashDefault,
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
	keys lnwl.CommitmentKeyRing,
	whoseCommit lntypes.ChannelParty) lfn.Result[lnwl.CommitDiffAuxResult] {

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

	supportSTXO := commitment.STXO.Val

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

			// If this is an incoming HTLC (to us), but on the
			// remote party's commitment transaction, then they'll
			// need to go to the second level to time it out.
			var cltvTimeout fn.Option[uint32]
			if whoseCommit == lntypes.Remote {
				cltvTimeout = fn.Some(htlc.RefundTimeout)
			}

			leaf, err := CreateSecondLevelHtlcTx(
				chanState, com.CommitTx, htlc.Amt.ToSatoshis(),
				keys, chainParams, htlcOutputs, cltvTimeout,
				htlc.HtlcIndex, supportSTXO,
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

			// If this is an outgoing commit on our local
			// commitment, then we'll need to go to the second level
			// to time out it out.
			var cltvTimeout fn.Option[uint32]
			if whoseCommit == lntypes.Local {
				cltvTimeout = fn.Some(htlc.RefundTimeout)
			}

			leaf, err := CreateSecondLevelHtlcTx(
				chanState, com.CommitTx, htlc.Amt.ToSatoshis(),
				keys, chainParams, htlcOutputs, cltvTimeout,
				htlc.HtlcIndex, supportSTXO,
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
// The additional parameters (chanState, keys, commitTx, chainParams)
// are needed to compute second-level HTLC auxiliary leaves at runtime,
// since these are not stored in the commitment blob.
func FetchLeavesFromRevocation(r *channeldb.RevocationLog,
	chanState lnwl.AuxChanState, keys lnwl.CommitmentKeyRing,
	commitTx *wire.MsgTx,
	chainParams *address.ChainParams) lfn.Result[lnwl.CommitDiffAuxResult] {

	type returnType = lnwl.CommitDiffAuxResult

	return lfn.MapOptionZ(
		r.CustomBlob.ValOpt(),
		func(blob tlv.Blob) lfn.Result[lnwl.CommitDiffAuxResult] {
			commitment, err := cmsg.DecodeCommitment(blob)
			if err != nil {
				return lfn.Err[returnType](fmt.Errorf("unable "+
					"to decode commitment: %w", err))
			}

			leaves := commitment.Leaves()

			// If we have the commit tx and chain params, we
			// can compute the second-level HTLC aux leaves
			// that aren't stored in the commitment blob.
			if commitTx != nil && chainParams != nil {
				err = populateSecondLevelLeaves(
					r, commitment, chanState, keys,
					commitTx, chainParams, &leaves,
				)
				if err != nil {
					return lfn.Err[returnType](
						fmt.Errorf("unable to "+
							"populate second "+
							"level leaves: %w",
							err),
					)
				}
			}

			return lfn.Ok(lnwl.CommitDiffAuxResult{
				AuxLeaves: lfn.Some(leaves),
			})
		},
	)
}

// populateSecondLevelLeaves computes the second-level HTLC aux leaves
// for each HTLC in the revocation log and populates them in the given
// leaves struct. This mirrors the logic in FetchLeavesFromCommit.
func populateSecondLevelLeaves(r *channeldb.RevocationLog,
	commitment *cmsg.Commitment, chanState lnwl.AuxChanState,
	keys lnwl.CommitmentKeyRing, commitTx *wire.MsgTx,
	chainParams *address.ChainParams,
	leaves *lnwl.CommitAuxLeaves) error {

	supportSTXO := commitment.STXO.Val

	incomingHtlcs := commitment.IncomingHtlcAssets.Val.HtlcOutputs
	incomingHtlcLeaves := commitment.AuxLeaves.Val.
		IncomingHtlcLeaves.Val.HtlcAuxLeaves
	outgoingHtlcs := commitment.OutgoingHtlcAssets.Val.HtlcOutputs
	outgoingHtlcLeaves := commitment.AuxLeaves.Val.
		OutgoingHtlcLeaves.Val.HtlcAuxLeaves

	for _, htlcEntry := range r.HTLCEntries {
		// Skip HTLCs without an index.
		htlcIdxOpt := htlcEntry.HtlcIndex.ValOpt()
		if htlcIdxOpt.IsNone() {
			continue
		}

		htlcIdx := htlcIdxOpt.UnsafeFromSome().Int()
		htlcAmt := htlcEntry.Amt.Val.Int()

		if htlcEntry.Incoming.Val {
			htlcOutputs := incomingHtlcs[htlcIdx].Outputs
			auxLeaf := incomingHtlcLeaves[htlcIdx].AuxLeaf

			if len(htlcOutputs) == 0 {
				continue
			}

			// For incoming HTLCs on the remote party's
			// commitment, they'll need to go to the second
			// level to time it out.
			cltvTimeout := fn.Some(
				htlcEntry.RefundTimeout.Val,
			)

			leaf, err := CreateSecondLevelHtlcTx(
				chanState, commitTx, htlcAmt,
				keys, chainParams, htlcOutputs,
				cltvTimeout, htlcIdx, supportSTXO,
			)
			if err != nil {
				return fmt.Errorf("unable to create "+
					"second level incoming HTLC "+
					"leaf: %w", err)
			}

			existingLeaf := lfn.MapOption(
				func(l cmsg.TapLeafRecord) txscript.TapLeaf {
					return l.Leaf
				},
			)(auxLeaf.ValOpt())

			leaves.IncomingHtlcLeaves[htlcIdx] = input.HtlcAuxLeaf{
				AuxTapLeaf:      existingLeaf,
				SecondLevelLeaf: leaf,
			}
		} else {
			htlcOutputs := outgoingHtlcs[htlcIdx].Outputs
			auxLeaf := outgoingHtlcLeaves[htlcIdx].AuxLeaf

			if len(htlcOutputs) == 0 {
				continue
			}

			// For outgoing HTLCs on the remote party's
			// commitment, they don't need a CLTV timeout
			// (they go to second level via the success path).
			leaf, err := CreateSecondLevelHtlcTx(
				chanState, commitTx, htlcAmt,
				keys, chainParams, htlcOutputs,
				fn.None[uint32](), htlcIdx,
				supportSTXO,
			)
			if err != nil {
				return fmt.Errorf("unable to create "+
					"second level outgoing HTLC "+
					"leaf: %w", err)
			}

			existingLeaf := lfn.MapOption(
				func(l cmsg.TapLeafRecord) txscript.TapLeaf {
					return l.Leaf
				},
			)(auxLeaf.ValOpt())

			leaves.OutgoingHtlcLeaves[htlcIdx] = input.HtlcAuxLeaf{
				AuxTapLeaf:      existingLeaf,
				SecondLevelLeaf: leaf,
			}
		}
	}

	return nil
}

// ApplyHtlcView serves as the state transition function for the custom
// channel's blob. Given the old blob, and an HTLC view, then a new
// blob should be returned that reflects the pending updates.
func ApplyHtlcView(chainParams *address.ChainParams,
	in lnwl.CommitDiffAuxInput,
	bitFetcher FeatureBitFetcher) lfn.Result[lfn.Option[tlv.Blob]] {

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

	features := bitFetcher.GetChannelFeatures(
		lnwire.NewChanIDFromOutPoint(
			in.ChannelState.FundingOutpoint,
		),
	)

	supportSTXO := features.HasFeature(
		tapfeatures.STXOOptional,
	)
	sigHashDefault := features.HasFeature(
		tapfeatures.SigHashDefaultHTLCsOptional,
	)

	_, newCommitment, err := GenerateCommitmentAllocations(
		prevState, in.ChannelState, chanAssetState, in.WhoseCommit,
		in.OurBalance, in.TheirBalance, in.UnfilteredView, chainParams,
		in.KeyRing, supportSTXO, sigHashDefault,
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
