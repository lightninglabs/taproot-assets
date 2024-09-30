package tapchannel

import (
	"bytes"
	"context"
	"fmt"
	"sort"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	cmsg "github.com/lightninglabs/taproot-assets/tapchannelmsg"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/lightningnetwork/lnd/channeldb"
	lfn "github.com/lightningnetwork/lnd/fn"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/lightningnetwork/lnd/lnwire"
)

// DecodedDescriptor is a wrapper around a PaymentDescriptor that also includes
// the decoded asset balances of the HTLC to avoid multiple decoding round
// trips.
type DecodedDescriptor struct {
	// AuxHtlcDescriptor is the original payment descriptor.
	lnwallet.AuxHtlcDescriptor

	// AssetBalances is the decoded asset balances of the HTLC.
	AssetBalances []*rfqmsg.AssetBalance
}

// DecodedView is a copy of the original HTLC view, but with the asset balances
// of the HTLCs decoded.
type DecodedView struct {
	// OurUpdates is a list of decoded descriptors for our updates.
	OurUpdates []*DecodedDescriptor

	// TheirUpdates is a list of decoded descriptors for their updates.
	TheirUpdates []*DecodedDescriptor

	// FeePerKw is the current commitment fee rate.
	FeePerKw chainfee.SatPerKWeight
}

// ComputeView processes all update entries in both HTLC update logs,
// producing a final view which is the result of properly applying all adds,
// settles, timeouts and fee updates found in both logs. The resulting view
// returned reflects the current state of HTLCs within the remote or local
// commitment chain, and the current commitment fee rate.
func ComputeView(ourBalance, theirBalance uint64,
	whoseCommit lntypes.ChannelParty, original *lnwallet.HtlcView) (uint64,
	uint64, *DecodedView, *DecodedView, error) {

	log.Tracef("Computing view, whoseCommit=%v, ourAssetBalance=%d, "+
		"theirAssetBalance=%d, ourUpdates=%d, theirUpdates=%d",
		whoseCommit, ourBalance, theirBalance, len(original.OurUpdates),
		len(original.TheirUpdates))

	newView := &DecodedView{
		FeePerKw: original.FeePerKw,
	}
	nonAssetView := &DecodedView{
		FeePerKw: original.FeePerKw,
	}

	// By the time we're computing a view, the HTLCs have already been
	// processed, so they'll have a add/remove height set. Instead of
	// checking zero as the lnd algo does, we'll instead look *next*
	// height.
	nextHeight := original.NextHeight

	// We use two maps, one for the local log and one for the remote log to
	// keep track of which entries we need to skip when creating the final
	// htlc view. We skip an entry whenever we find a settle or a timeout
	// modifying an entry.
	skipUs := make(map[uint64]struct{})
	skipThem := make(map[uint64]struct{})

	// Only the add HTLCs have the custom blobs, so we'll make an index of
	// them so we can look them up to decide how to handle the
	// settle/remove entries.
	localHtlcIndex := make(map[uint64]lnwallet.AuxHtlcDescriptor)
	remoteHtlcIndex := make(map[uint64]lnwallet.AuxHtlcDescriptor)

	for _, entry := range original.AuxOurUpdates() {
		if entry.EntryType == lnwallet.Add {
			localHtlcIndex[entry.HtlcIndex] = entry
		}
	}
	for _, entry := range original.AuxTheirUpdates() {
		if entry.EntryType == lnwallet.Add {
			remoteHtlcIndex[entry.HtlcIndex] = entry
		}
	}

	local, remote := ourBalance, theirBalance
	for _, entry := range original.AuxOurUpdates() {
		switch entry.EntryType {
		// Skip adds for now, they will be processed below.
		case lnwallet.Add:
			continue

		// Fee updates don't concern us at the asset level.
		case lnwallet.FeeUpdate:
			continue

		// A settle or a timeout means we need to skip the corresponding
		// "add" entry.
		case lnwallet.Settle, lnwallet.Fail, lnwallet.MalformedFail:
			skipThem[entry.ParentIndex] = struct{}{}

			parentEntry, ok := remoteHtlcIndex[entry.ParentIndex]
			if !ok {
				return 0, 0, nil, nil, fmt.Errorf("unable to "+
					"find remote htlc with index %d",
					entry.ParentIndex)
			}

			if len(parentEntry.CustomRecords) > 0 {
				assetHtlc, err := rfqmsg.HtlcFromCustomRecords(
					parentEntry.CustomRecords,
				)
				if err != nil {
					return 0, 0, nil, nil,
						fmt.Errorf("unable to decode "+
							"asset htlc: %w", err)
				}

				decodedEntry := &DecodedDescriptor{
					AuxHtlcDescriptor: entry,
					AssetBalances:     assetHtlc.Balances(),
				}

				local, remote = processRemoveEntry(
					decodedEntry, local, remote,
					whoseCommit, true, nextHeight,
				)
			}
		}
	}
	for _, entry := range original.AuxTheirUpdates() {
		switch entry.EntryType {
		// Skip adds for now, they will be processed below.
		case lnwallet.Add:
			continue

		// Fee updates don't concern us at the asset level.
		case lnwallet.FeeUpdate:
			continue

		// A settle or a timeout means we need to skip the corresponding
		// "add" entry.
		case lnwallet.Settle, lnwallet.Fail, lnwallet.MalformedFail:
			skipUs[entry.ParentIndex] = struct{}{}

			parentEntry, ok := localHtlcIndex[entry.ParentIndex]
			if !ok {
				return 0, 0, nil, nil, fmt.Errorf("unable to "+
					"find local htlc with index %d",
					entry.ParentIndex)
			}

			if len(parentEntry.CustomRecords) > 0 {
				assetHtlc, err := rfqmsg.HtlcFromCustomRecords(
					parentEntry.CustomRecords,
				)
				if err != nil {
					return 0, 0, nil, nil,
						fmt.Errorf("unable to decode "+
							"asset htlc: %w", err)
				}

				decodedEntry := &DecodedDescriptor{
					AuxHtlcDescriptor: entry,
					AssetBalances:     assetHtlc.Balances(),
				}
				local, remote = processRemoveEntry(
					decodedEntry, local, remote,
					whoseCommit, false, nextHeight,
				)
			}
		}
	}

	// Next we take a second pass through all the log entries, skipping any
	// settled HTLCs, and debiting the chain state balance due to any newly
	// added HTLCs.
	for _, entry := range original.AuxOurUpdates() {
		isAdd := entry.EntryType == lnwallet.Add

		// Skip any entries that aren't adds or adds that were already
		// settled or failed by a child HTLC entry we processed above.
		if _, ok := skipUs[entry.HtlcIndex]; !isAdd || ok {
			continue
		}

		// Again skip any entries that aren't TAP related, at least
		// when it comes to balance calculations. We still need to keep
		// track of them, so we can create non-asset allocations
		// correctly.
		if len(entry.CustomRecords) == 0 {
			nonAssetView.OurUpdates = append(
				nonAssetView.OurUpdates, &DecodedDescriptor{
					AuxHtlcDescriptor: entry,
				},
			)

			continue
		}

		assetHtlc, err := rfqmsg.HtlcFromCustomRecords(
			entry.CustomRecords,
		)
		if err != nil {
			return 0, 0, nil, nil, fmt.Errorf("unable to decode "+
				"asset htlc: %w", err)
		}

		decodedEntry := &DecodedDescriptor{
			AuxHtlcDescriptor: entry,
			AssetBalances:     assetHtlc.Balances(),
		}
		local, remote = processAddEntry(
			decodedEntry, local, remote, whoseCommit, false,
			nextHeight,
		)

		newView.OurUpdates = append(newView.OurUpdates, decodedEntry)
	}
	for _, entry := range original.AuxTheirUpdates() {
		isAdd := entry.EntryType == lnwallet.Add

		// Skip any entries that aren't adds or adds that were already
		// settled or failed by a child HTLC entry we processed above.
		if _, ok := skipThem[entry.HtlcIndex]; !isAdd || ok {
			continue
		}

		// Again skip any entries that aren't TAP related, at least
		// when it comes to balance calculations. We still need to keep
		// track of them, so we can create non-asset allocations
		// correctly.
		if len(entry.CustomRecords) == 0 {
			nonAssetView.TheirUpdates = append(
				nonAssetView.TheirUpdates, &DecodedDescriptor{
					AuxHtlcDescriptor: entry,
				},
			)

			continue
		}

		assetHtlc, err := rfqmsg.HtlcFromCustomRecords(
			entry.CustomRecords,
		)
		if err != nil {
			return 0, 0, nil, nil, fmt.Errorf("unable to decode "+
				"asset htlc: %w", err)
		}

		decodedEntry := &DecodedDescriptor{
			AuxHtlcDescriptor: entry,
			AssetBalances:     assetHtlc.Balances(),
		}
		local, remote = processAddEntry(
			decodedEntry, local, remote, whoseCommit, true,
			nextHeight,
		)

		newView.TheirUpdates = append(
			newView.TheirUpdates, decodedEntry,
		)
	}

	return local, remote, newView, nonAssetView, nil
}

// processRemoveEntry processes the removal of an HTLC from the commitment
// transaction. It returns the updated balances for both parties.
func processRemoveEntry(htlc *DecodedDescriptor, ourBalance,
	theirBalance uint64, whoseCommit lntypes.ChannelParty, isIncoming bool,
	nextHeight uint64) (uint64, uint64) {

	// Ignore any removal entries which have already been processed.
	removeHeight := htlc.RemoveHeight(whoseCommit)
	if removeHeight != nextHeight {
		return ourBalance, theirBalance
	}

	var (
		amount = rfqmsg.Sum(htlc.AssetBalances)
		isFail = htlc.EntryType == lnwallet.Fail ||
			htlc.EntryType == lnwallet.MalformedFail
	)
	switch {
	// If an incoming HTLC is being settled, then this means that we've
	// received the preimage either from another subsystem, or the upstream
	// peer in the route. Therefore, we increase our balance by the HTLC
	// amount.
	case isIncoming && htlc.EntryType == lnwallet.Settle:
		ourBalance += amount

	// Otherwise, this HTLC is being failed out, therefore the value of the
	// HTLC should return to the remote party.
	case isIncoming && isFail:
		theirBalance += amount

	// If an outgoing HTLC is being settled, then this means that the
	// downstream party resented the preimage or learned of it via a
	// downstream peer. In either case, we credit their settled value with
	// the value of the HTLC.
	case !isIncoming && htlc.EntryType == lnwallet.Settle:
		theirBalance += amount

	// Otherwise, one of our outgoing HTLCs has timed out, so the value of
	// the HTLC should be returned to our settled balance.
	case !isIncoming && isFail:
		ourBalance += amount
	}

	return ourBalance, theirBalance
}

// processAddEntry processes the addition of an HTLC to the commitment
// transaction. It returns the updated balances for both parties.
func processAddEntry(htlc *DecodedDescriptor, ourBalance, theirBalance uint64,
	whoseCommit lntypes.ChannelParty, isIncoming bool,
	nextHeight uint64) (uint64, uint64) {

	// Ignore any add entries which have already been processed.
	addHeight := htlc.AddHeight(whoseCommit)
	if addHeight != nextHeight {
		return ourBalance, theirBalance
	}

	var amount = rfqmsg.Sum(htlc.AssetBalances)
	if isIncoming {
		// If this is a new incoming (un-committed) HTLC, then we need
		// to update their balance accordingly by subtracting the
		// amount of the HTLC that are funds pending.
		theirBalance -= amount
	} else {
		// Similarly, we need to debit our balance if this is an
		// outgoing HTLC to reflect the pending balance.
		ourBalance -= amount
	}

	return ourBalance, theirBalance
}

// SanityCheckAmounts makes sure that any output that carries an asset has a
// non-dust satoshi balance. It also checks and returns whether we need a local
// and/or remote anchor output.
func SanityCheckAmounts(ourBalance, theirBalance btcutil.Amount,
	ourAssetBalance, theirAssetBalance uint64, view *DecodedView,
	chanType channeldb.ChannelType, whoseCommit lntypes.ChannelParty,
	dustLimit btcutil.Amount) (bool, bool, error) {

	log.Tracef("Sanity checking amounts, whoseCommit=%v, ourBalance=%d, "+
		"theirBalance=%d, ourAssetBalance=%d, theirAssetBalance=%d",
		whoseCommit, ourBalance, theirBalance, ourAssetBalance,
		theirAssetBalance)

	var (
		numHTLCs int64
		feePerKw = view.FeePerKw
	)
	for _, entry := range view.OurUpdates {
		isDust := lnwallet.HtlcIsDust(
			chanType, false, whoseCommit, feePerKw,
			entry.Amount.ToSatoshis(), dustLimit,
		)
		if rfqmsg.Sum(entry.AssetBalances) > 0 && isDust {
			return false, false, fmt.Errorf("outgoing HTLC asset "+
				"balance %d has dust BTC balance (%v) on HTLC "+
				"with index %d (dust limit %v)",
				rfqmsg.Sum(entry.AssetBalances), entry.Amount,
				entry.HtlcIndex, dustLimit)
		}

		numHTLCs++
	}
	for _, entry := range view.TheirUpdates {
		isDust := lnwallet.HtlcIsDust(
			chanType, true, whoseCommit, feePerKw,
			entry.Amount.ToSatoshis(), dustLimit,
		)
		if rfqmsg.Sum(entry.AssetBalances) > 0 && isDust {
			return false, false, fmt.Errorf("incoming HTLC asset "+
				"balance %d has dust BTC balance (%v) on HTLC "+
				"with index %d (dust limit %v)",
				rfqmsg.Sum(entry.AssetBalances), entry.Amount,
				entry.HtlcIndex, dustLimit)
		}

		numHTLCs++
	}

	// Any output that carries an asset balance must have a corresponding
	// non-dust satoshi balance.
	if ourAssetBalance > 0 && ourBalance < dustLimit {
		return false, false, fmt.Errorf("our asset balance %d has "+
			"dust BTC balance (%v)", ourAssetBalance, ourBalance)
	}
	if theirAssetBalance > 0 && theirBalance < dustLimit {
		return false, false, fmt.Errorf("their asset balance %d has "+
			"dust BTC balance (%v)", theirAssetBalance,
			theirBalance)
	}

	// If for some reason the channel type doesn't have anchors, we fail
	// here, as this is a requirement for TAP channels.
	if !chanType.HasAnchors() {
		return false, false, fmt.Errorf("channel type %v doesn't have "+
			"anchors", chanType)
	}

	// Due to push amounts on channel open or pure BTC payments, we can have
	// a BTC balance even if the asset balance is zero.
	ourBtcNonDust := ourBalance >= dustLimit
	theirBtcNonDust := theirBalance >= dustLimit

	// So we want an anchor if we either have assets or non-dust BTC or
	// any in-flight HTLCs.
	wantLocalAnchor := ourAssetBalance > 0 || ourBtcNonDust || numHTLCs > 0
	wantRemoteAnchor := theirAssetBalance > 0 || theirBtcNonDust ||
		numHTLCs > 0

	return wantLocalAnchor, wantRemoteAnchor, nil
}

// GenerateCommitmentAllocations generates allocations for a channel commitment.
func GenerateCommitmentAllocations(prevState *cmsg.Commitment,
	chanState lnwallet.AuxChanState, chanAssetState *cmsg.OpenChannel,
	whoseCommit lntypes.ChannelParty, ourBalance,
	theirBalance lnwire.MilliSatoshi, originalView *lnwallet.HtlcView,
	chainParams *address.ChainParams,
	keys lnwallet.CommitmentKeyRing) ([]*Allocation, *cmsg.Commitment,
	error) {

	log.Tracef("Generating allocations, whoseCommit=%v, ourBalance=%d, "+
		"theirBalance=%d", whoseCommit, ourBalance, theirBalance)

	// Everywhere we have a isOurCommit boolean we define the local/remote
	// balances as seen from the perspective of the local node. So if this
	// is not our commit, then the previous state we take the balance from
	// is flipped from the point of view of the rest of the code. So we
	// need to flip the balances here in order for the rest of the code to
	// work correctly.
	localAssetStartBalance := prevState.LocalAssets.Val.Sum()
	remoteAssetStartBalance := prevState.RemoteAssets.Val.Sum()
	if whoseCommit.IsRemote() {
		localAssetStartBalance, remoteAssetStartBalance =
			remoteAssetStartBalance, localAssetStartBalance
	}

	// Process all HTLCs in the view to compute the new asset balance.
	//nolint:lll
	ourAssetBalance, theirAssetBalance, filteredView, nonAssetView, err := ComputeView(
		localAssetStartBalance, remoteAssetStartBalance,
		whoseCommit, originalView,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to compute view: %w", err)
	}

	dustLimit := chanState.LocalChanCfg.DustLimit
	if whoseCommit.IsRemote() {
		dustLimit = chanState.RemoteChanCfg.DustLimit
	}

	log.Tracef("Computed view, whoseCommit=%v, ourAssetBalance=%d, "+
		"theirAssetBalance=%d, dustLimit=%v", whoseCommit,
		ourAssetBalance, theirAssetBalance, dustLimit)

	// Make sure that every output that carries an asset balance has a
	// corresponding non-dust BTC output.
	wantLocalAnchor, wantRemoteAnchor, err := SanityCheckAmounts(
		ourBalance.ToSatoshis(), theirBalance.ToSatoshis(),
		ourAssetBalance, theirAssetBalance, filteredView,
		chanState.ChanType, whoseCommit, dustLimit,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("error checking amounts: %w", err)
	}

	// With all the balances checked, we can now create allocation entries
	// for each on-chain output. An allocation is a helper struct to keep
	// track of the original on-chain output, the keys/scripts involved on
	// the BTC level as well as the asset UTXOs that are being distributed.
	allocations, err := CreateAllocations(
		chanState, ourBalance.ToSatoshis(), theirBalance.ToSatoshis(),
		ourAssetBalance, theirAssetBalance, wantLocalAnchor,
		wantRemoteAnchor, filteredView, whoseCommit, keys, nonAssetView,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create allocations: %w",
			err)
	}

	log.Tracef("Created allocations, whoseCommit=%v, allocations=%v",
		whoseCommit, limitSpewer.Sdump(allocations))

	inputProofs := fn.Map(
		chanAssetState.Assets(),
		func(o *cmsg.AssetOutput) *proof.Proof {
			return &o.Proof.Val
		},
	)

	// Now we can distribute the inputs according to the allocations. This
	// creates a virtual packet for each distinct asset ID that is committed
	// to the channel.
	vPackets, err := DistributeCoins(inputProofs, allocations, chainParams)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to distribute coins: %w",
			err)
	}

	// Prepare the output assets for each virtual packet, then create the
	// output commitments.
	ctx := context.Background()
	for idx := range vPackets {
		err := tapsend.PrepareOutputAssets(ctx, vPackets[idx])
		if err != nil {
			return nil, nil, fmt.Errorf("unable to prepare output "+
				"assets: %w", err)
		}
	}

	outCommitments, err := tapsend.CreateOutputCommitments(vPackets)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create output "+
			"commitments: %w", err)
	}

	// The output commitment is all we need to create the auxiliary leaves.
	// We map the output commitments (which are keyed by on-chain output
	// index) back to the allocation.
	err = AssignOutputCommitments(allocations, outCommitments)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to assign alloc output "+
			"commitments: %w", err)
	}

	// We don't actually have the real commitment transaction yet, so for
	// now we'll make a dummy version. Once we go to force close, we'll
	// know the real commitment transaction, and can update the proofs
	// below.
	fakeCommitTx, err := FakeCommitTx(
		chanState.FundingOutpoint, allocations,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create fake commit tx: "+
			"%w", err)
	}

	// Now we have all the information we need to create the asset proofs.
	for idx := range vPackets {
		vPkt := vPackets[idx]
		for outIdx := range vPkt.Outputs {
			proofSuffix, err := tapsend.CreateProofSuffixCustom(
				fakeCommitTx, vPkt, outCommitments, outIdx,
				vPackets, NonAssetExclusionProofs(allocations),
			)
			if err != nil {
				return nil, nil, fmt.Errorf("unable to create "+
					"proof suffix for output %d: %w",
					outIdx, err)
			}

			vPkt.Outputs[outIdx].ProofSuffix = proofSuffix
		}
	}

	// Next, we can convert the allocations to auxiliary leaves and from
	// those construct our Commitment struct that will in the end also hold
	// our proof suffixes.
	newCommitment, err := ToCommitment(allocations, vPackets)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to convert to commitment: "+
			"%w", err)
	}

	return allocations, newCommitment, nil
}

// CreateAllocations creates the allocations for the channel state.
func CreateAllocations(chanState lnwallet.AuxChanState, ourBalance,
	theirBalance btcutil.Amount, ourAssetBalance, theirAssetBalance uint64,
	wantLocalCommitAnchor, wantRemoteCommitAnchor bool,
	filteredView *DecodedView, whoseCommit lntypes.ChannelParty,
	keys lnwallet.CommitmentKeyRing,
	nonAssetView *DecodedView) ([]*Allocation, error) {

	log.Tracef("Creating allocations, whoseCommit=%v, initiator=%v, "+
		"ourBalance=%d, theirBalance=%d, ourAssetBalance=%d, "+
		"theirAssetBalance=%d, wantLocalCommitAnchor=%v, "+
		"wantRemoteCommitAnchor=%v, ourUpdates=%d, theirUpdates=%d, "+
		"nonAssetOurUpdates=%d, nonAssetTheirUpdates=%d", whoseCommit,
		chanState.IsInitiator, ourBalance, theirBalance,
		ourAssetBalance, theirAssetBalance, wantLocalCommitAnchor,
		wantRemoteCommitAnchor,
		len(filteredView.OurUpdates), len(filteredView.TheirUpdates),
		len(nonAssetView.OurUpdates), len(nonAssetView.TheirUpdates))

	// We'll have at most 2 outputs for the local and remote commitment
	// anchor outputs, 2 outputs for the local/remote balance and one output
	// for each HTLC. We might over-allocate slightly, but that's likely
	// slightly better than re-allocating in this case.
	var (
		numAllocations = len(filteredView.OurUpdates) +
			len(filteredView.TheirUpdates) +
			len(nonAssetView.OurUpdates) +
			len(nonAssetView.TheirUpdates) + 4
		allocations = make([]*Allocation, 0, numAllocations)
		addAlloc    = func(a *Allocation) {
			allocations = append(allocations, a)
		}
	)

	var leaseExpiry uint32
	if chanState.ChanType.HasLeaseExpiration() {
		leaseExpiry = chanState.ThawHeight
	}

	dustLimit := chanState.LocalChanCfg.DustLimit
	if whoseCommit.IsRemote() {
		dustLimit = chanState.RemoteChanCfg.DustLimit
	}

	// The "local" and "remote" notations are always from the perspective of
	// the local node. So if we want to find out the asset balance of the
	// _initiator_ of the channel, we just need to take into account the
	// chanstate.IsInitiator flags.
	initiatorAssetBalance := ourAssetBalance
	if !chanState.IsInitiator {
		initiatorAssetBalance = theirAssetBalance
	}

	var err error
	if whoseCommit.IsLocal() {
		err = addCommitmentOutputs(
			chanState.ChanType, &chanState.LocalChanCfg,
			&chanState.RemoteChanCfg, chanState.IsInitiator,
			ourBalance, theirBalance, ourAssetBalance,
			theirAssetBalance, wantLocalCommitAnchor,
			wantRemoteCommitAnchor, keys, leaseExpiry, addAlloc,
		)
	} else {
		err = addCommitmentOutputs(
			chanState.ChanType, &chanState.RemoteChanCfg,
			&chanState.LocalChanCfg, !chanState.IsInitiator,
			theirBalance, ourBalance, theirAssetBalance,
			ourAssetBalance, wantRemoteCommitAnchor,
			wantLocalCommitAnchor, keys, leaseExpiry, addAlloc,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("error creating commitment output "+
			"allocations: %w", err)
	}

	log.Tracef("Channel initiator's asset balance is %d",
		initiatorAssetBalance)

	// Next, we add the HTLC outputs, using this helper function to
	// distinguish between incoming and outgoing HTLCs. The haveHtlcSplit
	// boolean is used to store if one of the HTLCs has already been chosen
	// to be the split root (only the very first HTLC might be chosen).
	var haveHtlcSplitRoot bool
	addHtlc := func(htlc *DecodedDescriptor, isIncoming bool) error {
		htlcScript, err := lnwallet.GenTaprootHtlcScript(
			isIncoming, whoseCommit, htlc.Timeout, htlc.RHash,
			&keys, lfn.None[txscript.TapLeaf](),
		)
		if err != nil {
			return fmt.Errorf("error creating HTLC script: %w", err)
		}

		sibling, htlcTree, err := LeavesFromTapscriptScriptTree(
			htlcScript,
		)
		if err != nil {
			return fmt.Errorf("error creating HTLC script "+
				"sibling: %w", err)
		}

		// We should always just have a single split root, which
		// normally is the initiator's balance. However, if the
		// initiator has no balance, then we choose the very first HTLC
		// in the list to be the split root. If there are no HTLCs, then
		// all the balance is on the receiver side and we don't need a
		// split root.
		shouldHouseSplitRoot := initiatorAssetBalance == 0 &&
			!haveHtlcSplitRoot

		// Make sure we only select the very first HTLC that pays to the
		// initiator.
		if shouldHouseSplitRoot {
			haveHtlcSplitRoot = true
		}

		allocType := CommitAllocationHtlcOutgoing
		if isIncoming {
			allocType = CommitAllocationHtlcIncoming
		}

		// If HTLC is dust, do not create allocation for it.
		isDust := lnwallet.HtlcIsDust(
			chanState.ChanType, isIncoming, whoseCommit,
			filteredView.FeePerKw, htlc.Amount.ToSatoshis(),
			dustLimit,
		)
		if isDust {
			// We need to error out, as a dust HTLC carrying assets
			// should not be expected.
			return fmt.Errorf("error creating asset HTLC " +
				"allocation, HTLC is dust")
		}

		allocations = append(allocations, &Allocation{
			Type:           allocType,
			Amount:         rfqmsg.Sum(htlc.AssetBalances),
			AssetVersion:   asset.V1,
			SplitRoot:      shouldHouseSplitRoot,
			BtcAmount:      htlc.Amount.ToSatoshis(),
			InternalKey:    htlcTree.InternalKey,
			NonAssetLeaves: sibling,
			ScriptKey: asset.ScriptKey{
				PubKey: asset.NewScriptKey(
					htlcTree.TaprootKey,
				).PubKey,
				TweakedScriptKey: &asset.TweakedScriptKey{
					RawKey: keychain.KeyDescriptor{
						PubKey: htlcTree.InternalKey,
					},
					Tweak: htlcTree.TapscriptRoot,
				},
			},
			SortTaprootKeyBytes: schnorr.SerializePubKey(
				htlcTree.TaprootKey,
			),
			CLTV:      htlc.Timeout,
			HtlcIndex: htlc.HtlcIndex,
		})

		return nil
	}
	for _, htlc := range filteredView.OurUpdates {
		err := addHtlc(htlc, false)
		if err != nil {
			return nil, fmt.Errorf("error creating our HTLC "+
				"allocation: %w", err)
		}
	}

	for _, htlc := range filteredView.TheirUpdates {
		err := addHtlc(htlc, true)
		if err != nil {
			return nil, fmt.Errorf("error creating their HTLC "+
				"allocation: %w", err)
		}
	}

	// Finally, we add the non-asset HTLC outputs. These are HTLCs that
	// don't carry any asset balance, but are still part of the commitment
	// transaction.
	addNonAssetHtlc := func(htlc *DecodedDescriptor,
		isIncoming bool) error {

		htlcScript, err := lnwallet.GenTaprootHtlcScript(
			isIncoming, whoseCommit, htlc.Timeout, htlc.RHash,
			&keys, lfn.None[txscript.TapLeaf](),
		)
		if err != nil {
			return fmt.Errorf("error creating HTLC script: %w", err)
		}

		sibling, htlcTree, err := LeavesFromTapscriptScriptTree(
			htlcScript,
		)
		if err != nil {
			return fmt.Errorf("error creating HTLC script "+
				"sibling: %w", err)
		}

		// If HTLC is dust, do not create allocation for it.
		isDust := lnwallet.HtlcIsDust(
			chanState.ChanType, isIncoming, whoseCommit,
			filteredView.FeePerKw, htlc.Amount.ToSatoshis(),
			dustLimit,
		)
		if isDust {
			return nil
		}

		allocations = append(allocations, &Allocation{
			Type:           AllocationTypeNoAssets,
			BtcAmount:      htlc.Amount.ToSatoshis(),
			InternalKey:    htlcTree.InternalKey,
			NonAssetLeaves: sibling,
			SortTaprootKeyBytes: schnorr.SerializePubKey(
				htlcTree.TaprootKey,
			),
			CLTV:      htlc.Timeout,
			HtlcIndex: htlc.HtlcIndex,
		})

		return nil
	}

	for _, htlc := range nonAssetView.OurUpdates {
		err := addNonAssetHtlc(htlc, false)
		if err != nil {
			return nil, fmt.Errorf("error creating our HTLC "+
				"allocation: %w", err)
		}
	}

	for _, htlc := range nonAssetView.TheirUpdates {
		err := addNonAssetHtlc(htlc, true)
		if err != nil {
			return nil, fmt.Errorf("error creating their HTLC "+
				"allocation: %w", err)
		}
	}

	// With all allocations created, we now sort them to ensure that we have
	// a stable and deterministic order that both parties can arrive at. We
	// then assign the output indexes according to that order.
	InPlaceAllocationSort(allocations)
	for idx := range allocations {
		allocations[idx].OutputIndex = uint32(idx)
	}

	return allocations, nil
}

// addCommitmentOutputs creates the allocations for all commitment and
// commitment anchor outputs, depending on whether this is our commitment
// transaction or not.
func addCommitmentOutputs(chanType channeldb.ChannelType, localChanCfg,
	remoteChanCfg *channeldb.ChannelConfig, initiator bool, ourBalance,
	theirBalance btcutil.Amount, ourAssetBalance, theirAssetBalance uint64,
	wantLocalCommitAnchor, wantRemoteCommitAnchor bool,
	keys lnwallet.CommitmentKeyRing, leaseExpiry uint32,
	addAllocation func(a *Allocation)) error {

	// Start with the commitment anchor outputs.
	localAnchor, remoteAnchor, err := lnwallet.CommitScriptAnchors(
		chanType, localChanCfg, remoteChanCfg, &keys,
	)
	if err != nil {
		return fmt.Errorf("error creating commitment anchors: %w", err)
	}

	if wantLocalCommitAnchor {
		sibling, scriptTree, err := LeavesFromTapscriptScriptTree(
			localAnchor,
		)
		if err != nil {
			return fmt.Errorf("error creating local anchor script "+
				"sibling: %w", err)
		}

		addAllocation(&Allocation{
			// Commitment anchor outputs never carry assets.
			Type:           AllocationTypeNoAssets,
			Amount:         0,
			BtcAmount:      lnwallet.AnchorSize,
			InternalKey:    scriptTree.InternalKey,
			NonAssetLeaves: sibling,
			SortTaprootKeyBytes: schnorr.SerializePubKey(
				scriptTree.TaprootKey,
			),
		})
	}
	if wantRemoteCommitAnchor {
		sibling, scriptTree, err := LeavesFromTapscriptScriptTree(
			remoteAnchor,
		)
		if err != nil {
			return fmt.Errorf("error creating remote anchor "+
				"script sibling: %w", err)
		}

		addAllocation(&Allocation{
			// Commitment anchor outputs never carry assets.
			Type:           AllocationTypeNoAssets,
			Amount:         0,
			BtcAmount:      lnwallet.AnchorSize,
			InternalKey:    scriptTree.InternalKey,
			NonAssetLeaves: sibling,
			SortTaprootKeyBytes: schnorr.SerializePubKey(
				scriptTree.TaprootKey,
			),
		})
	}

	// We've asserted that we have a non-dust BTC balance if we have an
	// asset balance before, so we can just check the asset balance here.
	if ourAssetBalance > 0 || ourBalance > 0 {
		toLocalScript, err := lnwallet.CommitScriptToSelf(
			chanType, initiator, keys.ToLocalKey,
			keys.RevocationKey, uint32(localChanCfg.CsvDelay),
			leaseExpiry, lfn.None[txscript.TapLeaf](),
		)
		if err != nil {
			return fmt.Errorf("error creating to local script: %w",
				err)
		}

		sibling, toLocalTree, err := LeavesFromTapscriptScriptTree(
			toLocalScript,
		)
		if err != nil {
			return fmt.Errorf("error creating to local script "+
				"sibling: %w", err)
		}

		allocation := &Allocation{
			Type:           CommitAllocationToLocal,
			Amount:         ourAssetBalance,
			AssetVersion:   asset.V1,
			SplitRoot:      initiator,
			BtcAmount:      ourBalance,
			InternalKey:    toLocalTree.InternalKey,
			NonAssetLeaves: sibling,
			ScriptKey: asset.ScriptKey{
				PubKey: asset.NewScriptKey(
					toLocalTree.TaprootKey,
				).PubKey,
				TweakedScriptKey: &asset.TweakedScriptKey{
					RawKey: keychain.KeyDescriptor{
						PubKey: toLocalTree.InternalKey,
					},
					Tweak: toLocalTree.TapscriptRoot,
				},
			},
			SortTaprootKeyBytes: schnorr.SerializePubKey(
				toLocalTree.TaprootKey,
			),
		}

		// If there are no assets, only BTC (for example due to a push
		// amount), the allocation looks simpler.
		if ourAssetBalance == 0 {
			allocation = &Allocation{
				Type:           AllocationTypeNoAssets,
				BtcAmount:      ourBalance,
				InternalKey:    toLocalTree.InternalKey,
				NonAssetLeaves: sibling,
				ScriptKey: asset.NewScriptKey(
					toLocalTree.TaprootKey,
				),
				SortTaprootKeyBytes: schnorr.SerializePubKey(
					toLocalTree.TaprootKey,
				),
			}
		}

		addAllocation(allocation)
	}

	if theirAssetBalance > 0 || theirBalance > 0 {
		toRemoteScript, _, err := lnwallet.CommitScriptToRemote(
			chanType, initiator, keys.ToRemoteKey, leaseExpiry,
			lfn.None[txscript.TapLeaf](),
		)
		if err != nil {
			return fmt.Errorf("error creating to remote script: %w",
				err)
		}

		sibling, toRemoteTree, err := LeavesFromTapscriptScriptTree(
			toRemoteScript,
		)
		if err != nil {
			return fmt.Errorf("error creating to remote script "+
				"sibling: %w", err)
		}

		allocation := &Allocation{
			Type:           CommitAllocationToRemote,
			Amount:         theirAssetBalance,
			AssetVersion:   asset.V1,
			SplitRoot:      !initiator,
			BtcAmount:      theirBalance,
			InternalKey:    toRemoteTree.InternalKey,
			NonAssetLeaves: sibling,
			ScriptKey: asset.ScriptKey{
				PubKey: asset.NewScriptKey(
					toRemoteTree.TaprootKey,
				).PubKey,
				TweakedScriptKey: &asset.TweakedScriptKey{
					RawKey: keychain.KeyDescriptor{
						//nolint:lll
						PubKey: toRemoteTree.InternalKey,
					},
					Tweak: toRemoteTree.TapscriptRoot,
				},
			},
			SortTaprootKeyBytes: schnorr.SerializePubKey(
				toRemoteTree.TaprootKey,
			),
		}

		// If there are no assets, only BTC (for example due to a push
		// amount), the allocation looks simpler.
		if theirAssetBalance == 0 {
			allocation = &Allocation{
				Type:           AllocationTypeNoAssets,
				BtcAmount:      theirBalance,
				InternalKey:    toRemoteTree.InternalKey,
				NonAssetLeaves: sibling,
				ScriptKey: asset.NewScriptKey(
					toRemoteTree.TaprootKey,
				),
				SortTaprootKeyBytes: schnorr.SerializePubKey(
					toRemoteTree.TaprootKey,
				),
			}
		}

		addAllocation(allocation)
	}

	return nil
}

// LeavesFromTapscriptScriptTree creates a tapscript sibling from a commit
// script tree.
func LeavesFromTapscriptScriptTree(
	scriptTree input.ScriptDescriptor) ([]txscript.TapLeaf,
	input.ScriptTree, error) {

	emptyTree := input.ScriptTree{}

	tapscriptTree, ok := scriptTree.(input.TapscriptDescriptor)
	if !ok {
		return nil, emptyTree, fmt.Errorf("expected tapscript tree, "+
			"got %T", scriptTree)
	}

	leaves := fn.Map(
		tapscriptTree.TapScriptTree().LeafMerkleProofs,
		func(proof txscript.TapscriptProof) txscript.TapLeaf {
			return proof.TapLeaf
		},
	)

	return leaves, tapscriptTree.Tree(), nil
}

// ToCommitment converts the allocations to a Commitment struct.
func ToCommitment(allocations []*Allocation,
	vPackets []*tappsbt.VPacket) (*cmsg.Commitment, error) {

	var (
		localAssets   []*cmsg.AssetOutput
		remoteAssets  []*cmsg.AssetOutput
		outgoingHtlcs = make(map[input.HtlcIndex][]*cmsg.AssetOutput)
		incomingHtlcs = make(map[input.HtlcIndex][]*cmsg.AssetOutput)
		auxLeaves     lnwallet.CommitAuxLeaves
	)

	// Start with the to_local output. There should be at most one of these
	// outputs.
	toLocal := fn.Filter(allocations, FilterByType(CommitAllocationToLocal))
	switch {
	case len(toLocal) > 1:
		return nil, fmt.Errorf("expected at most one to local output, "+
			"got %d", len(toLocal))

	case len(toLocal) == 1:
		toLocalLeaf, err := toLocal[0].AuxLeaf()
		if err != nil {
			return nil, fmt.Errorf("error creating to local aux "+
				"leaf: %w", err)
		}
		auxLeaves.LocalAuxLeaf = lfn.Some(toLocalLeaf)

		localAssets, err = collectOutputs(toLocal[0], vPackets)
		if err != nil {
			return nil, fmt.Errorf("error collecting to local "+
				"outputs: %w", err)
		}
	}

	// The same for the to_remote, at most one should exist.
	toRemote := fn.Filter(
		allocations, FilterByType(CommitAllocationToRemote),
	)
	switch {
	case len(toRemote) > 1:
		return nil, fmt.Errorf("expected at most one to remote "+
			"output, got %d", len(toRemote))

	case len(toRemote) == 1:
		toRemoteLeaf, err := toRemote[0].AuxLeaf()
		if err != nil {
			return nil, fmt.Errorf("error creating to remote aux "+
				"leaf: %w", err)
		}
		auxLeaves.RemoteAuxLeaf = lfn.Some(toRemoteLeaf)

		remoteAssets, err = collectOutputs(toRemote[0], vPackets)
		if err != nil {
			return nil, fmt.Errorf("error collecting to remote "+
				"outputs: %w", err)
		}
	}

	outgoing := fn.Filter(
		allocations, FilterByType(CommitAllocationHtlcOutgoing),
	)
	for _, a := range outgoing {
		htlcLeaf, err := a.AuxLeaf()
		if err != nil {
			return nil, fmt.Errorf("error creating outgoing htlc "+
				"aux leaf: %w", err)
		}

		if auxLeaves.OutgoingHtlcLeaves == nil {
			auxLeaves.OutgoingHtlcLeaves = make(input.HtlcAuxLeaves)
		}

		auxLeaves.OutgoingHtlcLeaves[a.HtlcIndex] = input.HtlcAuxLeaf{
			AuxTapLeaf: lfn.Some(htlcLeaf),

			// At this point we cannot derive the second level leaf
			// yet. We'll need to do that right before signing the
			// second level transaction, only then do we know the
			// full commitment transaction to reference.
			SecondLevelLeaf: lfn.None[txscript.TapLeaf](),
		}

		outgoingHtlcs[a.HtlcIndex], err = collectOutputs(a, vPackets)
		if err != nil {
			return nil, fmt.Errorf("error collecting outgoing "+
				"htlc outputs: %w", err)
		}
	}

	incoming := fn.Filter(
		allocations, FilterByType(CommitAllocationHtlcIncoming),
	)
	for _, a := range incoming {
		htlcLeaf, err := a.AuxLeaf()
		if err != nil {
			return nil, fmt.Errorf("error creating incoming htlc "+
				"aux leaf: %w", err)
		}

		if auxLeaves.IncomingHtlcLeaves == nil {
			auxLeaves.IncomingHtlcLeaves = make(input.HtlcAuxLeaves)
		}

		auxLeaves.IncomingHtlcLeaves[a.HtlcIndex] = input.HtlcAuxLeaf{
			AuxTapLeaf: lfn.Some(htlcLeaf),

			// At this point we cannot derive the second level leaf
			// yet. We'll need to do that right before signing the
			// second level transaction, only then do we know the
			// full commitment transaction to reference.
			SecondLevelLeaf: lfn.None[txscript.TapLeaf](),
		}

		incomingHtlcs[a.HtlcIndex], err = collectOutputs(a, vPackets)
		if err != nil {
			return nil, fmt.Errorf("error collecting incoming "+
				"htlc outputs: %w", err)
		}
	}

	return cmsg.NewCommitment(
		localAssets, remoteAssets, outgoingHtlcs, incomingHtlcs,
		auxLeaves,
	), nil
}

// collectOutputs collects all virtual transaction outputs for a given
// allocation from the given packets.
func collectOutputs(a *Allocation,
	allPackets []*tappsbt.VPacket) ([]*cmsg.AssetOutput, error) {

	var outputs []*cmsg.AssetOutput
	for _, p := range allPackets {
		assetID, err := p.AssetID()
		if err != nil {
			return nil, fmt.Errorf("error getting asset ID of "+
				"packet: %w", err)
		}

		for idx, o := range p.Outputs {
			if o.ProofSuffix == nil {
				return nil, fmt.Errorf("output %v is missing "+
					"proof", idx)
			}
			if o.AnchorOutputIndex == a.OutputIndex {
				outputs = append(outputs, cmsg.NewAssetOutput(
					assetID, o.Amount, *o.ProofSuffix,
				))
			}
		}
	}

	return outputs, nil
}

// CreateSecondLevelHtlcPackets creates the virtual packets for the second level
// HTLC transaction.
func CreateSecondLevelHtlcPackets(chanState lnwallet.AuxChanState,
	commitTx *wire.MsgTx, htlcAmt btcutil.Amount,
	keys lnwallet.CommitmentKeyRing, chainParams *address.ChainParams,
	htlcOutputs []*cmsg.AssetOutput) ([]*tappsbt.VPacket, []*Allocation,
	error) {

	var leaseExpiry uint32
	if chanState.ChanType.HasLeaseExpiration() {
		leaseExpiry = chanState.ThawHeight
	}

	// Next, we'll generate the script used as the output for all second
	// level HTLC which forces a covenant w.r.t what can be done with all
	// HTLC outputs.
	scriptInfo, err := lnwallet.SecondLevelHtlcScript(
		chanState.ChanType, chanState.IsInitiator, keys.RevocationKey,
		keys.ToLocalKey, uint32(chanState.LocalChanCfg.CsvDelay),
		leaseExpiry, lfn.None[txscript.TapLeaf](),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating second level htlc "+
			"script: %w", err)
	}

	sibling, htlcTree, err := LeavesFromTapscriptScriptTree(scriptInfo)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating second level HTLC "+
			"script sibling: %w", err)
	}

	allocations := []*Allocation{{
		Type:         SecondLevelHtlcAllocation,
		Amount:       cmsg.OutputSum(htlcOutputs),
		AssetVersion: asset.V1,
		BtcAmount:    htlcAmt,
		Sequence: lnwallet.HtlcSecondLevelInputSequence(
			chanState.ChanType,
		),
		InternalKey:    htlcTree.InternalKey,
		NonAssetLeaves: sibling,
		ScriptKey:      asset.NewScriptKey(htlcTree.TaprootKey),
		SortTaprootKeyBytes: schnorr.SerializePubKey(
			htlcTree.TaprootKey,
		),
	}}

	// The proofs in the asset outputs don't have the full commitment
	// transaction, so we need to add it now to make them complete.
	inputProofs := fn.Map(
		htlcOutputs, func(o *cmsg.AssetOutput) *proof.Proof {
			p := o.Proof.Val
			p.AnchorTx = *commitTx

			return &p
		},
	)

	vPackets, err := DistributeCoins(inputProofs, allocations, chainParams)
	if err != nil {
		return nil, nil, fmt.Errorf("error distributing coins: %w", err)
	}

	// Prepare the output assets for each virtual packet, then create the
	// output commitments.
	ctx := context.Background()
	for idx := range vPackets {
		err := tapsend.PrepareOutputAssets(ctx, vPackets[idx])
		if err != nil {
			return nil, nil, fmt.Errorf("unable to prepare output "+
				"assets: %w", err)
		}
	}

	return vPackets, allocations, nil
}

// CreateSecondLevelHtlcTx creates the auxiliary leaf for a successful or timed
// out second level HTLC transaction.
func CreateSecondLevelHtlcTx(chanState lnwallet.AuxChanState,
	commitTx *wire.MsgTx, htlcAmt btcutil.Amount,
	keys lnwallet.CommitmentKeyRing, chainParams *address.ChainParams,
	htlcOutputs []*cmsg.AssetOutput) (input.AuxTapLeaf, error) {

	none := input.NoneTapLeaf()

	vPackets, allocations, err := CreateSecondLevelHtlcPackets(
		chanState, commitTx, htlcAmt, keys, chainParams, htlcOutputs,
	)
	if err != nil {
		return none, fmt.Errorf("error creating second level HTLC "+
			"packets: %w", err)
	}

	outCommitments, err := tapsend.CreateOutputCommitments(vPackets)
	if err != nil {
		return none, fmt.Errorf("unable to create output commitments: "+
			"%w", err)
	}

	// The output commitment is all we need to create the auxiliary leaves.
	// We map the output commitments (which are keyed by on-chain output
	// index) back to the allocation.
	err = AssignOutputCommitments(allocations, outCommitments)
	if err != nil {
		return none, fmt.Errorf("unable to assign output commitments: "+
			"%w", err)
	}

	// Finally, we can create the auxiliary leaf for the second level HTLC
	// transaction.
	auxLeaf, err := allocations[0].AuxLeaf()
	if err != nil {
		return none, fmt.Errorf("error creating aux leaf: %w", err)
	}
	return lfn.Some(auxLeaf), nil
}

// FakeCommitTx creates a fake commitment on-chain transaction from the given
// funding outpoint and allocations. The transaction is not signed.
func FakeCommitTx(fundingOutpoint wire.OutPoint,
	allocations []*Allocation) (*wire.MsgTx, error) {

	fakeCommitTx := wire.NewMsgTx(2)
	fakeCommitTx.TxIn = []*wire.TxIn{
		{
			PreviousOutPoint: fundingOutpoint,
		},
	}
	fakeCommitTx.TxOut = make([]*wire.TxOut, len(allocations))

	for _, a := range allocations {
		pkScript, err := a.finalPkScript()
		if err != nil {
			return nil, fmt.Errorf("error getting final pk "+
				"script: %w", err)
		}

		fakeCommitTx.TxOut[a.OutputIndex] = &wire.TxOut{
			Value:    int64(a.BtcAmount),
			PkScript: pkScript,
		}
	}

	return fakeCommitTx, nil
}

// InPlaceCustomCommitSort performs an in-place sort of a transaction, given a
// list of allocations. The sort is applied to the transaction outputs, using
// the allocation's OutputIndex. The transaction inputs are sorted by the
// default BIP69 sort.
func InPlaceCustomCommitSort(tx *wire.MsgTx, cltvs []uint32,
	htlcIndexes []input.HtlcIndex, allocations []*Allocation) error {

	if len(tx.TxOut) != len(allocations) {
		return fmt.Errorf("output and allocation size mismatch")
	}

	if len(tx.TxOut) != len(cltvs) {
		return fmt.Errorf("output and cltv list size mismatch")
	}

	// First the easy part, sort the inputs by BIP69.
	sort.Sort(sortableInputSlice(tx.TxIn))

	// We simply create a backup of the outputs first, then completely
	// re-create the outputs in the desired order.
	txOutOriginal := tx.TxOut
	tx.TxOut = make([]*wire.TxOut, len(tx.TxOut))
	newCltvs := make([]uint32, len(cltvs))

	for i, original := range txOutOriginal {
		var allocation *Allocation
		for _, a := range allocations {
			match, err := a.MatchesOutput(
				original.PkScript, original.Value, cltvs[i],
				htlcIndexes[i],
			)
			if err != nil {
				return fmt.Errorf("error matching output: %w",
					err)
			}

			if match {
				allocation = a
				break
			}
		}

		if allocation == nil {
			return fmt.Errorf("no corresponding allocation entry "+
				"found for output index %d", i)
		}

		newOrder := allocation.OutputIndex
		if newOrder >= uint32(len(tx.TxOut)) {
			return fmt.Errorf("order index %d out of bounds "+
				"(num_tx_out=%d)", newOrder, len(tx.TxOut))
		}

		tx.TxOut[newOrder] = &wire.TxOut{
			Value:    original.Value,
			PkScript: original.PkScript,
		}
		newCltvs[newOrder] = cltvs[i]
	}

	// Finally, we copy the new CLTVs back to the original slice.
	copy(cltvs, newCltvs)

	return nil
}

// sortableInputSlice is a slice of transaction inputs that supports sorting via
// BIP69.
type sortableInputSlice []*wire.TxIn

// Len returns the length of the sortableInputSlice.
//
// NOTE: Part of the sort.Interface interface.
func (s sortableInputSlice) Len() int { return len(s) }

// Swap exchanges the position of inputs i and j.
//
// NOTE: Part of the sort.Interface interface.
func (s sortableInputSlice) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

// Less is the BIP69 input comparison function. The sort is first applied on
// input hash (reversed / rpc-style), then index. This logic is copied from
// btcutil/txsort.
//
// NOTE: Part of the sort.Interface interface.
func (s sortableInputSlice) Less(i, j int) bool {
	// Input hashes are the same, so compare the index.
	ihash := s[i].PreviousOutPoint.Hash
	jhash := s[j].PreviousOutPoint.Hash
	if ihash == jhash {
		return s[i].PreviousOutPoint.Index < s[j].PreviousOutPoint.Index
	}

	// At this point, the hashes are not equal, so reverse them to
	// big-endian and return the result of the comparison.
	const hashSize = chainhash.HashSize
	for b := 0; b < hashSize/2; b++ {
		ihash[b], ihash[hashSize-1-b] = ihash[hashSize-1-b], ihash[b]
		jhash[b], jhash[hashSize-1-b] = jhash[hashSize-1-b], jhash[b]
	}
	return bytes.Compare(ihash[:], jhash[:]) == -1
}
