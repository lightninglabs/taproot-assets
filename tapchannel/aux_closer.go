package tapchannel

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"sync"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapchannelmsg"
	"github.com/lightninglabs/taproot-assets/tapfreighter"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/tapscript"
	"github.com/lightninglabs/taproot-assets/tapsend"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwallet/chancloser"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/tlv"
)

// AuxChanCloserCfg houses the configuration for the auxiliary channel closer.
type AuxChanCloserCfg struct {
	// ChainParams describes the params for the chain we're on.
	ChainParams *address.ChainParams

	// AddrBook is what we'll use to generate new keys for the co-op close
	// transaction, and also import proof for our settled outputs as the
	// non-initiator.
	AddrBook *address.Book

	// TxSender is what we'll use to broadcast a transaction to the
	// network, while ensuring we also update all our asset and UTXO state
	// on disk (insert a proper transfer, etc., etc.).
	TxSender tapfreighter.Porter

	// DefaultCourierAddr is the default address we'll use to send/receive
	// proofs for the co-op close process
	DefaultCourierAddr *url.URL

	// ProofFetcher is used to fetch proofs needed to properly import the
	// funding output into the database as our own.
	ProofFetcher proof.CourierDispatch

	// ProofArchive is used to store import funding output proofs.
	ProofArchive proof.Archiver

	// HeaderVerifier is used to verify headers in a proof.
	HeaderVerifier proof.HeaderVerifier

	// GroupVerifier is used to verify group keys in a proof.
	GroupVerifier proof.GroupVerifier

	// ChainBridge is used to fetch blocks from the main chain.
	ChainBridge tapgarden.ChainBridge
}

// assetCloseInfo houses the information we need to finalize the close of an
// asset channel.
type assetCloseInfo struct {
	// allocations is the list of allocations for the remote+local party.
	// There'll be at most 4 of these: local+remote BTC outputs,
	// local+remote asset outputs.
	allocations []*tapsend.Allocation

	// vPackets is the list of virtual packets that we'll use to anchor the
	// outputs.
	vPackets []*tappsbt.VPacket

	// outputCommitments maps an output index to the tap commitment for
	// that output.
	outputCommitments tappsbt.OutputCommitments

	// closeFee is the fee that was paid to close the channel.
	closeFee int64
}

// AuxChanCloser is used to implement asset-aware co-op close for channels.
type AuxChanCloser struct {
	cfg AuxChanCloserCfg

	sync.RWMutex

	closeInfo map[wire.OutPoint]*assetCloseInfo
}

// NewAuxChanCloser creates a new instance of the auxiliary channel closer.
func NewAuxChanCloser(cfg AuxChanCloserCfg) *AuxChanCloser {
	return &AuxChanCloser{
		cfg:       cfg,
		closeInfo: make(map[wire.OutPoint]*assetCloseInfo),
	}
}

// createCloseAlloc is a helper function that creates an allocation for an asset
// close. This does not set a script key, as the script key will be set for each
// packet after the coins have been distributed.
func createCloseAlloc(isLocal bool, outputSum uint64,
	shutdownMsg tapchannelmsg.AuxShutdownMsg) (*tapsend.Allocation, error) {

	// The sort pkScript for the allocation will just be the internal key,
	// mapped to a BIP 86 taproot output key.
	sortKeyBytes := txscript.ComputeTaprootKeyNoScript(
		shutdownMsg.AssetInternalKey.Val,
	).SerializeCompressed()

	scriptKeyGen := func(assetID asset.ID) (asset.ScriptKey, error) {
		var emptyKey asset.ScriptKey

		scriptKey, ok := shutdownMsg.ScriptKeys.Val[assetID]
		if !ok {
			return emptyKey, fmt.Errorf("no script key for asset "+
				"%v", assetID)
		}

		return asset.NewScriptKey(&scriptKey), nil
	}

	var proofDeliveryUrl *url.URL
	err := lfn.MapOptionZ(
		shutdownMsg.ProofDeliveryAddr.ValOpt(), func(u []byte) error {
			var err error
			proofDeliveryUrl, err = url.Parse(string(u))
			return err
		},
	)
	if err != nil {
		return nil, fmt.Errorf("unable to decode proof delivery "+
			"address: %w", err)
	}

	return &tapsend.Allocation{
		Type: func() tapsend.AllocationType {
			if isLocal {
				return tapsend.CommitAllocationToLocal
			}

			return tapsend.CommitAllocationToRemote
		}(),
		InternalKey:          shutdownMsg.AssetInternalKey.Val,
		GenScriptKey:         scriptKeyGen,
		Amount:               outputSum,
		AssetVersion:         asset.V0,
		BtcAmount:            tapsend.DummyAmtSats,
		SortTaprootKeyBytes:  sortKeyBytes,
		ProofDeliveryAddress: proofDeliveryUrl,
	}, nil
}

// signCommitVirtualPackets signs the commit virtual packets with the funding
// witness, which is just the script and control block for the OP_TRUE spend.
func signCommitVirtualPackets(ctx context.Context,
	vPackets []*tappsbt.VPacket) error {

	useUniqueScriptKey := len(vPackets) > 1
	for idx := range vPackets {
		assetID, err := vPackets[idx].AssetID()
		if err != nil {
			return fmt.Errorf("unable to get asset ID: %w", err)
		}

		// First, we'll prepare the funding witness which includes the
		// OP_TRUE ctrl block.
		fundingWitness, err := tapscript.ChannelFundingSpendWitness(
			useUniqueScriptKey, assetID,
		)
		if err != nil {
			return fmt.Errorf("unable to make funding witness: %w",
				err)
		}

		err = tapsend.PrepareOutputAssets(ctx, vPackets[idx])
		if err != nil {
			return fmt.Errorf("unable to prepare output "+
				"assets: %w", err)
		}

		// With the packets prepared, we'll swap in the correct witness
		// for each of them. We need to do this _after_ calling
		// PrepareOutputAsset, because that method will overwrite any
		// asset in the virtual outputs. Which means we'll also need to
		// set the witness on _every_ output of the packet, to make sure
		// each split output's root asset reference also gets the
		// correct witness.
		for outIdx := range vPackets[idx].Outputs {
			outAsset := vPackets[idx].Outputs[outIdx].Asset

			// There is always only a single input, as we're
			// spending a single funding output w/ each vPkt.
			const inputIndex = 0
			err := outAsset.UpdateTxWitness(
				inputIndex, fundingWitness,
			)
			if err != nil {
				return fmt.Errorf("error updating witness: %w",
					err)
			}
		}
	}

	return nil
}

// AuxCloseOutputs returns the set of close outputs to use for this co-op close
// attempt. We'll add some extra outputs to the co-op close transaction, and
// also give the caller a custom sorting routine.
//
// NOTE: This method is part of the chancloser.AuxChanCloser interface.
func (a *AuxChanCloser) AuxCloseOutputs(
	desc chancloser.AuxCloseDesc) (lfn.Option[chancloser.AuxCloseOutputs],
	error) {

	a.Lock()
	defer a.Unlock()

	none := lfn.None[chancloser.AuxCloseOutputs]()

	// If there's no commit blob present, then we don't need to do
	// anything, as there aren't any assets in the channel.
	if desc.CommitBlob.IsNone() {
		return none, nil
	}

	log.Infof("Constructing aux close options for ChannelPoint(%v): ",
		desc.ChanPoint)

	// Otherwise, we'll decode the commit blob, and the funding blob.
	commitState, err := tapchannelmsg.DecodeCommitment(
		desc.CommitBlob.UnwrapOr(nil),
	)
	if err != nil {
		return none, err
	}
	fundingInfo, err := tapchannelmsg.DecodeOpenChannel(
		desc.FundingBlob.UnwrapOr(nil),
	)
	if err != nil {
		return none, fmt.Errorf("unable decode channel asset "+
			"state: %w", err)
	}

	// Each of the co-op close outputs needs to ref a funding input, so
	// we'll map a map of asset ID to the funding output now.
	inputProofs := make(
		[]*proof.Proof, 0, len(fundingInfo.FundedAssets.Val.Outputs),
	)
	for _, fundingInput := range fundingInfo.FundedAssets.Val.Outputs {
		inputProofs = append(inputProofs, &fundingInput.Proof.Val)
	}

	// We'll also decode the shutdown blobs, so we can extract the shutdown
	// information (delivery script keys, etc.).
	var localShutdown, remoteShutdown tapchannelmsg.AuxShutdownMsg
	err = lfn.MapOptionZ(
		desc.LocalCloseOutput, func(o chancloser.CloseOutput) error {
			blob, err := o.ShutdownRecords.Serialize()
			if err != nil {
				return err
			}

			return localShutdown.Decode(bytes.NewReader(blob))
		},
	)
	if err != nil {
		return none, err
	}
	err = lfn.MapOptionZ(
		desc.RemoteCloseOutput, func(o chancloser.CloseOutput) error {
			blob, err := o.ShutdownRecords.Serialize()
			if err != nil {
				return err
			}

			return remoteShutdown.Decode(bytes.NewReader(blob))
		},
	)
	if err != nil {
		return none, err
	}

	log.Tracef("Decoded local_shutdown=%v, remote_shutdown=%v",
		limitSpewer.Sdump(localShutdown),
		limitSpewer.Sdump(remoteShutdown))

	// To start with, we'll now create the allocations for the asset
	// outputs. We track the amount that'll go to the anchor assets, so we
	// can subtract this from the settled BTC amount.
	var (
		closeAllocs                               []*tapsend.Allocation
		localAlloc, remoteAlloc                   *tapsend.Allocation
		localAssetAnchorAmt, remoteAssetAnchorAmt btcutil.Amount
	)
	sumAmounts := func(accu uint64, o *tapchannelmsg.AssetOutput) uint64 {
		return accu + o.Amount.Val
	}
	localSum := fn.Reduce(commitState.LocalAssets.Val.Outputs, sumAmounts)
	remoteSum := fn.Reduce(commitState.RemoteAssets.Val.Outputs, sumAmounts)
	if localSum > 0 {
		localAlloc, err = createCloseAlloc(
			true, localSum, localShutdown,
		)
		if err != nil {
			return none, err
		}

		localAssetAnchorAmt += localAlloc.BtcAmount

		closeAllocs = append(closeAllocs, localAlloc)
	}
	if remoteSum > 0 {
		remoteAlloc, err = createCloseAlloc(
			false, remoteSum, remoteShutdown,
		)
		if err != nil {
			return none, err
		}

		remoteAssetAnchorAmt += remoteAlloc.BtcAmount

		closeAllocs = append(closeAllocs, remoteAlloc)
	}

	// Next, we'll create allocations for the (up to) two settled outputs
	// in the co-op close transaction.
	desc.LocalCloseOutput.WhenSome(func(o chancloser.CloseOutput) {
		btcAmt := o.Amt
		if desc.Initiator {
			btcAmt += desc.CommitFee
			btcAmt -= desc.CloseFee
		}

		amtAfterAnchor := btcAmt - localAssetAnchorAmt

		// If we can't have a non-dust output after subtracting the
		// anchor amt, then we'll just drop this allocation, and modify
		// our asset allocation to match this value.
		if amtAfterAnchor <= o.DustLimit {
			if localAlloc != nil {
				localAlloc.BtcAmount = btcAmt
			}
			return
		}

		// Snip off the first two bytes, as we'll be getting a P2TR
		// output from the higher level. We want a raw pubkey here.
		sortScript := o.PkScript[2:]
		closeAllocs = append(closeAllocs, &tapsend.Allocation{
			Type:                tapsend.AllocationTypeNoAssets,
			BtcAmount:           amtAfterAnchor,
			SortTaprootKeyBytes: sortScript,
			InternalKey:         localShutdown.BtcInternalKey.Val,
		})
	})
	desc.RemoteCloseOutput.WhenSome(func(o chancloser.CloseOutput) {
		btcAmt := o.Amt
		if !desc.Initiator {
			btcAmt += desc.CommitFee
			btcAmt -= desc.CloseFee
		}

		amtAfterAnchor := btcAmt - remoteAssetAnchorAmt

		// If we can't have a non-dust output after subtracting the
		// anchor amt, then we'll just drop this allocation, and modify
		// our asset allocation to match this value.
		if amtAfterAnchor <= o.DustLimit {
			if remoteAlloc != nil {
				remoteAlloc.BtcAmount = btcAmt
			}

			return
		}

		// Snip off the first two bytes, as we'll be getting a P2TR
		// output from the higher level. We want a raw pubkey here.
		sortScript := o.PkScript[2:]
		closeAllocs = append(closeAllocs, &tapsend.Allocation{
			Type:                tapsend.AllocationTypeNoAssets,
			BtcAmount:           amtAfterAnchor,
			SortTaprootKeyBytes: sortScript,
			InternalKey:         remoteShutdown.BtcInternalKey.Val,
		})
	})

	log.Infof("Allocations for co-op close txn: %v",
		limitSpewer.Sdump(closeAllocs))

	// With all allocations created, we now sort them to ensure that we
	// have a stable and deterministic order that both parties can arrive
	// at. We then assign the output indexes according to that order.
	tapsend.InPlaceAllocationSort(closeAllocs)
	for idx := range closeAllocs {
		closeAllocs[idx].OutputIndex = uint32(idx)
	}

	// Now we know the deterministic ordering of the local/remote asset/btc
	// outputs, we can extract the output indexes for the allocations.
	var (
		localOutputIndex, remoteOutputIndex uint32
	)
	if localAlloc != nil {
		localOutputIndex = localAlloc.OutputIndex
	}
	if remoteAlloc != nil {
		remoteOutputIndex = remoteAlloc.OutputIndex
	}

	// We don't use the normal allocation code here. This requires a bit of
	// a lengthy explanation: When we close a channel, the output of the
	// `lncli closedchannels` command will show the last commitment state of
	// the channel as the closing asset balance. Which is correct in terms
	// of balances. But if there are multiple different asset IDs (e.g., in
	// a grouped asset channel), then _how_ those pieces are distributed
	// within the commitment transaction depends on the order of the
	// allocations. And the order of the allocations is dependent on the
	// BTC amount and the pkScript of the BTC-level output. Both of which
	// are different in the coop close output (we set the asset-level output
	// BTC amount to the dummy amount, and the pkScript will be a newly
	// derived internal key with no sibling script path).
	// So, long story short: If we used the tapsend.DistributeCoins method
	// here, it could happen that the actual asset output distribution shown
	// in the `lncli closedchannels` command would be different from the
	// actual distribution in the co-op close transaction.
	// This could mostly be seen as an UX-only issue, but was actually
	// discovered while attempting to assert the final closing balance of
	// grouped asset channels in the litd integration test.
	vPackets, err := CommitmentToPackets(
		commitState, inputProofs, a.cfg.ChainParams, localShutdown,
		remoteShutdown, localOutputIndex, remoteOutputIndex, tappsbt.V1,
	)
	if err != nil {
		return none, fmt.Errorf("unable to create vPackets: %w", err)
	}

	// We can now add the witness for the OP_TRUE spend of the commitment
	// output to the vPackets.
	ctxb := context.Background()
	if err := signCommitVirtualPackets(ctxb, vPackets); err != nil {
		return none, fmt.Errorf("error signing commit virtual "+
			"packets: %w", err)
	}

	// With the outputs prepared, we can now create the set of output
	// commitments, then with the output index locations known, we can set
	// the output indexes in the allocations.
	outCommitments, err := tapsend.CreateOutputCommitments(vPackets)
	if err != nil {
		return none, fmt.Errorf("unable to create output "+
			"commitments: %w", err)
	}
	err = tapsend.AssignOutputCommitments(closeAllocs, outCommitments)
	if err != nil {
		return none, fmt.Errorf("unable to assign alloc output "+
			"commitments: %w", err)
	}

	// Now that the vPackets have been fully updated, we'll store them for
	// later so we can finalize the coop close.
	a.closeInfo[desc.ChanPoint] = &assetCloseInfo{
		allocations:       closeAllocs,
		vPackets:          vPackets,
		outputCommitments: outCommitments,
		closeFee:          int64(desc.CloseFee),
	}

	// With the taproot keys updated, we know the pkScripts needed, so
	// we'll create the wallet option for the co-op close.
	var closeOutputs []lnwallet.CloseOutput
	assetAllocations := fn.Filter(closeAllocs, tapsend.FilterByTypeExclude(
		tapsend.AllocationTypeNoAssets,
	))
	for _, alloc := range assetAllocations {
		pkScript, err := alloc.FinalPkScript()
		if err != nil {
			return none, fmt.Errorf("unable to make final "+
				"pkScript: %w", err)
		}

		closeOutputs = append(closeOutputs, lnwallet.CloseOutput{
			TxOut: wire.TxOut{
				PkScript: pkScript,
				Value:    int64(alloc.BtcAmount),
			},
			IsLocal: alloc.Type == tapsend.CommitAllocationToLocal,
		})
	}

	// As a final step, we'll craft a custom sorting function for the co-op
	// close txn.
	sortFunc := func(tx *wire.MsgTx) error {
		cltvs := make([]uint32, len(closeAllocs))
		htlcIndexes := make([]input.HtlcIndex, len(closeAllocs))
		return InPlaceCustomCommitSort(
			tx, cltvs, htlcIndexes, closeAllocs,
		)
	}

	return lfn.Some(chancloser.AuxCloseOutputs{
		ExtraCloseOutputs: closeOutputs,
		CustomSort:        sortFunc,
	}), nil
}

// ShutdownBlob returns the set of custom records that should be included in
// the shutdown message.
//
// NOTE: This method is part of the chancloser.AuxChanCloser interface.
func (a *AuxChanCloser) ShutdownBlob(
	req chancloser.AuxShutdownReq) (lfn.Option[lnwire.CustomRecords],
	error) {

	a.Lock()
	defer a.Unlock()

	none := lfn.None[lnwire.CustomRecords]()

	// If there's no custom blob, then we don't need to do anything.
	if req.FundingBlob.IsNone() {
		log.Debugf("No funding blob for ChannelPoint(%v)",
			req.ChanPoint)
		return none, nil
	}

	// Also ensure that an internal key was provided.
	btcInternalKey, err := req.InternalKey.UnwrapOrErr(
		fmt.Errorf("internal key must be provided"),
	)
	if err != nil {
		return none, err
	}

	log.Infof("Creating shutdown blob for close of ChannelPoint(%v)",
		req.ChanPoint)

	// Otherwise, we'll decode the funding state, so we can examine the
	// different asset IDs in the channel.
	var fundingState tapchannelmsg.OpenChannel
	err = lfn.MapOptionZ(req.FundingBlob, func(blob tlv.Blob) error {
		c, err := tapchannelmsg.DecodeOpenChannel(blob)
		if err != nil {
			return err
		}

		fundingState = *c

		return nil
	})
	if err != nil {
		return none, err
	}

	ctx := context.Background()

	// We'll use the address book to query for a new internal key that will
	// be used to anchor the output we get sent.
	newInternalKey, err := a.cfg.AddrBook.NextInternalKey(
		ctx, asset.TaprootAssetsKeyFamily,
	)
	if err != nil {
		return none, err
	}

	// Next, we'll collect all the asset IDs that were committed to the
	// channel.
	assetIDs := fn.Map(
		fundingState.FundedAssets.Val.Outputs,
		func(o *tapchannelmsg.AssetOutput) asset.ID {
			return o.AssetID.Val
		},
	)

	// Now that we have all the asset IDs, we'll query for a new key for
	// each of them which we'll use as both the internal key and the script
	// key.
	scriptKeys := make(tapchannelmsg.ScriptKeyMap)
	for _, assetID := range assetIDs {
		newKey, err := a.cfg.AddrBook.NextScriptKey(
			ctx, asset.TaprootAssetsKeyFamily,
		)
		if err != nil {
			return none, err
		}

		scriptKeys[assetID] = *newKey.PubKey
	}

	// Finally, we'll map the extra shutdown info to a TLV record map we
	// can send to lnd to have included.
	shutdownRecord := tapchannelmsg.NewAuxShutdownMsg(
		&btcInternalKey, newInternalKey.PubKey, scriptKeys,
		a.cfg.DefaultCourierAddr,
	)
	records, err := tlv.RecordsToMap(shutdownRecord.EncodeRecords())
	if err != nil {
		return none, err
	}

	log.Infof("Constructed shutdown record: %v", limitSpewer.Sdump(records))

	return lfn.Some[lnwire.CustomRecords](records), nil
}

// shipChannelTxn takes a channel transaction, an output commitment, and the
// set of vPackets used to make the output commitment and ships a complete
// pre-singed package off to the porter. This'll insert a transfer for the
// channel, send the final transaction to the network, and update any
// transition proofs once a confirmation occurs.
func shipChannelTxn(txSender tapfreighter.Porter, chanTx *wire.MsgTx,
	outputCommitments tappsbt.OutputCommitments,
	vPkts []*tappsbt.VPacket, closeFee int64) error {

	chanTxPsbt, err := tapsend.PrepareAnchoringTemplate(vPkts)
	if err != nil {
		return fmt.Errorf("unable to make close psbt: %w", err)
	}
	for _, vPkt := range vPkts {
		err = tapsend.UpdateTaprootOutputKeys(
			chanTxPsbt, vPkt, outputCommitments,
		)
		if err != nil {
			return fmt.Errorf("unable to update taproot "+
				"keys: %w", err)
		}
	}

	// With the proofs updated, we can now send things off to the freighter
	// to insert the transfer and add the merkle inclusion proof after
	// confirmation.
	closeAnchor := &tapsend.AnchorTransaction{
		FundedPsbt: &tapsend.FundedPsbt{
			Pkt:       chanTxPsbt,
			ChainFees: closeFee,
		},
		ChainFees: closeFee,
		FinalTx:   chanTx,
	}
	preSignedParcel := tapfreighter.NewPreAnchoredParcel(
		vPkts, nil, closeAnchor,
	)
	_, err = txSender.RequestShipment(preSignedParcel)
	if err != nil {
		return fmt.Errorf("error requesting delivery: %w", err)
	}

	return nil
}

// FinalizeClose is called once the co-op close transaction has been agreed
// upon. We'll finalize the exclusion proofs, then send things off to the
// custodian or porter to finish sending/receiving the proofs.
//
// NOTE: This method is part of the chancloser.AuxChanCloser interface.
func (a *AuxChanCloser) FinalizeClose(desc chancloser.AuxCloseDesc,
	closeTx *wire.MsgTx) error {

	a.Lock()
	defer a.Unlock()

	// Ignore non-asset channels.
	if desc.CommitBlob.IsNone() {
		return nil
	}

	closeInfo, ok := a.closeInfo[desc.ChanPoint]
	if !ok {
		return fmt.Errorf("no vPackets found for ChannelPoint(%v)",
			desc.ChanPoint)
	}

	// Before we finalize the close process, we'll make sure to also import
	// a transfer for the funding outputs. This way we'll ensure that we're
	// able to insert the transfer that spends these outputs. We only need
	// to do this for the responder though, as the creator of the channel
	// already has these proofs inserted.
	if !desc.Initiator {
		fundingInfo, err := tapchannelmsg.DecodeOpenChannel(
			desc.FundingBlob.UnwrapOr(nil),
		)
		if err != nil {
			return err
		}

		fundingInputProofs := fn.Map(
			fundingInfo.FundedAssets.Val.Outputs,
			func(a *tapchannelmsg.AssetOutput) *proof.Proof {
				return &a.Proof.Val
			},
		)
		err = importOutputProofs(
			desc.ShortChanID, fundingInputProofs,
			a.cfg.DefaultCourierAddr, a.cfg.ProofFetcher,
			a.cfg.ChainBridge, a.cfg.HeaderVerifier,
			a.cfg.GroupVerifier, a.cfg.ProofArchive,
		)
		if err != nil {
			return fmt.Errorf("unable to import output "+
				"proofs: %w", err)
		}
	}

	log.Infof("Finalizing close for ChannelPoint(%v): ", desc.ChanPoint)

	defer delete(a.closeInfo, desc.ChanPoint)

	// With the co-op close transaction known, we have the information we
	// need to create the proof suffixes for each relevant close output.
	for idx := range closeInfo.vPackets {
		vPkt := closeInfo.vPackets[idx]
		for outIdx := range vPkt.Outputs {
			exclusionCreator := tapsend.NonAssetExclusionProofs(
				closeInfo.allocations,
			)

			proofSuffix, err := tapsend.CreateProofSuffixCustom(
				closeTx, vPkt, closeInfo.outputCommitments,
				outIdx, closeInfo.vPackets, exclusionCreator,
			)
			if err != nil {
				return fmt.Errorf("unable to create proof "+
					"suffix for output %d: %w", outIdx, err)
			}

			vPkt.Outputs[outIdx].ProofSuffix = proofSuffix
		}
	}

	// With the proofs finalized above, we'll now ship the transaction off
	// to the porter so it can insert a record on disk, and deliver the
	// relevant set of proofs.
	return shipChannelTxn(
		a.cfg.TxSender, closeTx, closeInfo.outputCommitments,
		closeInfo.vPackets, closeInfo.closeFee,
	)
}
