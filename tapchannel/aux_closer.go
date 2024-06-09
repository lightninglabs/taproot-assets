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
	"github.com/davecgh/go-spew/spew"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapchannelmsg"
	"github.com/lightninglabs/taproot-assets/tapfreighter"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/tapsend"
	lfn "github.com/lightningnetwork/lnd/fn"
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
}

// assetCloseInfo houses the information we need to finalize the close of an
// asset channel.
type assetCloseInfo struct {
	// allocations is the list of allocations for the remote+local party.
	// There'll be at most 4 of these: local+remote BTC outputs,
	// local+remote asset outputs.
	allocations []*Allocation

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

// createCloseAlloc is a helper function that creates an allocation for an
// asset close.
func createCloseAlloc(isLocal, isInitiator bool, closeAsset *asset.Asset,
	shutdownMsg tapchannelmsg.AuxShutdownMsg) (*Allocation, error) {

	assetID := closeAsset.ID()

	// The sort pkScript for the allocation will just be the internal key,
	// mapped to a BIP 86 taproot output key.
	sortKeyBytes := txscript.ComputeTaprootKeyNoScript(
		shutdownMsg.AssetInternalKey.Val,
	).SerializeCompressed()

	scriptKey, ok := shutdownMsg.ScriptKeys.Val[assetID]
	if !ok {
		return nil, fmt.Errorf("no script key for asset %v", assetID)
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

	return &Allocation{
		Type: func() AllocationType {
			if isLocal {
				return CommitAllocationToLocal
			}

			return CommitAllocationToRemote
		}(),
		SplitRoot:            isInitiator,
		InternalKey:          shutdownMsg.AssetInternalKey.Val,
		ScriptKey:            asset.NewScriptKey(&scriptKey),
		Amount:               closeAsset.Amount,
		AssetVersion:         asset.V0,
		BtcAmount:            tapsend.DummyAmtSats,
		SortTaprootKeyBytes:  sortKeyBytes,
		ProofDeliveryAddress: proofDeliveryUrl,
	}, nil
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
	fundingInputs := make(map[asset.ID]*tapchannelmsg.AssetOutput)
	inputProofs := make(
		[]*proof.Proof, 0, len(fundingInfo.FundedAssets.Val.Outputs),
	)
	for _, fundingInput := range fundingInfo.FundedAssets.Val.Outputs {
		fundingInputs[fundingInput.AssetID.Val] = fundingInput
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
		spew.Sdump(localShutdown), spew.Sdump(remoteShutdown))

	// To start with, we'll now create the allocations for the asset
	// outputs. We track the amount that'll go to the anchor assets, so we
	// can subtract this from the settled BTC amount.
	var (
		closeAllocs                               []*Allocation
		localAlloc, remoteAlloc                   *Allocation
		localAssetAnchorAmt, remoteAssetAnchorAmt btcutil.Amount
	)
	for _, localAssetProof := range commitState.LocalAssets.Val.Outputs {
		localAsset := localAssetProof.Proof.Val.Asset

		closeAlloc, err := createCloseAlloc(
			true, desc.Initiator, &localAsset, localShutdown,
		)
		if err != nil {
			return none, err
		}

		localAlloc = closeAlloc

		localAssetAnchorAmt += closeAlloc.BtcAmount

		closeAllocs = append(closeAllocs, closeAlloc)
	}
	for _, remoteAssetProof := range commitState.RemoteAssets.Val.Outputs {
		remoteAsset := remoteAssetProof.Proof.Val.Asset

		closeAlloc, err := createCloseAlloc(
			false, !desc.Initiator, &remoteAsset, remoteShutdown,
		)
		if err != nil {
			return none, err
		}

		remoteAlloc = closeAlloc

		remoteAssetAnchorAmt += closeAlloc.BtcAmount

		closeAllocs = append(closeAllocs, closeAlloc)
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
		closeAllocs = append(closeAllocs, &Allocation{
			Type:                AllocationTypeNoAssets,
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
		closeAllocs = append(closeAllocs, &Allocation{
			Type:                AllocationTypeNoAssets,
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
	InPlaceAllocationSort(closeAllocs)
	for idx := range closeAllocs {
		closeAllocs[idx].OutputIndex = uint32(idx)
	}

	// Now that we have the complete set of allocations, we'll distribute
	// them to create the vPackets we'll need to anchor everything.
	vPackets, err := DistributeCoins(
		inputProofs, closeAllocs, a.cfg.ChainParams,
	)
	if err != nil {
		return none, fmt.Errorf("unable to distribute coins: %w", err)
	}

	// With the vPackets created we'll now prepare all the split
	// information encoded in the vPackets.
	fundingScriptTree := NewFundingScriptTree()
	ctx := context.Background()
	for idx := range vPackets {
		err := tapsend.PrepareOutputAssets(ctx, vPackets[idx])
		if err != nil {
			return none, fmt.Errorf("unable to prepare output "+
				"assets: %w", err)
		}

		// For our split root, we'll need to create a valid control
		// block for our OP_TRUE script.
		tapscriptTree := fundingScriptTree.TapscriptTree
		ctrlBlock := tapscriptTree.LeafMerkleProofs[0].ToControlBlock(
			&input.TaprootNUMSKey,
		)
		ctrlBlockBytes, err := ctrlBlock.ToBytes()
		if err != nil {
			return none, fmt.Errorf("unable to serialize "+
				"control block: %w", err)
		}

		txWitness := wire.TxWitness{
			anyoneCanSpendScript(), ctrlBlockBytes,
		}

		for outIdx := range vPackets[idx].Outputs {
			outAsset := vPackets[idx].Outputs[outIdx].Asset

			// There is always only a single input, which is the
			// funding output.
			const inputIndex = 0
			err := outAsset.UpdateTxWitness(inputIndex, txWitness)
			if err != nil {
				return none, fmt.Errorf("error updating "+
					"witness: %w", err)
			}
		}
	}

	// With the outputs prepared, we can now create the set of output
	// commitments, then with the output index locations known, we can set
	// the output indexes in the allocations.
	outCommitments, err := tapsend.CreateOutputCommitments(vPackets)
	if err != nil {
		return none, fmt.Errorf("unable to create output "+
			"commitments: %w", err)
	}
	err = AssignOutputCommitments(closeAllocs, outCommitments)
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
	assetAllocations := fn.Filter(closeAllocs, FilterByTypeExclude(
		AllocationTypeNoAssets,
	))
	for _, alloc := range assetAllocations {
		pkScript, err := alloc.finalPkScript()
		if err != nil {
			return none, fmt.Errorf("unable to make final "+
				"pkScript: %w", err)
		}

		closeOutputs = append(closeOutputs, lnwallet.CloseOutput{
			TxOut: wire.TxOut{
				PkScript: pkScript,
				Value:    int64(alloc.BtcAmount),
			},
			IsLocal: alloc.Type == CommitAllocationToLocal,
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
	if req.CommitBlob.IsNone() {
		log.Debugf("No commit blob for ChannelPoint(%v)", req.ChanPoint)
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

	// Otherwise, we'll decode the commitment, so we can examine the current
	// state.
	var commitState tapchannelmsg.Commitment
	err = lfn.MapOptionZ(req.CommitBlob, func(blob tlv.Blob) error {
		c, err := tapchannelmsg.DecodeCommitment(blob)
		if err != nil {
			return err
		}

		commitState = *c

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

	// Next, we'll collect all the assets that we own in this channel.
	assets := commitState.LocalAssets.Val.Outputs

	// Now that we have all the asset IDs, we'll query for a new key for
	// each of them which we'll use as both the internal key and the script
	// key.
	scriptKeys := make(tapchannelmsg.ScriptKeyMap)
	for idx := range assets {
		channelAsset := assets[idx]

		newKey, err := a.cfg.AddrBook.NextScriptKey(
			ctx, asset.TaprootAssetsKeyFamily,
		)
		if err != nil {
			return none, err
		}

		// We now add the a
		// TODO(guggero): This only works if there's only a single asset
		// in the channel. We need to extend this to support multiple
		// assets.
		_, err = a.cfg.AddrBook.NewAddressWithKeys(
			ctx, channelAsset.AssetID.Val, channelAsset.Amount.Val,
			newKey, newInternalKey, nil, *a.cfg.DefaultCourierAddr,
		)
		if err != nil {
			return none, fmt.Errorf("error adding new address: %w",
				err)
		}

		scriptKeys[channelAsset.AssetID.Val] = *newKey.PubKey
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

	log.Infof("Constructed shutdown record: %v", spew.Sdump(records))

	return lfn.Some[lnwire.CustomRecords](records), nil
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

	log.Infof("Finalizing close for ChannelPoint(%v): ", desc.ChanPoint)

	defer delete(a.closeInfo, desc.ChanPoint)

	// With the co-op close transaction known, we have the information we
	// need to create the proof suffixes for each relevant close output.
	for idx := range closeInfo.vPackets {
		vPkt := closeInfo.vPackets[idx]
		for outIdx := range vPkt.Outputs {
			exclusionCreator := NonAssetExclusionProofs(
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

	coopClosePsbt, err := tapsend.PrepareAnchoringTemplate(
		closeInfo.vPackets,
	)
	if err != nil {
		return fmt.Errorf("unable to make close psbt: %w", err)
	}
	for _, vPkt := range closeInfo.vPackets {
		err = tapsend.UpdateTaprootOutputKeys(
			coopClosePsbt, vPkt, closeInfo.outputCommitments,
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
			Pkt:       coopClosePsbt,
			ChainFees: closeInfo.closeFee,
		},
		ChainFees: closeInfo.closeFee,
		FinalTx:   closeTx,
	}
	preSignedParcel := tapfreighter.NewPreAnchoredParcel(
		closeInfo.vPackets, nil, closeAnchor,
	)
	_, err = a.cfg.TxSender.RequestShipment(preSignedParcel)
	if err != nil {
		return fmt.Errorf("error requesting delivery: %w", err)
	}

	return nil
}
