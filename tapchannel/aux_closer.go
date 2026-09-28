package tapchannel

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"sort"
	"sync"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapchannelmsg"
	"github.com/lightninglabs/taproot-assets/tapfeatures"
	"github.com/lightninglabs/taproot-assets/tapfreighter"
	"github.com/lightninglabs/taproot-assets/tapnode"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/tapscript"
	"github.com/lightninglabs/taproot-assets/tapsend"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwallet/chancloser"
	"github.com/lightningnetwork/lnd/lnwallet/types"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
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

	// AnchoringRegistrar imports funding proofs together with their re-org
	// protection.
	AnchoringRegistrar ReceiveAnchoringRegistrar

	// HeaderVerifier is used to verify headers in a proof.
	HeaderVerifier proof.HeaderVerifier

	// GroupVerifier is used to verify group keys in a proof.
	GroupVerifier proof.GroupVerifier

	// ChainBridge is used to fetch blocks from the main chain.
	ChainBridge tapnode.ChainBridge

	// IgnoreChecker is an optional function that can be used to check if
	// a proof should be ignored.
	IgnoreChecker lfn.Option[proof.IgnoreChecker]

	// AuxChanNegotiator is responsible for producing the extra tlv blob
	// that is encapsulated in the init and reestablish peer messages. This
	// helps us communicate custom feature bits with our peer.
	AuxChanNegotiator *tapfeatures.AuxChannelNegotiator

	// CloseStore persists per-channel close info across restarts. Without
	// it, a tapd restart between AuxCloseOutputs and FinalizeClose loses
	// the in-memory closeInfo and leaves the close stuck pending on the
	// lnd side. When nil, persistence is disabled (e.g., in tests that
	// don't exercise the restart path).
	CloseStore AuxCloseStore
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

	// closeFee is the fee that was paid to close the channel. With the
	// RBF close flow the fee isn't known when the close info is created,
	// so it's zero and the fee is taken from the confirmed transaction.
	closeFee int64

	// stxoFeatures are the channel's STXO features at AuxCloseOutputs
	// time. We pin them here so that FinalizeClose can take the same
	// branch even after a restart wipes the in-memory feature map on
	// AuxChannelNegotiator.
	stxoFeatures STXOFeatures

	// assetOutputs are the asset carrying outputs of the close
	// transaction this info was built for. The transaction that confirms
	// needs to carry them, at these indexes, for the asset state to
	// apply to it.
	assetOutputs []closeAssetOutput

	// templateID identifies the close template this info is, if it was
	// built for the RBF close flow, where it serves every close
	// transaction of the negotiation. Zero for the legacy close flow,
	// which builds a new info for every fee.
	templateID closeTemplateID

	// sortFunc is the sort of the close transaction outputs this info
	// was built for.
	sortFunc lnwallet.CloseSortFunc
}

// auxCloseOutputs returns the extra close outputs and the sort lnd needs to
// build the close transaction this info applies to.
func (a *assetCloseInfo) auxCloseOutputs() chancloser.AuxCloseOutputs {
	return chancloser.AuxCloseOutputs{
		ExtraCloseOutputs: fn.Map(
			a.assetOutputs,
			func(o closeAssetOutput) lnwallet.CloseOutput {
				return lnwallet.CloseOutput{
					TxOut: wire.TxOut{
						PkScript: o.pkScript,
						Value:    o.value,
					},
					IsLocal: o.isLocal,
				}
			},
		),
		CustomSort: a.sortFunc,
	}
}

// assetScripts returns the scripts of the asset carrying outputs, in order.
func (a *assetCloseInfo) assetScripts() [][]byte {
	return fn.Map(a.assetOutputs, func(o closeAssetOutput) []byte {
		return o.pkScript
	})
}

// matchesCloseTx returns true if the close transaction carries the asset
// outputs of this close info at their indexes.
func (a *assetCloseInfo) matchesCloseTx(closeTx *wire.MsgTx) bool {
	if len(a.assetOutputs) == 0 {
		return false
	}

	for _, out := range a.assetOutputs {
		if out.outputIndex >= uint32(len(closeTx.TxOut)) {
			return false
		}

		txOut := closeTx.TxOut[out.outputIndex]
		if !bytes.Equal(txOut.PkScript, out.pkScript) {
			return false
		}
	}

	return true
}

// ErrCloseTemplateChanged is returned when the close template of a channel
// is requested with other terms than the ones it was built with. The asset
// state is signed for one template per close, and a close transaction that
// carries it may still confirm, so no second template is built.
var ErrCloseTemplateChanged = errors.New("close template of channel changed")

// newCloseTemplateID returns the ID of the close template the given
// description leads to: a hash over everything the asset outputs of the
// close transaction depend on, which is the final channel state and the
// shutdown terms of both parties.
func newCloseTemplateID(
	desc types.AuxCloseTemplateDesc) (closeTemplateID, error) {

	var id closeTemplateID

	localRecords, err := canonicalShutdownRecords(
		desc.LocalShutdownRecords,
	)
	if err != nil {
		return id, fmt.Errorf("unable to serialize local shutdown "+
			"records: %w", err)
	}
	remoteRecords, err := canonicalShutdownRecords(
		desc.RemoteShutdownRecords,
	)
	if err != nil {
		return id, fmt.Errorf("unable to serialize remote shutdown "+
			"records: %w", err)
	}

	h := sha256.New()
	writeField := func(field []byte) {
		_ = binary.Write(h, binary.BigEndian, uint32(len(field)))
		_, _ = h.Write(field)
	}

	var initiator byte
	if desc.Initiator {
		initiator = 1
	}
	_, _ = h.Write([]byte{initiator})
	writeField(desc.FundingBlob.UnwrapOr(nil))
	writeField(desc.CommitBlob.UnwrapOr(nil))
	writeField(desc.LocalDeliveryScript)
	writeField(localRecords)
	writeField(desc.RemoteDeliveryScript)
	writeField(remoteRecords)

	copy(id[:], h.Sum(nil))

	return id, nil
}

// canonicalShutdownRecords serializes the shutdown records of a party in a
// form that is the same for every encoding of the same shutdown message.
// The script key record is encoded by ranging over a map, so its bytes can
// differ between two encodings, whether they stem from us or from the peer
// retransmitting its shutdown. That record is replaced with its entries
// sorted by asset ID, the other records are serialized sorted by type.
func canonicalShutdownRecords(records lnwire.CustomRecords) ([]byte, error) {
	keyRecord := tlv.ZeroRecordT[
		tapchannelmsg.ScriptKeysShutdownType,
		tapchannelmsg.ScriptKeyMap,
	]()
	keyType := uint64(keyRecord.TlvType())
	keyBlob, ok := records[keyType]
	if !ok {
		return records.Serialize()
	}

	otherRecords := make(lnwire.CustomRecords, len(records)-1)
	for recordType, value := range records {
		if recordType != keyType {
			otherRecords[recordType] = value
		}
	}
	serialized, err := otherRecords.Serialize()
	if err != nil {
		return nil, err
	}

	record := keyRecord.Record()
	err = record.Decode(bytes.NewReader(keyBlob), uint64(len(keyBlob)))
	if err != nil {
		return nil, fmt.Errorf("unable to decode script keys: %w", err)
	}

	assetIDs := make([]asset.ID, 0, len(keyRecord.Val))
	for assetID := range keyRecord.Val {
		assetIDs = append(assetIDs, assetID)
	}
	slices.SortFunc(assetIDs, func(a, b asset.ID) int {
		return bytes.Compare(a[:], b[:])
	})

	var buf bytes.Buffer
	buf.Write(serialized)
	_ = binary.Write(&buf, binary.BigEndian, keyType)
	_ = binary.Write(&buf, binary.BigEndian, uint64(len(assetIDs)))
	for _, assetID := range assetIDs {
		scriptKey := keyRecord.Val[assetID]
		buf.Write(assetID[:])
		buf.Write(scriptKey.SerializeCompressed())
	}

	return buf.Bytes(), nil
}

// existingCloseTemplate decides what an existing close info of a channel
// means for a request of the close template with the given ID: the info is
// returned if it is that template, a new template needs to be built if
// there is no info or it stems from a legacy close negotiation, and
// ErrCloseTemplateChanged is returned if the info is another template.
func existingCloseTemplate(existing *assetCloseInfo,
	templateID closeTemplateID) (*assetCloseInfo, error) {

	switch {
	case existing == nil || existing.templateID.IsZero():
		return nil, nil

	case existing.templateID == templateID:
		return existing, nil

	default:
		return nil, fmt.Errorf("%w: have %x, requested %x",
			ErrCloseTemplateChanged, existing.templateID[:],
			templateID[:])
	}
}

// settledBtcAmount returns the BTC amount a party's close output settles to
// with the legacy close negotiation, before the asset anchor amounts are
// subtracted. The channel initiator gets the commitment fee back and pays
// the close fee.
func settledBtcAmount(desc types.AuxCloseDesc, isLocal bool,
	amt btcutil.Amount) btcutil.Amount {

	if desc.Initiator == isLocal {
		amt += desc.CommitFee
		amt -= desc.CloseFee
	}

	return amt
}

// sortCloseAllocsByKey orders the close allocations independently of their
// BTC amounts: the asset allocations come first, followed by the BTC
// allocations, each ordered by their taproot key.
func sortCloseAllocsByKey(allocs []*tapsend.Allocation) {
	slices.SortStableFunc(allocs, func(a, b *tapsend.Allocation) int {
		aAssets := a.Type != tapsend.AllocationTypeNoAssets
		bAssets := b.Type != tapsend.AllocationTypeNoAssets

		switch {
		case aAssets && !bAssets:
			return -1

		case !aAssets && bAssets:
			return 1
		}

		return bytes.Compare(
			a.SortTaprootKeyBytes, b.SortTaprootKeyBytes,
		)
	})
}

// closeOutputSort returns the sort of the close transactions of an RBF close
// negotiation. The order doesn't depend on the output values, as those
// change with every fee: the asset outputs come first, in the order of the
// given scripts, followed by the BTC outputs ordered by script. A BTC output
// that lnd merged into an asset output, because the party's balance left no
// room for a separate output, is found by the asset script it carries.
func closeOutputSort(assetScripts [][]byte) func(*wire.MsgTx) error {
	rank := func(txOut *wire.TxOut) int {
		for i, script := range assetScripts {
			if bytes.Equal(txOut.PkScript, script) {
				return i
			}
		}

		return len(assetScripts)
	}

	return func(tx *wire.MsgTx) error {
		sort.Sort(sortableInputSlice(tx.TxIn))

		slices.SortStableFunc(tx.TxOut, func(a, b *wire.TxOut) int {
			return cmp.Or(
				cmp.Compare(rank(a), rank(b)),
				bytes.Compare(a.PkScript, b.PkScript),
				cmp.Compare(a.Value, b.Value),
			)
		})

		return nil
	}
}

// btcCloseAllocations returns a BTC allocation for every output of the
// confirmed close transaction that isn't one of the asset outputs of the
// close info. The exclusion proofs of the asset outputs are built from
// them. The outputs are found by the BTC internal keys of the shutdown
// records rather than by the indexes the allocations were created with, as
// with the legacy close flow the fee of the final transaction decides the
// order, and a party's BTC output may have been merged into its asset output
// altogether. A close info without asset outputs predates this record, and
// keeps its allocations as they are.
func btcCloseAllocations(closeTx *wire.MsgTx,
	closeInfo *assetCloseInfo) ([]*tapsend.Allocation, error) {

	if len(closeInfo.assetOutputs) == 0 {
		return closeInfo.allocations, nil
	}

	isAssetOutput := make(map[uint32]bool, len(closeInfo.assetOutputs))
	for _, out := range closeInfo.assetOutputs {
		isAssetOutput[out.outputIndex] = true
	}

	btcKeys := make(map[string]*btcec.PublicKey)
	for _, alloc := range closeInfo.allocations {
		if alloc.Type != tapsend.AllocationTypeNoAssets {
			continue
		}

		taprootKey := txscript.ComputeTaprootKeyNoScript(
			alloc.InternalKey,
		)
		pkScript, err := txscript.PayToTaprootScript(taprootKey)
		if err != nil {
			return nil, err
		}

		btcKeys[string(pkScript)] = alloc.InternalKey
	}

	var allocs []*tapsend.Allocation
	for idx, txOut := range closeTx.TxOut {
		if isAssetOutput[uint32(idx)] {
			continue
		}

		internalKey, ok := btcKeys[string(txOut.PkScript)]
		if !ok {
			return nil, fmt.Errorf("output %d of close tx pays "+
				"to unknown script %x", idx, txOut.PkScript)
		}

		allocs = append(allocs, &tapsend.Allocation{
			Type:        tapsend.AllocationTypeNoAssets,
			OutputIndex: uint32(idx),
			InternalKey: internalKey,
			BtcAmount:   btcutil.Amount(txOut.Value),
		})
	}

	return allocs, nil
}

// validateShutdownBtcKey makes sure the delivery script of a close output is
// a P2TR output for the BTC internal key that was sent in the shutdown
// records. The internal key is what the exclusion proofs for the output are
// built with, so a mismatch makes every proof of the close invalid.
func validateShutdownBtcKey(pkScript []byte,
	shutdownMsg tapchannelmsg.AuxShutdownMsg) error {

	if !txscript.IsPayToTaproot(pkScript) {
		return fmt.Errorf("delivery script %x is not P2TR", pkScript)
	}

	internalKey := shutdownMsg.BtcInternalKey.Val
	if internalKey == nil {
		return fmt.Errorf("shutdown records carry no BTC internal key")
	}

	taprootKey := txscript.ComputeTaprootKeyNoScript(internalKey)
	expectedScript, err := txscript.PayToTaprootScript(taprootKey)
	if err != nil {
		return err
	}

	if !bytes.Equal(expectedScript, pkScript) {
		return fmt.Errorf("delivery script %x doesn't match BTC "+
			"internal key %x of shutdown records", pkScript,
			internalKey.SerializeCompressed())
	}

	return nil
}

// AuxChanCloser is used to implement asset-aware co-op close for channels.
type AuxChanCloser struct {
	startOnce sync.Once
	stopOnce  sync.Once

	cfg AuxChanCloserCfg

	sync.RWMutex

	// closeInfo holds the close info per channel.
	closeInfo map[wire.OutPoint]*assetCloseInfo

	// ContextGuard provides a wait group and main quit channel that can
	// be used to create guarded contexts.
	*fn.ContextGuard
}

// NewAuxChanCloser creates a new instance of the auxiliary channel closer.
func NewAuxChanCloser(cfg AuxChanCloserCfg) *AuxChanCloser {
	return &AuxChanCloser{
		cfg:       cfg,
		closeInfo: make(map[wire.OutPoint]*assetCloseInfo),
		ContextGuard: &fn.ContextGuard{
			DefaultTimeout: DefaultTimeout,
			Quit:           make(chan struct{}),
		},
	}
}

// auxOpCtx returns a context bounded by the default aux-hook timeout. Used
// for short-lived I/O (close-info DB calls, recovery pipeline) where the
// LND-side AuxChanCloser interface doesn't pass a context through.
func auxOpCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), DefaultTimeout)
}

// Start attempts to start the auxiliary channel closer.
func (a *AuxChanCloser) Start() error {
	var startErr error
	a.startOnce.Do(func() {
		log.Info("Starting aux chan closer")
	})
	return startErr
}

// Stop signals for the auxiliary channel closer to gracefully exit.
func (a *AuxChanCloser) Stop() error {
	var stopErr error
	a.stopOnce.Do(func() {
		log.Info("Stopping aux chan closer")

		close(a.Quit)
		a.Wg.Wait()
	})

	return stopErr
}

// createCloseAlloc is a helper function that creates an allocation for an asset
// close. This does not set a script key, as the script key will be set for each
// packet after the coins have been distributed.
func createCloseAlloc(isLocal, isInitiator bool, outputSum uint64,
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
		SplitRoot:            isInitiator,
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

// AuxCloseShape returns the fee-independent shape of the auxiliary close
// outputs: one P2TR asset output per party with a non-zero asset balance.
// The close fee only affects the values of these outputs, never their number
// or script sizes.
//
// NOTE: This method is part of the chancloser.AuxChanCloser interface.
func (a *AuxChanCloser) AuxCloseShape(
	desc types.AuxCloseShapeDesc) (lfn.Option[chancloser.AuxCloseShape],
	error) {

	none := lfn.None[chancloser.AuxCloseShape]()

	// If there's no commit blob present, there are no assets in the
	// channel, and no auxiliary outputs on the close transaction.
	if desc.CommitBlob.IsNone() {
		return none, nil
	}

	commitState, err := tapchannelmsg.DecodeCommitment(
		desc.CommitBlob.UnwrapOr(nil),
	)
	if err != nil {
		return none, err
	}

	sumAmounts := func(accu uint64, o *tapchannelmsg.AssetOutput) uint64 {
		return accu + o.Amount.Val
	}
	localSum := fn.Reduce(commitState.LocalAssets.Val.Outputs, sumAmounts)
	remoteSum := fn.Reduce(
		commitState.RemoteAssets.Val.Outputs, sumAmounts,
	)

	var outputs []chancloser.AuxCloseOutputShape
	if localSum > 0 {
		outputs = append(outputs, chancloser.AuxCloseOutputShape{
			IsLocal:      true,
			PkScriptSize: input.P2TRSize,
		})
	}
	if remoteSum > 0 {
		outputs = append(outputs, chancloser.AuxCloseOutputShape{
			IsLocal:      false,
			PkScriptSize: input.P2TRSize,
		})
	}

	return lfn.Some(chancloser.AuxCloseShape{Outputs: outputs}), nil
}

// AuxCloseOutputs returns the set of close outputs to use for this co-op close
// attempt of the legacy close negotiation. We'll add some extra outputs to the
// co-op close transaction, and also give the caller a custom sorting routine.
// The negotiation asks anew for every fee, as the fee decides the order of
// the outputs, so the close info of the channel is replaced each time.
//
// NOTE: This method is part of the chancloser.AuxChanCloser interface.
func (a *AuxChanCloser) AuxCloseOutputs(
	desc types.AuxCloseDesc) (lfn.Option[chancloser.AuxCloseOutputs],
	error) {

	a.Lock()
	defer a.Unlock()

	none := lfn.None[chancloser.AuxCloseOutputs]()

	// If there's no commit blob present, then we don't need to do
	// anything, as there aren't any assets in the channel.
	if desc.CommitBlob.IsNone() {
		return none, nil
	}

	closeInfo, pristineVPackets, err := a.buildCloseInfo(desc, false)
	if err != nil {
		return none, err
	}

	if err := a.storeCloseInfo(
		desc.ChanPoint, closeInfo, pristineVPackets,
	); err != nil {
		return none, err
	}

	return lfn.Some(closeInfo.auxCloseOutputs()), nil
}

// AuxCloseTemplate returns the asset outputs every close transaction of an
// RBF close negotiation carries, along with the sort of those transactions.
// The outputs are built once per close of the channel and reused for every
// request with the same terms, which is what a shutdown exchanged again
// after a reconnect or a restart leads to. A request with other terms fails,
// as a close transaction carrying the outputs built first may still confirm.
//
// NOTE: This method is part of the chancloser.AuxChanCloser interface.
func (a *AuxChanCloser) AuxCloseTemplate(
	desc types.AuxCloseTemplateDesc) (
	lfn.Option[chancloser.AuxCloseOutputs], error) {

	a.Lock()
	defer a.Unlock()

	none := lfn.None[chancloser.AuxCloseOutputs]()

	// If there's no commit blob present, then we don't need to do
	// anything, as there aren't any assets in the channel.
	if desc.CommitBlob.IsNone() {
		return none, nil
	}

	templateID, err := newCloseTemplateID(desc)
	if err != nil {
		return none, err
	}

	existing, err := a.currentCloseInfo(desc.ChanPoint)
	if err != nil {
		return none, err
	}
	template, err := existingCloseTemplate(existing, templateID)
	if err != nil {
		return none, err
	}
	if template != nil {
		log.Infof("Reusing close template %x for ChannelPoint(%v)",
			templateID[:], desc.ChanPoint)

		return lfn.Some(template.auxCloseOutputs()), nil
	}

	// The asset outputs don't depend on the amounts of the settled
	// outputs, as lnd only signs a close transaction that keeps them.
	closeDesc := types.AuxCloseDesc{
		AuxShutdownReq: desc.AuxShutdownReq,
		LocalCloseOutput: lfn.Some(types.CloseOutput{
			PkScript:        desc.LocalDeliveryScript,
			ShutdownRecords: desc.LocalShutdownRecords,
		}),
		RemoteCloseOutput: lfn.Some(types.CloseOutput{
			PkScript:        desc.RemoteDeliveryScript,
			ShutdownRecords: desc.RemoteShutdownRecords,
		}),
	}
	closeInfo, pristineVPackets, err := a.buildCloseInfo(closeDesc, true)
	if err != nil {
		return none, err
	}
	closeInfo.templateID = templateID

	if err := a.storeCloseInfo(
		desc.ChanPoint, closeInfo, pristineVPackets,
	); err != nil {
		return none, err
	}

	log.Infof("Built close template %x for ChannelPoint(%v)",
		templateID[:], desc.ChanPoint)

	return lfn.Some(closeInfo.auxCloseOutputs()), nil
}

// buildCloseInfo builds the asset outputs of the co-op close transaction and
// the asset state that goes with them. With a fixed order, the outputs are
// ordered by their keys alone, so the order holds for every fee of an RBF
// close negotiation. Otherwise the order follows the BTC amounts of the
// close outputs, the way the legacy close negotiation sorts them. The
// pristine virtual packets are returned alongside, for the close info to be
// persisted.
func (a *AuxChanCloser) buildCloseInfo(desc types.AuxCloseDesc,
	fixedOrder bool) (*assetCloseInfo, []*tappsbt.VPacket, error) {

	log.Infof("Constructing aux close options for ChannelPoint(%v): ",
		desc.ChanPoint)

	// Otherwise, we'll decode the commit blob, and the funding blob.
	commitState, err := tapchannelmsg.DecodeCommitment(
		desc.CommitBlob.UnwrapOr(nil),
	)
	if err != nil {
		return nil, nil, err
	}
	fundingInfo, err := tapchannelmsg.DecodeOpenChannel(
		desc.FundingBlob.UnwrapOr(nil),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("unable decode channel asset "+
			"state: %w", err)
	}

	ctxb := context.Background()

	// Each of the co-op close outputs needs to ref a funding input, so
	// we'll map a map of asset ID to the funding output now.
	inputProofs := make(
		[]*proof.Proof, 0, len(fundingInfo.FundedAssets.Val.Outputs),
	)
	for _, fundingInput := range fundingInfo.FundedAssets.Val.Outputs {
		inputProofs = append(inputProofs, &fundingInput.Proof.Val)
	}

	err = updateProofsFromShortChanID(
		ctxb, a.cfg.ChainBridge, desc.ShortChanID, inputProofs,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to update funding "+
			"proofs: %w", err)
	}

	// We'll also decode the shutdown blobs, so we can extract the shutdown
	// information (delivery script keys, etc.).
	var localShutdown, remoteShutdown tapchannelmsg.AuxShutdownMsg
	err = lfn.MapOptionZ(
		desc.LocalCloseOutput, func(o types.CloseOutput) error {
			blob, err := o.ShutdownRecords.Serialize()
			if err != nil {
				return err
			}

			return localShutdown.Decode(bytes.NewReader(blob))
		},
	)
	if err != nil {
		return nil, nil, err
	}
	err = lfn.MapOptionZ(
		desc.RemoteCloseOutput, func(o types.CloseOutput) error {
			blob, err := o.ShutdownRecords.Serialize()
			if err != nil {
				return err
			}

			return remoteShutdown.Decode(bytes.NewReader(blob))
		},
	)
	if err != nil {
		return nil, nil, err
	}

	log.Tracef("Decoded local_shutdown=%v, remote_shutdown=%v",
		limitSpewer.Sdump(localShutdown),
		limitSpewer.Sdump(remoteShutdown))

	// The BTC outputs of both parties need to match the internal keys
	// sent in the shutdown records, as those keys are what the exclusion
	// proofs of the close are built with.
	err = lfn.MapOptionZ(
		desc.LocalCloseOutput, func(o types.CloseOutput) error {
			return validateShutdownBtcKey(o.PkScript, localShutdown)
		},
	)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid local close output: %w",
			err)
	}
	err = lfn.MapOptionZ(
		desc.RemoteCloseOutput, func(o types.CloseOutput) error {
			return validateShutdownBtcKey(
				o.PkScript, remoteShutdown,
			)
		},
	)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid remote close output: %w",
			err)
	}

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
			true, desc.Initiator, localSum, localShutdown,
		)
		if err != nil {
			return nil, nil, err
		}

		localAssetAnchorAmt += localAlloc.BtcAmount

		closeAllocs = append(closeAllocs, localAlloc)
	}
	if remoteSum > 0 {
		remoteAlloc, err = createCloseAlloc(
			false, !desc.Initiator, remoteSum, remoteShutdown,
		)
		if err != nil {
			return nil, nil, err
		}

		remoteAssetAnchorAmt += remoteAlloc.BtcAmount

		closeAllocs = append(closeAllocs, remoteAlloc)
	}

	// Next, we'll create allocations for the (up to) two settled outputs
	// in the co-op close transaction. With a fixed order the amounts
	// play no part: the outputs serve every close transaction of the
	// negotiation, whatever its fee, and lnd refuses a fee that would
	// merge or drop a settled output. Otherwise, we mirror the amounts
	// of the close transaction so the allocations sort the way lnd sorts
	// the outputs.
	addBtcAlloc := func(o types.CloseOutput, isLocal bool,
		assetAlloc *tapsend.Allocation, anchorAmt btcutil.Amount,
		shutdown tapchannelmsg.AuxShutdownMsg) {

		// Snip off the first two bytes, as we'll be getting a P2TR
		// output from the higher level. We want a raw pubkey here.
		sortScript := o.PkScript[2:]
		btcAlloc := &tapsend.Allocation{
			Type:                tapsend.AllocationTypeNoAssets,
			SortTaprootKeyBytes: sortScript,
			InternalKey:         shutdown.BtcInternalKey.Val,
		}

		if fixedOrder {
			closeAllocs = append(closeAllocs, btcAlloc)

			return
		}

		btcAmt := settledBtcAmount(desc, isLocal, o.Amt)
		amtAfterAnchor := btcAmt - anchorAmt

		// If we can't have a non-dust output after subtracting the
		// anchor amt, then we'll just drop this allocation, and modify
		// the asset allocation to match this value.
		if amtAfterAnchor <= o.DustLimit {
			if assetAlloc != nil {
				assetAlloc.BtcAmount = btcAmt
			}

			return
		}

		btcAlloc.BtcAmount = amtAfterAnchor
		closeAllocs = append(closeAllocs, btcAlloc)
	}
	desc.LocalCloseOutput.WhenSome(func(o types.CloseOutput) {
		addBtcAlloc(
			o, true, localAlloc, localAssetAnchorAmt, localShutdown,
		)
	})
	desc.RemoteCloseOutput.WhenSome(func(o types.CloseOutput) {
		addBtcAlloc(
			o, false, remoteAlloc, remoteAssetAnchorAmt,
			remoteShutdown,
		)
	})

	log.Infof("Allocations for co-op close txn: %v",
		limitSpewer.Sdump(closeAllocs))

	// With all allocations created, we now sort them to ensure that we
	// have a stable and deterministic order that both parties can arrive
	// at. We then assign the output indexes according to that order. The
	// RBF close flow needs an order that doesn't depend on the amounts,
	// as the asset outputs are signed for their indexes once, for every
	// fee of the negotiation.
	if fixedOrder {
		sortCloseAllocsByKey(closeAllocs)
	} else {
		tapsend.InPlaceAllocationSort(closeAllocs)
	}
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
		return nil, nil, fmt.Errorf("unable to create vPackets: %w",
			err)
	}

	// Snapshot a pristine deep copy of the vPackets before any of the
	// downstream mutations (signCommitVirtualPackets,
	// CreateOutputCommitments) so we can persist them for restart-time
	// recovery. The persisted copies are the inputs we'll feed back
	// through the same pipeline at FinalizeClose time to reproduce the
	// post-mutation vPackets + outputCommitments deterministically.
	pristineVPackets := make([]*tappsbt.VPacket, len(vPackets))
	for i, p := range vPackets {
		pristineVPackets[i] = p.Copy()
	}

	// We can now add the witness for the OP_TRUE spend of the commitment
	// output to the vPackets.
	if err := signCommitVirtualPackets(ctxb, vPackets); err != nil {
		return nil, nil, fmt.Errorf("error signing commit virtual "+
			"packets: %w", err)
	}

	features := a.cfg.AuxChanNegotiator.GetChannelFeatures(
		lnwire.NewChanIDFromOutPoint(desc.ChanPoint),
	)
	stxoFeatures := NewSTXOFeatures(features)
	opts := stxoFeatures.CommitOpts()

	// With the outputs prepared, we can now create the set of output
	// commitments, then with the output index locations known, we can set
	// the output indexes in the allocations.
	outCommitments, err := tapsend.CreateOutputCommitments(
		vPackets, opts...,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create output "+
			"commitments: %w", err)
	}
	err = tapsend.AssignOutputCommitments(closeAllocs, outCommitments)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to assign alloc output "+
			"commitments: %w", err)
	}

	// With the taproot keys updated, we know the pkScripts of the asset
	// outputs.
	var assetOutputs []closeAssetOutput
	assetAllocations := fn.Filter(closeAllocs, tapsend.FilterByTypeExclude(
		tapsend.AllocationTypeNoAssets,
	))
	for _, alloc := range assetAllocations {
		pkScript, err := alloc.FinalPkScript()
		if err != nil {
			return nil, nil, fmt.Errorf("unable to make final "+
				"pkScript: %w", err)
		}

		isLocal := alloc.Type == tapsend.CommitAllocationToLocal
		assetOutputs = append(assetOutputs, closeAssetOutput{
			outputIndex: alloc.OutputIndex,
			pkScript:    pkScript,
			value:       int64(alloc.BtcAmount),
			isLocal:     isLocal,
		})
	}

	closeInfo := &assetCloseInfo{
		allocations:       closeAllocs,
		vPackets:          vPackets,
		outputCommitments: outCommitments,
		closeFee:          int64(desc.CloseFee),
		stxoFeatures:      stxoFeatures,
		assetOutputs:      assetOutputs,
	}

	// As a final step, we'll craft a custom sorting function for the co-op
	// close txn. With a fixed order it sorts by script alone, so the
	// order holds for every fee of the negotiation.
	closeInfo.sortFunc = func(tx *wire.MsgTx) error {
		cltvs := make([]uint32, len(closeAllocs))
		htlcIndexes := make([]input.HtlcIndex, len(closeAllocs))
		return InPlaceCustomCommitSort(
			tx, cltvs, htlcIndexes, closeAllocs,
		)
	}
	if fixedOrder {
		closeInfo.sortFunc = closeOutputSort(closeInfo.assetScripts())
	}

	return closeInfo, pristineVPackets, nil
}

// ShutdownBlob returns the set of custom records that should be included in
// the shutdown message.
//
// NOTE: This method is part of the chancloser.AuxChanCloser interface.
func (a *AuxChanCloser) ShutdownBlob(
	req types.AuxShutdownReq) (lfn.Option[lnwire.CustomRecords],
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

	// A shutdown that is sent again for the channel, after a reconnect
	// or a restart, carries the keys of the first one: the asset outputs
	// of the close commit to them, and the close template built for the
	// negotiation only holds as long as they don't change.
	chanClose, err := a.loadChanClose(req.ChanPoint)
	if err != nil {
		return none, err
	}
	if chanClose.shutdownMsg != nil {
		log.Infof("Reusing shutdown record of ChannelPoint(%v)",
			req.ChanPoint)

		shutdownRecord := *chanClose.shutdownMsg
		shutdownRecord.BtcInternalKey.Val = &btcInternalKey

		records, err := tlv.RecordsToMap(
			shutdownRecord.EncodeRecords(),
		)
		if err != nil {
			return none, err
		}

		return lfn.Some[lnwire.CustomRecords](records), nil
	}

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

	err = a.updateChanClose(
		req.ChanPoint, func(chanClose *persistedChanClose) {
			chanClose.shutdownMsg = shutdownRecord
		},
	)
	if err != nil {
		return none, fmt.Errorf("persist shutdown record: %w", err)
	}

	log.Infof("Constructed shutdown record: %v", limitSpewer.Sdump(records))

	return lfn.Some[lnwire.CustomRecords](records), nil
}

// SupportsRbfClose returns true if the channel can be closed with lnd's RBF
// co-op close flow with the given peer. That's the case if the peer signalled
// the feature in its init message, which means it drives its aux closer hooks
// from within the RBF flow as well.
//
// NOTE: This method is part of the chancloser.AuxChanCloser interface.
func (a *AuxChanCloser) SupportsRbfClose(chanID lnwire.ChannelID,
	peer route.Vertex) bool {

	features := a.cfg.AuxChanNegotiator.GetPeerFeatures(peer)
	supported := features.HasFeature(tapfeatures.RbfCoopCloseOptional)

	log.Debugf("RBF co-op close for channel %v with peer %x "+
		"supported=%v", chanID, peer[:], supported)

	return supported
}

// shipChannelTxn takes a channel transaction, an output commitment, and the
// set of vPackets used to make the output commitment and ships a complete
// pre-signed package off to the porter. This'll insert a transfer for the
// channel, send the final transaction to the network, and update any
// transition proofs once a confirmation occurs.
func shipChannelTxn(txSender tapfreighter.Porter, chanTx *wire.MsgTx,
	outputCommitments tappsbt.OutputCommitments,
	vPkts []*tappsbt.VPacket, closeFee int64,
	anchorTxHeightHint fn.Option[uint32]) error {

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
	parcelLabel := fmt.Sprintf("channel-tx-%s", chanTx.TxHash().String())

	// Broadcast (and rebroadcast) of channel transactions is always owned
	// by lnd: the channel peer flow for cooperative closes, the channel
	// arbitrator for commitment transactions (which are only ever shipped
	// here after they confirmed), and the sweeper for force-close sweeps.
	// The porter therefore only records the transfer and watches for its
	// confirmation. Publishing here as well would race lnd's own
	// bookkeeping and, worse, a replaced or conflicted sweep version
	// would fail the porter's broadcast and strand the transfer.
	preSignedParcel := tapfreighter.NewPreAnchoredParcel(
		vPkts, nil, closeAnchor, true, parcelLabel,
		anchorTxHeightHint,
	)
	_, err = txSender.RequestShipment(preSignedParcel)
	if err != nil {
		return fmt.Errorf("error requesting delivery: %w", err)
	}

	return nil
}

// loadChanClose returns the persisted close state of the channel, or an
// empty one if there is none or no store is configured.
func (a *AuxChanCloser) loadChanClose(
	chanPoint wire.OutPoint) (*persistedChanClose, error) {

	if a.cfg.CloseStore == nil {
		return &persistedChanClose{}, nil
	}

	ctx, cancel := auxOpCtx()
	defer cancel()

	chanClose, err := a.cfg.CloseStore.Get(ctx, chanPoint)
	switch {
	case errors.Is(err, ErrNoAuxCloseInfo):
		return &persistedChanClose{}, nil

	case err != nil:
		return nil, fmt.Errorf("load persisted close info: %w", err)
	}

	return chanClose, nil
}

// updateChanClose applies the given update to the persisted close state of
// the channel. Without a store, nothing is persisted and the only
// consequence is that the state doesn't survive a restart.
func (a *AuxChanCloser) updateChanClose(chanPoint wire.OutPoint,
	update func(*persistedChanClose)) error {

	if a.cfg.CloseStore == nil {
		return nil
	}

	chanClose, err := a.loadChanClose(chanPoint)
	if err != nil {
		return err
	}

	update(chanClose)

	ctx, cancel := auxOpCtx()
	defer cancel()

	return a.cfg.CloseStore.Put(ctx, chanPoint, chanClose)
}

// storeCloseInfo makes the given close info the one of the channel, in
// memory and on disk, so a tapd restart between now and the on-chain close
// confirmation (which is when FinalizeClose will run via the chain watcher)
// doesn't strand the channel in a pending state.
func (a *AuxChanCloser) storeCloseInfo(chanPoint wire.OutPoint,
	closeInfo *assetCloseInfo, pristineVPackets []*tappsbt.VPacket) error {

	err := a.updateChanClose(
		chanPoint, func(chanClose *persistedChanClose) {
			chanClose.closeInfo = &persistedCloseInfo{
				vPackets:         closeInfo.vPackets,
				pristineVPackets: pristineVPackets,
				noAssetAllocs: extractNoAssetAllocs(
					closeInfo.allocations,
				),
				assetOutputs: closeInfo.assetOutputs,
				closeFee:     closeInfo.closeFee,
				stxoFeatures: closeInfo.stxoFeatures,
				templateID:   closeInfo.templateID,
			}
		},
	)
	if err != nil {
		return fmt.Errorf("persist aux close info: %w", err)
	}

	a.closeInfo[chanPoint] = closeInfo

	return nil
}

// currentCloseInfo returns the close info of the channel, from memory or,
// after a restart, recovered from the persisted close state. Nil if there
// is none.
func (a *AuxChanCloser) currentCloseInfo(
	chanPoint wire.OutPoint) (*assetCloseInfo, error) {

	if closeInfo, ok := a.closeInfo[chanPoint]; ok {
		return closeInfo, nil
	}

	chanClose, err := a.loadChanClose(chanPoint)
	if err != nil {
		return nil, err
	}
	if chanClose.closeInfo == nil {
		return nil, nil
	}

	closeInfo, err := recoverCloseInfo(chanClose.closeInfo)
	if err != nil {
		return nil, err
	}

	a.closeInfo[chanPoint] = closeInfo

	return closeInfo, nil
}

// recoverCloseInfo reconstructs the close info of a channel from the
// persisted snapshot written by storeCloseInfo. The post-mutation vPackets
// are used directly; the pristine vPackets are fed through the same pipeline
// (signCommitVirtualPackets + CreateOutputCommitments) to rebuild the output
// commitments map without disturbing the post-mutation state.
func recoverCloseInfo(saved *persistedCloseInfo) (*assetCloseInfo, error) {
	ctx, cancel := auxOpCtx()
	defer cancel()

	// Replay the pristine vPackets through the same pipeline that
	// originally produced the output commitments. We work on the pristine
	// copies, never on saved.vPackets, because the latter are already in
	// the post-mutation state and another pass through
	// CreateOutputCommitments would double-append STXO leaves.
	if err := signCommitVirtualPackets(
		ctx, saved.pristineVPackets,
	); err != nil {
		return nil, fmt.Errorf("sign commit virtual packets: %w", err)
	}

	// Use the STXO features captured when the close info was built, not
	// whatever the (in-memory, post-restart-empty) negotiator currently
	// reports.
	opts := saved.stxoFeatures.CommitOpts()

	outCommitments, err := tapsend.CreateOutputCommitments(
		saved.pristineVPackets, opts...,
	)
	if err != nil {
		return nil, fmt.Errorf("create output commitments: %w", err)
	}

	closeInfo := &assetCloseInfo{
		allocations:       allocsFromNoAssetAllocs(saved.noAssetAllocs),
		vPackets:          saved.vPackets,
		outputCommitments: outCommitments,
		closeFee:          saved.closeFee,
		stxoFeatures:      saved.stxoFeatures,
		assetOutputs:      saved.assetOutputs,
		templateID:        saved.templateID,
	}

	// Only a close template is ever asked for again after a restart, and
	// its sort is by script alone.
	closeInfo.sortFunc = closeOutputSort(closeInfo.assetScripts())

	return closeInfo, nil
}

// FinalizeClose is called once the co-op close transaction has been agreed
// upon. We'll finalize the exclusion proofs, then send things off to the
// custodian or porter to finish sending/receiving the proofs.
//
// NOTE: This method is part of the types.AuxChanCloser interface.
func (a *AuxChanCloser) FinalizeClose(desc types.AuxCloseDesc,
	closeTx *wire.MsgTx) error {

	a.Lock()
	defer a.Unlock()

	// Ignore non-asset channels.
	if desc.CommitBlob.IsNone() {
		return nil
	}

	// The close info is in memory, or, if tapd was restarted between
	// building it and the on-chain close confirmation, recovered from the
	// persisted close state.
	closeInfo, err := a.currentCloseInfo(desc.ChanPoint)
	if err != nil {
		return fmt.Errorf("unable to load close info of "+
			"ChannelPoint(%v): %w", desc.ChanPoint, err)
	}
	if closeInfo == nil {
		return fmt.Errorf("no close info found for ChannelPoint(%v)",
			desc.ChanPoint)
	}

	// The asset state only applies to the close transaction it was
	// built for, which carries the asset outputs at their indexes. A
	// close info written before the asset outputs were recorded can't be
	// checked.
	if len(closeInfo.assetOutputs) > 0 &&
		!closeInfo.matchesCloseTx(closeTx) {

		return fmt.Errorf("close tx %v of ChannelPoint(%v) doesn't "+
			"carry the asset outputs of the close info",
			closeTx.TxHash(), desc.ChanPoint)
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
		quitCtx, quitCancel := a.WithCtxQuitNoTimeout()
		defer quitCancel()
		ctx, progress, cancel := contextWithProgressDeadline(
			quitCtx, fundingProvenanceIdleTimeout,
			fundingProvenanceMaxTimeout,
		)
		ctx = proof.WithProgressCallback(ctx, progress)

		a.Wg.Add(1)
		defer a.Wg.Done()

		err = importOutputProofs(
			ctx, desc.ShortChanID, fundingInputProofs,
			a.cfg.DefaultCourierAddr, a.cfg.ProofFetcher,
			a.cfg.ChainBridge, a.cfg.ProofArchive,
			a.cfg.AnchoringRegistrar,
		)
		cause := context.Cause(ctx)
		cancel()
		if err != nil {
			if cause != nil && !errors.Is(cause, context.Canceled) {
				return fmt.Errorf("unable to import output "+
					"proofs: %w", cause)
			}

			return fmt.Errorf("unable to import output "+
				"proofs: %w", err)
		}
		if cause != nil {
			return fmt.Errorf("unable to import output proofs: %w",
				cause)
		}
	}

	log.Infof("Finalizing close for ChannelPoint(%v): ", desc.ChanPoint)

	defer delete(a.closeInfo, desc.ChanPoint)

	// The BTC outputs of the confirmed transaction are what the exclusion
	// proofs of the asset outputs are built against.
	btcAllocs, err := btcCloseAllocations(closeTx, closeInfo)
	if err != nil {
		return fmt.Errorf("unable to match close tx outputs: %w", err)
	}

	// The close fee is known once the transaction is, which is what lnd
	// reports it from. The fee recorded with the close info is what the
	// legacy close flow negotiated.
	closeFee := closeInfo.closeFee
	if desc.CloseFee > 0 {
		closeFee = int64(desc.CloseFee)
	}

	// With the co-op close transaction known, we have the information we
	// need to create the proof suffixes for each relevant close output.
	for idx := range closeInfo.vPackets {
		vPkt := closeInfo.vPackets[idx]
		for outIdx := range vPkt.Outputs {
			exclusionCreator := tapsend.NonAssetExclusionProofs(
				btcAllocs,
			)

			// Prefer the STXO features pinned on closeInfo at
			// AuxCloseOutputs time over a fresh negotiator
			// query: after a restart the in-memory feature map
			// is empty and would silently flip the proof shape.
			opts := closeInfo.stxoFeatures.ProofOpts()

			proofSuffix, err := tapsend.CreateProofSuffixCustom(
				closeTx, vPkt, closeInfo.outputCommitments,
				outIdx, closeInfo.vPackets, exclusionCreator,
				opts...,
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
	// relevant set of proofs. For co-op close, no height hint is needed
	// as the transaction is being broadcast now.
	err = shipChannelTxn(
		a.cfg.TxSender, closeTx, closeInfo.outputCommitments,
		closeInfo.vPackets, closeFee, fn.None[uint32](),
	)
	if err != nil {
		return err
	}

	// Only drop the persisted close state once the close has actually
	// been finalized. A transient failure above must leave the row in
	// place so that a retry (possibly after a restart) can still recover.
	if a.cfg.CloseStore != nil {
		delCtx, cancel := auxOpCtx()
		defer cancel()
		if err := a.cfg.CloseStore.Delete(
			delCtx, desc.ChanPoint,
		); err != nil {
			log.Warnf("unable to delete persisted aux close "+
				"info for ChannelPoint(%v): %v",
				desc.ChanPoint, err)
		}
	}

	return nil
}
