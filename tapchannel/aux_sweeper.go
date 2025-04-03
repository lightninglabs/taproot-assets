package tapchannel

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"net/url"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapchannelmsg"
	cmsg "github.com/lightninglabs/taproot-assets/tapchannelmsg"
	"github.com/lightninglabs/taproot-assets/tapfreighter"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/tapscript"
	"github.com/lightninglabs/taproot-assets/tapsend"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/sweep"
	"github.com/lightningnetwork/lnd/tlv"
	"golang.org/x/exp/maps"
)

const (
	// sweeperBudgetMultiplier is the multiplier used to determine the
	// budget expressed in sats, report to lnd's sweeper. As we have small
	// outputs on chain, we'll need an increased budget (the amount we
	// should spend on fees) to make sure the outputs are always swept.
	sweeperBudgetMultiplier = 20
)

// resolutionReq carries a request to resolve a contract output along with a
// response channel of the result.
type resolutionReq struct {
	// req is the resolution request that we'll use to resolve the
	// contract.
	req lnwallet.ResolutionReq

	// resp is the channel that we'll use to send the result of the
	// resolution.
	resp chan lfn.Result[tlv.Blob]
}

// sweepAddrReq is a request to sweep a set of inputs to a specified address.
type sweepAddrReq struct {
	// inputs is the set of inputs to be swept.
	inputs []input.Input

	// change is the addr that the sweeper will use for the non-asset
	// funds. This includes an internal key so we can generate an exclusion
	// proof for the sweep transaction.
	change lnwallet.AddrWithKey

	// resp is the channel that we'll use to send the result of the sweep.
	resp chan lfn.Result[sweep.SweepOutput]
}

// broadcastReq is used by the sweeper to notify us of a transaction broadcast.
type broadcastReq struct {
	// req holds the sweep request that includes the set of inputs to be
	// swept.
	req *sweep.BumpRequest

	// tx is the transaction to be broadcast.
	tx *wire.MsgTx

	// fee is the fee that was used for the transaction.
	fee btcutil.Amount

	// outpointToTxIndex maps a spent outpoint to the tx index on the sweep
	// transaction of the corresponding output. This is only needed to make
	// sure we make proofs properly for the pre-signed HTLC transactions.
	outpointToTxIndex map[wire.OutPoint]int

	// resp is the error result of the broadcast.
	resp chan error
}

// AuxSweeperCfg holds the configuration for the AuxSweeper.
type AuxSweeperCfg struct {
	// AddrBook is the address book that the signer will use to generate
	// new script and internal keys for sweeping purposes.
	AddrBook *address.Book

	// ChainParams are the chain parameters of the network the signer is
	// operating on.
	ChainParams address.ChainParams

	// Signer is the backing wallet that can sign virtual packets.
	Signer VirtualPacketSigner

	// TxSender is what we'll use to broadcast a transaction to the
	// network, while ensuring we also update all our asset and UTXO state
	// on disk (insert a proper transfer, etc., etc.).
	TxSender tapfreighter.Porter

	// DefaultCourierAddr is the default address the funding controller uses
	// to deliver the funding output proofs to the channel peer.
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

// AuxSweeper is used to sweep funds from a commitment transaction that has
// been broadcast on chain (a force close). This subsystem interacts with the
// contract resolution and sweeping subsystems of lnd.
type AuxSweeper struct {
	started atomic.Bool
	stopped atomic.Bool

	resolutionReqs chan *resolutionReq
	sweepAddrReqs  chan *sweepAddrReq
	broadcastReqs  chan *broadcastReq

	cfg *AuxSweeperCfg

	quit chan struct{}
	wg   sync.WaitGroup
}

// NewAuxSweeper creates a new instance of the AuxSweeper from the specified
// config.
func NewAuxSweeper(cfg *AuxSweeperCfg) *AuxSweeper {
	return &AuxSweeper{
		resolutionReqs: make(chan *resolutionReq),
		sweepAddrReqs:  make(chan *sweepAddrReq),
		broadcastReqs:  make(chan *broadcastReq),
		cfg:            cfg,
		quit:           make(chan struct{}),
	}
}

// Start starts the AuxSweeper.
func (a *AuxSweeper) Start() error {
	if !a.started.CompareAndSwap(false, true) {
		return nil
	}

	log.Infof("Starting AuxSweeper")

	a.wg.Add(1)
	go a.contractResolver()

	return nil
}

// Stop stops the AuxSweeper.
func (a *AuxSweeper) Stop() error {
	if !a.stopped.CompareAndSwap(true, false) {
		return nil
	}

	log.Infof("Stopping AuxSweeper")

	close(a.quit)
	a.wg.Wait()

	return nil
}

// createSweepVpackets creates vPackets that sweep the funds from the specified
// set of asset inputs into the backing wallet.
func (a *AuxSweeper) createSweepVpackets(sweepInputs []*cmsg.AssetOutput,
	tapscriptDesc lfn.Result[tapscriptSweepDesc],
	resReq lnwallet.ResolutionReq) lfn.Result[[]*tappsbt.VPacket] {

	type returnType = []*tappsbt.VPacket

	log.Infof("Creating sweep packets for %v inputs", len(sweepInputs))

	// Unpack the tapscript desc, as we need it to be able to continue
	// forward.
	sweepDesc, err := tapscriptDesc.Unpack()
	if err != nil {
		return lfn.Err[returnType](err)
	}

	allocs := make([]*tapsend.Allocation, 0, len(sweepInputs))
	ctx := context.Background()

	// If this is a second level HTLC sweep, then we already have
	// the output information locked in, as this was a pre-signed
	// transaction.
	if sweepDesc.auxSigInfo.IsSome() {
		var cltvTimeout fn.Option[uint32]
		sweepDesc.absoluteDelay.WhenSome(func(delay uint64) {
			cltvTimeout = fn.Some(uint32(delay))
		})

		htlcIndex := resReq.HtlcID.UnwrapOr(math.MaxUint64)
		alloc, err := createSecondLevelHtlcAllocations(
			resReq.ChanType, resReq.Initiator, sweepInputs,
			resReq.HtlcAmt, resReq.CommitCsvDelay, *resReq.KeyRing,
			fn.Some(resReq.ContractPoint.Index), cltvTimeout,
			htlcIndex,
		)
		if err != nil {
			return lfn.Err[returnType](err)
		}

		allocs = append(allocs, alloc...)
	} else {
		// Otherwise, for each out we want to sweep, we'll construct an
		// allocation that we'll use to deliver the funds back to the
		// wallet.
		sweepAssetSum := tapchannelmsg.OutputSum(sweepInputs)

		// For this local allocation we'll need to create a new script
		// key to use for the sweep transaction.
		scriptKeyGen := func(asset.ID) (asset.ScriptKey, error) {
			var emptyKey asset.ScriptKey

			scriptKey, err := a.cfg.AddrBook.NextScriptKey(
				ctx, asset.TaprootAssetsKeyFamily,
			)
			if err != nil {
				return emptyKey, err
			}

			return scriptKey, nil
		}

		// With the script key created, we can make a new allocation
		// that will be used to sweep the funds back to our wallet.
		//
		// We leave out the internal key here, as we'll make it later
		// once we actually have the other set of inputs we need to
		// sweep.
		allocs = append(allocs, &tapsend.Allocation{
			Type: tapsend.CommitAllocationToLocal,
			// We don't need to worry about sorting, as
			// we'll always be the first output index in the
			// transaction.
			OutputIndex:  0,
			Amount:       sweepAssetSum,
			AssetVersion: asset.V1,
			BtcAmount:    tapsend.DummyAmtSats,
			GenScriptKey: scriptKeyGen,
		})
	}

	log.Infof("Created %v allocations for commit tx sweep: %v",
		len(allocs), limitSpewer.Sdump(allocs))

	// With the allocations created above, we'll now extract a slice of
	// each of the input proofs for each asset.
	inputProofs := fn.Map(
		sweepInputs, func(o *cmsg.AssetOutput) *proof.Proof {
			return &o.Proof.Val
		},
	)

	// With the proofs constructed, we can now distribute the coins to
	// create the vPackets that we'll pass on to the next stage.
	vPackets, err := tapsend.DistributeCoins(
		inputProofs, allocs, &a.cfg.ChainParams, true, tappsbt.V1,
	)
	if err != nil {
		return lfn.Errf[returnType]("error distributing coins: %w", err)
	}

	log.Infof("Created %v sweep packets: %v", len(vPackets),
		limitSpewer.Sdump(vPackets))

	// Next, we'll prepare all the vPackets for the sweep transaction, and
	// also set the courier address.
	courierAddr := a.cfg.DefaultCourierAddr
	for idx := range vPackets {
		// If we have a relative delay, then we'll set it for all the
		// vOuts in this packet.
		sweepDesc.relativeDelay.WhenSome(func(delay uint64) {
			for _, vOut := range vPackets[idx].Outputs {
				vOut.RelativeLockTime = delay
			}
		})

		// Similarly, if we have an absolute delay, we'll set it for all
		// the vOuts in this packet.
		sweepDesc.absoluteDelay.WhenSome(func(expiry uint64) {
			for _, vOut := range vPackets[idx].Outputs {
				vOut.LockTime = expiry
			}
		})

		err := tapsend.PrepareOutputAssets(ctx, vPackets[idx])
		if err != nil {
			return lfn.Errf[returnType]("unable to prepare output "+
				"assets: %w", err)
		}

		for outIdx := range vPackets[idx].Outputs {
			//nolint:lll
			vPackets[idx].Outputs[outIdx].ProofDeliveryAddress = courierAddr
		}
	}

	return lfn.Ok(vPackets)
}

// signSweepVpackets attempts to sign the vPackets specified using the passed
// sign desc and script tree.
func (a *AuxSweeper) signSweepVpackets(vPackets []*tappsbt.VPacket,
	signDesc input.SignDescriptor, tapTweak, ctrlBlock []byte,
	auxSigDesc lfn.Option[lnwallet.AuxSigDesc],
	secondLevelSigIndex lfn.Option[uint32]) error {

	// Before we sign below, we also need to generate the tapscript With
	// the vPackets prepared, we can now sign the output asset we'll create
	// at a later step.
	for vPktIndex, vPacket := range vPackets {
		if len(vPacket.Inputs) != 1 {
			return fmt.Errorf("expected single input, got %v",
				len(vPacket.Inputs))
		}

		// Each vPacket only has a single input, as we're sweeping a
		// single asset from our commitment output.
		vIn := vPacket.Inputs[0]

		// Next, we'll apply the sign desc to the vIn, setting the PSBT
		// specific fields. Along the way, we'll apply any relevant
		// tweaks to generate the key we'll use to verify the
		// signature.
		signingKey, leafToSign := applySignDescToVIn(
			signDesc, vIn, &a.cfg.ChainParams, tapTweak,
		)

		// In this case, the witness isn't special, so we'll set the
		// control block now for it.
		vIn.TaprootLeafScript[0].ControlBlock = ctrlBlock

		log.Debugf("signing vPacket for input=%v",
			limitSpewer.Sdump(vIn.PrevID))

		// With everything set, we can now sign the new leaf we'll
		// sweep into.
		signed, err := a.cfg.Signer.SignVirtualPacket(
			vPacket, tapfreighter.SkipInputProofVerify(),
			tapfreighter.WithValidator(&schnorrSigValidator{
				pubKey:     signingKey,
				tapLeaf:    lfn.Some(leafToSign),
				signMethod: input.TaprootScriptSpendSignMethod,
			}),
		)
		if err != nil {
			return fmt.Errorf("error signing virtual "+
				"packet: %w", err)
		}

		if len(signed) != 1 || signed[0] != 0 {
			return fmt.Errorf("error signing virtual packet, " +
				"got no sig")
		}

		// At this point, the witness looks like: <sig> <witnessScript>
		// <ctrlBlock>. This is a second level transaction, so we have
		// another signature that we need to add to the witness this
		// additional signature for the multi-sig.
		err = lfn.MapOptionZ(
			auxSigDesc,
			func(aux lnwallet.AuxSigDesc) error {
				assetSigs, err := cmsg.DecodeAssetSigListRecord(
					aux.AuxSig,
				)
				if err != nil {
					return fmt.Errorf("error "+
						"decoding asset sig list "+
						"record: %w", err)
				}
				auxSig := assetSigs.Sigs[vPktIndex]

				// With the sig obtained, we'll now insert the
				// signature at the specified index.
				//nolint:lll
				sigIndex, err := secondLevelSigIndex.UnwrapOrErr(
					fmt.Errorf("no sig index"),
				)
				if err != nil {
					return err
				}

				auxSigBytes := append(
					auxSig.Sig.Val.RawBytes(),
					byte(auxSig.SigHashType.Val),
				)

				newAsset := vPacket.Outputs[0].Asset

				//nolint:lll
				prevWitness := newAsset.PrevWitnesses[0].TxWitness
				prevWitness = slices.Insert(
					prevWitness, int(sigIndex), auxSigBytes,
				)
				return newAsset.UpdateTxWitness(0, prevWitness)
			},
		)
		if err != nil {
			return err
		}
	}

	return nil
}

// vPktsWithInput couples a vPkt along with the input that contained it.
type vPktsWithInput struct {
	// btcInput is the Bitcoin that the vPkt will the spending from (on the
	// TAP layer).
	btcInput input.Input

	// vPkts is the set of vPacket that will be used to spend the input.
	vPkts []*tappsbt.VPacket

	// tapSigDesc houses the information we'll need to re-sign the vPackets
	// above. Note that this is only set if this is a second level packet.
	tapSigDesc lfn.Option[cmsg.TapscriptSigDesc]
}

// isPresigned returns true if the vPktsWithInput is presigned. This will be the
// for an HTLC spent directly from our local commitment transaction.
func (v vPktsWithInput) isPresigned() bool {
	witType := v.btcInput.WitnessType()
	switch witType {
	case input.TaprootHtlcAcceptedLocalSuccess:
		return true
	case input.TaprootHtlcLocalOfferedTimeout:
		return true
	default:
		return false
	}
}

// sweepVpkts contains the set of vPkts needed for sweeping an output. Most
// outputs will only have the first level specified. The second level is needed
// for HTLC outputs on our local commitment transaction.
type sweepVpkts struct {
	// firstLevel houses vPackets that are used to sweep outputs directly
	// from the commitment transaction.
	firstLevel []vPktsWithInput

	// secondLevel is used to sweep outputs that are created by second level
	// HTLC transactions.
	secondLevel []vPktsWithInput
}

// firstLevelPkts returns a slice of the first level pkts.
func (s sweepVpkts) firstLevelPkts() []*tappsbt.VPacket {
	return fn.FlatMap(
		s.firstLevel, func(v vPktsWithInput) []*tappsbt.VPacket {
			return v.vPkts
		},
	)
}

// secondLevelPkts returns a slice of the second level pkts.
func (s sweepVpkts) secondLevelPkts() []*tappsbt.VPacket {
	return fn.FlatMap(
		s.secondLevel, func(v vPktsWithInput) []*tappsbt.VPacket {
			return v.vPkts
		},
	)
}

// allPkts returns a slice of both the first and second level pkts.
func (s sweepVpkts) allPkts() []*tappsbt.VPacket {
	return append(s.firstLevelPkts(), s.secondLevelPkts()...)
}

// allVpktsWithInput returns a slice of all vPktsWithInput.
func (s sweepVpkts) allVpktsWithInput() []vPktsWithInput {
	return append(s.firstLevel, s.secondLevel...)
}

// directSpendPkts returns the slice of all vPkts that are a direct spend from
// the commitment transaction. This excludes vPkts that are the pre-signed 2nd
// level transaction variant.
func (s sweepVpkts) directSpendPkts() []*tappsbt.VPacket {
	directSpends := lfn.Filter(
		s.allVpktsWithInput(), func(vi vPktsWithInput) bool {
			return !vi.isPresigned()
		},
	)
	directPkts := fn.FlatMap(
		directSpends, func(v vPktsWithInput) []*tappsbt.VPacket {
			return v.vPkts
		},
	)

	return directPkts
}

// createAndSignSweepVpackets creates vPackets that sweep the funds from the
// channel to the wallet, and then signs them as well.
func (a *AuxSweeper) createAndSignSweepVpackets(
	sweepInputs []*cmsg.AssetOutput, resReq lnwallet.ResolutionReq,
	sweepDesc lfn.Result[tapscriptSweepDesc],
) lfn.Result[[]*tappsbt.VPacket] {

	type returnType = []*tappsbt.VPacket
	type resultType = lfn.Result[returnType]

	// Based on the sweep inputs, make vPackets that sweep all the inputs
	// into a new output with a fresh script key. They won't have an
	// internal key set, we'll do that when we go to make the output to
	// anchor them all. We'll then take those, then sign all the vPackets
	// based on the specified sweepDesc.
	signPkts := func(vPkts []*tappsbt.VPacket,
		desc tapscriptSweepDesc) resultType {

		// If this is a second level output, then we'll use the
		// specified aux sign desc, otherwise, we'll use the
		// normal one.
		signDesc := lfn.MapOption(
			func(aux lnwallet.AuxSigDesc) input.SignDescriptor {
				return aux.SignDetails.SignDesc
			},
		)(desc.auxSigInfo).UnwrapOr(resReq.SignDesc)

		err := a.signSweepVpackets(
			vPkts, signDesc, desc.scriptTree.TapTweak(),
			desc.ctrlBlockBytes, desc.auxSigInfo,
			desc.secondLevelSigIndex,
		)
		if err != nil {
			return lfn.Err[returnType](err)
		}

		return lfn.Ok(vPkts)
	}

	return lfn.FlatMapResult(
		a.createSweepVpackets(sweepInputs, sweepDesc, resReq),
		func(vPkts []*tappsbt.VPacket) resultType {
			return lfn.FlatMapResult(
				sweepDesc,
				func(desc tapscriptSweepDesc) resultType {
					return signPkts(vPkts, desc)
				},
			)
		},
	)
}

// tapscriptSweepDesc is a helper struct that contains the tapscript tree and
// the control block needed to generate a valid spend.
type tapscriptSweepDesc struct {
	auxSigInfo lfn.Option[lnwallet.AuxSigDesc]

	scriptTree input.TapscriptDescriptor

	ctrlBlockBytes []byte

	relativeDelay lfn.Option[uint64]

	absoluteDelay lfn.Option[uint64]

	secondLevelSigIndex lfn.Option[uint32]
}

// tapscriptSweepDescs contains the sweep decs for the first and second level.
// Most outputs only go to the first level, but HTLCs on our local commitment
// transaction go to the second level.
type tapscriptSweepDescs struct {
	firstLevel tapscriptSweepDesc

	secondLevel lfn.Option[tapscriptSweepDesc]
}

// commitNoDelaySweepDesc creates a sweep desc for a commitment output that
// resides on the remote party's commitment transaction. This output is a
// non-delay output, so we don't need to worry about the CSV delay when
// sweeping it.
func commitNoDelaySweepDesc(keyRing *lnwallet.CommitmentKeyRing,
	csvDelay uint32) lfn.Result[tapscriptSweepDescs] {

	type returnType = tapscriptSweepDescs

	// We'll make the script tree for the to remote script (we're remote as
	// this is their commitment transaction). We don't have an auxLeaf here
	// as we're on the TAP layer.
	toRemoteScriptTree, err := input.NewRemoteCommitScriptTree(
		keyRing.ToRemoteKey, input.NoneTapLeaf(),
	)
	if err != nil {
		return lfn.Errf[returnType]("unable to make remote "+
			"script tree: %w", err)
	}

	// Now that we have the script tree, we'll make the control block
	// needed to spend it.
	ctrlBlock, err := toRemoteScriptTree.CtrlBlockForPath(
		input.ScriptPathSuccess,
	)
	if err != nil {
		return lfn.Err[returnType](err)
	}
	ctrlBlockBytes, err := ctrlBlock.ToBytes()
	if err != nil {
		return lfn.Errf[returnType]("unable to encode ctrl "+
			"block: %w", err)
	}

	return lfn.Ok(tapscriptSweepDescs{
		firstLevel: tapscriptSweepDesc{
			scriptTree:     toRemoteScriptTree,
			relativeDelay:  lfn.Some(uint64(csvDelay)),
			ctrlBlockBytes: ctrlBlockBytes,
		},
	})
}

// commitDelaySweepDesc creates a sweep desc for a commitment output that
// resides on our local commitment transaction. This output is a delay output,
// so we need to mind the CSV delay when sweeping it.
func commitDelaySweepDesc(keyRing *lnwallet.CommitmentKeyRing,
	csvDelay uint32) lfn.Result[tapscriptSweepDescs] {

	type returnType = tapscriptSweepDescs

	// We'll make the script tree for the to remote script (we're remote as
	// this is their commitment transaction). We don't have an auxLeaf here
	// as we're on the TAP layer.
	toLocalScriptTree, err := input.NewLocalCommitScriptTree(
		csvDelay, keyRing.ToLocalKey, keyRing.RevocationKey,
		input.NoneTapLeaf(),
	)
	if err != nil {
		return lfn.Err[returnType](err)
	}

	// Now that we have the script tree, we'll make the control block
	// needed to spend it.
	ctrlBlock, err := toLocalScriptTree.CtrlBlockForPath(
		input.ScriptPathSuccess,
	)
	if err != nil {
		return lfn.Err[returnType](err)
	}
	ctrlBlockBytes, err := ctrlBlock.ToBytes()
	if err != nil {
		return lfn.Err[returnType](err)
	}

	return lfn.Ok(tapscriptSweepDescs{
		firstLevel: tapscriptSweepDesc{
			scriptTree:     toLocalScriptTree,
			relativeDelay:  lfn.Some(uint64(csvDelay)),
			ctrlBlockBytes: ctrlBlockBytes,
		},
	})
}

// commitRevokeSweepDesc creates a sweep desc for a commitment output that is
// the local output on the remote party's commitment transaction. We can seep
// this in the case of a revoked commitment.
func commitRevokeSweepDesc(keyRing *lnwallet.CommitmentKeyRing,
	csvDelay uint32) lfn.Result[tapscriptSweepDescs] {

	type returnType = tapscriptSweepDescs

	// To sweep their revoked output, we'll make the script tree for the
	// local tree of their commitment transaction, which is actually their
	// output.
	toLocalScriptTree, err := input.NewLocalCommitScriptTree(
		csvDelay, keyRing.ToLocalKey, keyRing.RevocationKey,
		input.NoneTapLeaf(),
	)
	if err != nil {
		return lfn.Err[returnType](err)
	}

	// Now that we have the script tree, we'll make the control block
	// needed to spend it, but taking the revoked path.
	ctrlBlock, err := toLocalScriptTree.CtrlBlockForPath(
		input.ScriptPathRevocation,
	)
	if err != nil {
		return lfn.Err[returnType](err)
	}
	ctrlBlockBytes, err := ctrlBlock.ToBytes()
	if err != nil {
		return lfn.Err[tapscriptSweepDescs](err)
	}

	return lfn.Ok(tapscriptSweepDescs{
		firstLevel: tapscriptSweepDesc{
			scriptTree:     toLocalScriptTree,
			ctrlBlockBytes: ctrlBlockBytes,
		},
	})
}

// remoteHtlcTimeoutSweepDesc creates a sweep desc for an HTLC output that is
// close to timing out on the remote party's commitment transaction.
func remoteHtlcTimeoutSweepDesc(originalKeyRing *lnwallet.CommitmentKeyRing,
	payHash []byte, csvDelay uint32, htlcExpiry uint32,
	index input.HtlcIndex) lfn.Result[tapscriptSweepDescs] {

	// We're sweeping an HTLC output, which has a tweaked script key. To be
	// able to create the correct control block, we need to tweak the key
	// ring with the index of the HTLC.
	tweakedKeyRing := TweakedRevocationKeyRing(originalKeyRing, index)

	// We're sweeping a timed out HTLC, which means that we'll need to
	// create the receiver's HTLC script tree (from the remote party's PoV).
	htlcScriptTree, err := input.ReceiverHTLCScriptTaproot(
		htlcExpiry, tweakedKeyRing.LocalHtlcKey,
		tweakedKeyRing.RemoteHtlcKey, tweakedKeyRing.RevocationKey,
		payHash, lntypes.Remote, input.NoneTapLeaf(),
	)
	if err != nil {
		return lfn.Err[tapscriptSweepDescs](err)
	}

	// Now that we have the script tree, we'll make the control block needed
	// to spend it, but taking the revoked path.
	ctrlBlock, err := htlcScriptTree.CtrlBlockForPath(
		input.ScriptPathTimeout,
	)
	if err != nil {
		return lfn.Err[tapscriptSweepDescs](err)
	}
	ctrlBlockBytes, err := ctrlBlock.ToBytes()
	if err != nil {
		return lfn.Err[tapscriptSweepDescs](err)
	}

	return lfn.Ok(tapscriptSweepDescs{
		firstLevel: tapscriptSweepDesc{
			relativeDelay:  lfn.Some(uint64(csvDelay)),
			absoluteDelay:  lfn.Some(uint64(htlcExpiry)),
			scriptTree:     htlcScriptTree,
			ctrlBlockBytes: ctrlBlockBytes,
		},
	})
}

// remoteHtlcSuccessSweepDesc creates a sweep desc for an HTLC output present on
// the remote party's commitment transaction that we can sweep with the
// preimage.
func remoteHtlcSuccessSweepDesc(originalKeyRing *lnwallet.CommitmentKeyRing,
	payHash []byte, csvDelay uint32,
	index input.HtlcIndex) lfn.Result[tapscriptSweepDescs] {

	// We're sweeping an HTLC output, which has a tweaked script key. To be
	// able to create the correct control block, we need to tweak the key
	// ring with the index of the HTLC.
	tweakedKeyRing := TweakedRevocationKeyRing(originalKeyRing, index)

	// We're planning on sweeping an HTLC that we know the preimage to,
	// which the remote party sent, so we'll construct the sender version of
	// the HTLC script tree (from their PoV, they're the sender).
	htlcScriptTree, err := input.SenderHTLCScriptTaproot(
		tweakedKeyRing.RemoteHtlcKey, tweakedKeyRing.LocalHtlcKey,
		tweakedKeyRing.RevocationKey, payHash, lntypes.Remote,
		input.NoneTapLeaf(),
	)
	if err != nil {
		return lfn.Err[tapscriptSweepDescs](err)
	}

	// Now that we have the script tree, we'll make the control block needed
	// to spend it, but taking the revoked path.
	ctrlBlock, err := htlcScriptTree.CtrlBlockForPath(
		input.ScriptPathSuccess,
	)
	if err != nil {
		return lfn.Err[tapscriptSweepDescs](err)
	}
	ctrlBlockBytes, err := ctrlBlock.ToBytes()
	if err != nil {
		return lfn.Err[tapscriptSweepDescs](err)
	}

	return lfn.Ok(tapscriptSweepDescs{
		firstLevel: tapscriptSweepDesc{
			relativeDelay:  lfn.Some(uint64(csvDelay)),
			ctrlBlockBytes: ctrlBlockBytes,
			scriptTree:     htlcScriptTree,
		},
	})
}

// localHtlcTimeoutSweepDesc creates a sweep desc for an HTLC output that is
// present on our local commitment transaction. These are second level HTLCs, so
// we'll need to perform two stages of sweeps.
func localHtlcTimeoutSweepDesc(req lnwallet.ResolutionReq,
	index input.HtlcIndex) lfn.Result[tapscriptSweepDescs] {

	const isIncoming = false

	payHash, err := req.PayHash.UnwrapOrErr(
		fmt.Errorf("no pay hash"),
	)
	if err != nil {
		return lfn.Err[tapscriptSweepDescs](err)
	}
	htlcExpiry, err := req.CltvDelay.UnwrapOrErr(
		fmt.Errorf("no htlc expiry"),
	)
	if err != nil {
		return lfn.Err[tapscriptSweepDescs](err)
	}

	// We're sweeping an HTLC output, which has a tweaked script key. To be
	// able to create the correct control block, we need to tweak the key
	// ring with the index of the HTLC.
	tweakedKeyRing := TweakedRevocationKeyRing(req.KeyRing, index)

	// We'll need to complete the control block to spend the second-level
	// HTLC, so first we'll make the script tree for the HTLC.
	htlcScriptTree, err := lnwallet.GenTaprootHtlcScript(
		isIncoming, lntypes.Local, htlcExpiry, payHash, tweakedKeyRing,
		lfn.None[txscript.TapLeaf](),
	)
	if err != nil {
		return lfn.Errf[tapscriptSweepDescs]("error creating "+
			"HTLC script: %w", err)
	}

	// Now that we have the script tree, we'll make the control block needed
	// to spend it, but taking the timeout path.
	ctrlBlock, err := htlcScriptTree.CtrlBlockForPath(
		input.ScriptPathTimeout,
	)
	if err != nil {
		return lfn.Err[tapscriptSweepDescs](err)
	}
	ctrlBlockBytes, err := ctrlBlock.ToBytes()
	if err != nil {
		return lfn.Err[tapscriptSweepDescs](err)
	}

	//  For the second level transaction, the witness looks like this:
	//
	//  <receiver sig> <sender sig> <timeout_script> <control_block>
	//
	//  We're the sender, so we'll need to insert their sig at the very
	//  front.
	sigIndex := lfn.Some(uint32(0))

	// As this is an HTLC on our local commitment transaction, we'll also
	// need to generate a sweep desc for second level HTLC.
	secondLevelScriptTree, err := input.TaprootSecondLevelScriptTree(
		tweakedKeyRing.RevocationKey, req.KeyRing.ToLocalKey,
		req.CommitCsvDelay, lfn.None[txscript.TapLeaf](),
	)
	if err != nil {
		return lfn.Errf[tapscriptSweepDescs]("error "+
			"creating second level htlc script: %w", err)
	}
	secondLevelCtrBlock, err := secondLevelScriptTree.CtrlBlockForPath(
		input.ScriptPathSuccess,
	)
	if err != nil {
		return lfn.Err[tapscriptSweepDescs](err)
	}
	secondLevelCtrlBlockBytes, err := secondLevelCtrBlock.ToBytes()
	if err != nil {
		return lfn.Err[tapscriptSweepDescs](err)
	}

	secondLevelDesc := tapscriptSweepDesc{
		scriptTree:     secondLevelScriptTree,
		relativeDelay:  lfn.Some(uint64(req.CommitCsvDelay)),
		ctrlBlockBytes: secondLevelCtrlBlockBytes,
	}

	return lfn.Ok(tapscriptSweepDescs{
		firstLevel: tapscriptSweepDesc{
			scriptTree:          htlcScriptTree,
			ctrlBlockBytes:      ctrlBlockBytes,
			relativeDelay:       lfn.Some(uint64(req.CsvDelay)),
			absoluteDelay:       lfn.Some(uint64(htlcExpiry)),
			auxSigInfo:          req.AuxSigDesc,
			secondLevelSigIndex: sigIndex,
		},
		secondLevel: lfn.Some(secondLevelDesc),
	})
}

// localHtlcSuccessSweepDesc creates a sweep desc for an HTLC output that is
// present on our local commitment transaction that we can sweep with a
// preimage. These sweeps take two stages, so we'll add that extra information.
func localHtlcSuccessSweepDesc(req lnwallet.ResolutionReq,
	index input.HtlcIndex) lfn.Result[tapscriptSweepDescs] {

	const isIncoming = true

	payHash, err := req.PayHash.UnwrapOrErr(
		fmt.Errorf("no pay hash"),
	)
	if err != nil {
		return lfn.Err[tapscriptSweepDescs](err)
	}
	htlcExpiry, err := req.CltvDelay.UnwrapOrErr(
		fmt.Errorf("no htlc expiry"),
	)
	if err != nil {
		return lfn.Err[tapscriptSweepDescs](err)
	}

	// We're sweeping an HTLC output, which has a tweaked script key. To be
	// able to create the correct control block, we need to tweak the key
	// ring with the index of the HTLC.
	tweakedKeyRing := TweakedRevocationKeyRing(req.KeyRing, index)

	// We'll need to complete the control block to spend the second-level
	// HTLC, so first we'll make the script tree for the HTLC.
	htlcScriptTree, err := lnwallet.GenTaprootHtlcScript(
		isIncoming, lntypes.Local, htlcExpiry, payHash, tweakedKeyRing,
		lfn.None[txscript.TapLeaf](),
	)
	if err != nil {
		return lfn.Errf[tapscriptSweepDescs]("error creating "+
			"HTLC script: %w", err)
	}

	// Now that we have the script tree, we'll make the control block needed
	// to spend it, but taking the success path.
	ctrlBlock, err := htlcScriptTree.CtrlBlockForPath(
		input.ScriptPathSuccess,
	)
	if err != nil {
		return lfn.Err[tapscriptSweepDescs](err)
	}
	ctrlBlockBytes, err := ctrlBlock.ToBytes()
	if err != nil {
		return lfn.Err[tapscriptSweepDescs](err)
	}

	//  For the second level transaction, the witness looks like this:
	//
	//  * <sender sig> <receiver sig> <preimage> <success_script>
	//    <control_block>
	//
	// In this case, we're the receiver. After we sign the witness will look
	// like this: <receiver sig> <witness script> <ctrlBlock>.
	//
	// So we'll need to insert the remote party's signature at the very
	// front.
	sigIndex := lfn.Some(uint32(0))

	// As this is an HTLC on our local commitment transaction, we'll also
	// need to generate a sweep desc for second level HTLC.
	secondLevelScriptTree, err := input.TaprootSecondLevelScriptTree(
		tweakedKeyRing.RevocationKey, req.KeyRing.ToLocalKey,
		req.CommitCsvDelay, lfn.None[txscript.TapLeaf](),
	)
	if err != nil {
		return lfn.Errf[tapscriptSweepDescs]("error "+
			"creating second level htlc script: %w", err)
	}
	secondLevelCtrBlock, err := secondLevelScriptTree.CtrlBlockForPath(
		input.ScriptPathSuccess,
	)
	if err != nil {
		return lfn.Err[tapscriptSweepDescs](err)
	}
	secondLevelCtrlBlockBytes, err := secondLevelCtrBlock.ToBytes()
	if err != nil {
		return lfn.Err[tapscriptSweepDescs](err)
	}

	secondLevelDesc := tapscriptSweepDesc{
		scriptTree:     secondLevelScriptTree,
		relativeDelay:  lfn.Some(uint64(req.CommitCsvDelay)),
		ctrlBlockBytes: secondLevelCtrlBlockBytes,
	}

	return lfn.Ok(tapscriptSweepDescs{
		firstLevel: tapscriptSweepDesc{
			scriptTree:          htlcScriptTree,
			ctrlBlockBytes:      ctrlBlockBytes,
			relativeDelay:       lfn.Some(uint64(req.CsvDelay)),
			auxSigInfo:          req.AuxSigDesc,
			secondLevelSigIndex: sigIndex,
		},
		secondLevel: lfn.Some(secondLevelDesc),
	})
}

// assetOutputToVPacket converts an asset outputs to the corresponding vPackets
// that can be used to complete the proof needed to import a commitment
// transaction.  This new vPacket is added to the specified map.
func assetOutputToVPacket(fundingInputProofs map[asset.ID]*proof.Proof,
	vPktsByAssetID map[asset.ID]*tappsbt.VPacket,
	assetOutput *cmsg.AssetOutput, chainParams *address.ChainParams,
	commitTx *wire.MsgTx, courierAddr *url.URL) error {

	// Make a vPacket with the input set from the funding input proof for
	// this asset ID.
	var err error
	assetID := assetOutput.AssetID.Val
	vPkt, ok := vPktsByAssetID[assetID]
	if !ok {
		fundingInputProof, ok := fundingInputProofs[assetID]
		if !ok {
			return fmt.Errorf("funding input proof not found for "+
				"asset ID: %v", assetOutput.AssetID)
		}
		vPkt, err = tappsbt.FromProofs(
			[]*proof.Proof{fundingInputProof}, chainParams,
			tappsbt.V1,
		)
		if err != nil {
			return fmt.Errorf("unable to create "+
				"vPacket: %v", err)
		}

		vPktsByAssetID[assetID] = vPkt
	}

	// With the input set, we'll now add the extra information for the
	// output to the packet to complete it.
	assetProof := assetOutput.Proof.Val
	inclusionProof := assetProof.InclusionProof

	scriptKey := asset.NewScriptKey(assetProof.Asset.ScriptKey.PubKey)
	scriptKey.TweakedScriptKey = &asset.TweakedScriptKey{
		RawKey: keychain.KeyDescriptor{
			PubKey: assetProof.Asset.ScriptKey.PubKey,
		},
	}

	vOut := &tappsbt.VOutput{
		Amount:       assetProof.Asset.Amount,
		AssetVersion: assetProof.Asset.Version,
		Type: func() tappsbt.VOutputType {
			if assetProof.Asset.SplitCommitmentRoot == nil {
				return tappsbt.TypeSimple
			}
			return tappsbt.TypeSplitRoot
		}(),
		Interactive:             true,
		AnchorOutputIndex:       inclusionProof.OutputIndex,
		AnchorOutputInternalKey: inclusionProof.InternalKey,
		//nolint:lll
		AnchorOutputTapscriptSibling: inclusionProof.CommitmentProof.TapSiblingPreimage,
		ScriptKey:                    scriptKey,
		ProofSuffix:                  &assetProof,
	}

	// While we're here, we'll also replace the transaction stored in the
	// proof with the correct one.
	vOut.ProofSuffix.AnchorTx = *commitTx

	// Finally, we'll set the delivery address to the default courier, so
	// we publish the proof in the specified Universe.
	vOut.ProofDeliveryAddress = courierAddr

	vPkt.Outputs = append(vPkt.Outputs, vOut)
	vPktsByAssetID[assetID] = vPkt

	return nil
}

// anchorOutputAllocations is a helper function that creates a set of
// allocations for the anchor outputs. We'll use this later to create the proper
// exclusion proofs.
func anchorOutputAllocations(
	keyRing *lnwallet.CommitmentKeyRing) lfn.Result[[]*tapsend.Allocation] {

	anchorAlloc := func(
		k *btcec.PublicKey) lfn.Result[*tapsend.Allocation] {

		anchorTree, err := input.NewAnchorScriptTree(k)
		if err != nil {
			return lfn.Err[*tapsend.Allocation](err)
		}

		sibling, scriptTree, err := LeavesFromTapscriptScriptTree(
			anchorTree,
		)
		if err != nil {
			return lfn.Err[*tapsend.Allocation](err)
		}

		return lfn.Ok(&tapsend.Allocation{
			Type:           tapsend.AllocationTypeNoAssets,
			Amount:         0,
			BtcAmount:      lnwallet.AnchorSize,
			InternalKey:    scriptTree.InternalKey,
			NonAssetLeaves: sibling,
			SortTaprootKeyBytes: schnorr.SerializePubKey(
				scriptTree.TaprootKey,
			),
		})
	}

	localAnchor := anchorAlloc(keyRing.ToLocalKey)
	remoteAnchor := anchorAlloc(keyRing.ToRemoteKey)

	type resultType = lfn.Result[[]*tapsend.Allocation]
	sortAnchor := func(a1, a2 *tapsend.Allocation) resultType {
		// Before we return the anchors, we'll make sure that
		// they end up in the right sort order.
		scriptCompare := bytes.Compare(
			a1.SortTaprootKeyBytes, a2.SortTaprootKeyBytes,
		)

		if scriptCompare < 0 {
			a1.OutputIndex = 0
			a2.OutputIndex = 1
		} else {
			a2.OutputIndex = 0
			a1.OutputIndex = 1
		}

		return lfn.Ok([]*tapsend.Allocation{a1, a2})
	}

	return lfn.FlatMapResult(
		localAnchor, func(a1 *tapsend.Allocation) resultType {
			return lfn.FlatMapResult(
				remoteAnchor,
				func(a2 *tapsend.Allocation) resultType {
					return sortAnchor(a1, a2)
				},
			)
		},
	)
}

// remoteCommitScriptKey creates the script key for the remote commitment
// output.
func remoteCommitScriptKey(
	remoteKey *btcec.PublicKey) lfn.Result[asset.ScriptKey] {

	remoteScriptTree, err := input.NewRemoteCommitScriptTree(
		remoteKey, input.NoneTapLeaf(),
	)
	if err != nil {
		return lfn.Err[asset.ScriptKey](err)
	}

	outputKey := asset.NewScriptKey(remoteScriptTree.TaprootKey).PubKey

	return lfn.Ok(asset.ScriptKey{
		PubKey: outputKey,
		TweakedScriptKey: &asset.TweakedScriptKey{
			RawKey: keychain.KeyDescriptor{
				PubKey: remoteScriptTree.InternalKey,
			},
			Tweak: remoteScriptTree.TapscriptRoot,
		},
	})
}

// localCommitScriptKey creates the script key for the local commitment output.
func localCommitScriptKey(localKey, revokeKey *btcec.PublicKey,
	csvDelay uint32) lfn.Result[asset.ScriptKey] {

	localScriptTree, err := input.NewLocalCommitScriptTree(
		csvDelay, localKey, revokeKey, input.NoneTapLeaf(),
	)
	if err != nil {
		return lfn.Err[asset.ScriptKey](err)
	}

	outputKey := asset.NewScriptKey(localScriptTree.TaprootKey).PubKey

	return lfn.Ok(asset.ScriptKey{
		PubKey: outputKey,
		TweakedScriptKey: &asset.TweakedScriptKey{
			RawKey: keychain.KeyDescriptor{
				PubKey: localScriptTree.InternalKey,
			},
			Tweak: localScriptTree.TapscriptRoot,
		},
	})
}

// deriveCommitKeys derives the script keys for the local and remote party.
func deriveCommitKeys(req lnwallet.ResolutionReq) (*asset.ScriptKey,
	*asset.ScriptKey, error) {

	// This might be a breach case we need to handle. In this case, our
	// output is the remote output and their output is local here.
	// Therefore, we'll try to use the BreachCsvDelay if present,
	// otherwise, we'll stick with the main one specified.
	toLocalCsvDelay := req.BreachCsvDelay.UnwrapOr(req.CsvDelay)
	localScriptTree, err := localCommitScriptKey(
		req.KeyRing.ToLocalKey, req.KeyRing.RevocationKey,
		toLocalCsvDelay,
	).Unpack()
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create local "+
			"script key: %w", err)
	}

	remoteScriptTree, err := remoteCommitScriptKey(
		req.KeyRing.ToRemoteKey,
	).Unpack()
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create remote "+
			"script key: %w", err)
	}

	return &localScriptTree, &remoteScriptTree, nil
}

// importCommitScriptKeys imports the script keys for the commitment outputs
// into the local addr book.
func (a *AuxSweeper) importCommitScriptKeys(req lnwallet.ResolutionReq) error {
	// Generate the local and remote script key, so we can properly import
	// into the addr book, like we did above.
	localCommitScriptKey, remoteCommitScriptKey, err := deriveCommitKeys(
		req,
	)
	if err != nil {
		return fmt.Errorf("unable to derive script keys: %w", err)
	}

	// Depending on the close type, we'll import one or both of the script
	// keys generated above.
	keysToImport := make([]asset.ScriptKey, 0, 2)
	switch {
	case req.CloseType == lnwallet.Breach:
		keysToImport = append(keysToImport, *localCommitScriptKey)
		keysToImport = append(keysToImport, *remoteCommitScriptKey)

	case req.CloseType == lnwallet.LocalForceClose:
		keysToImport = append(keysToImport, *localCommitScriptKey)

	case req.CloseType == lnwallet.RemoteForceClose:
		keysToImport = append(keysToImport, *remoteCommitScriptKey)

	default:
		return fmt.Errorf("unknown close type: %v", req.CloseType)
	}

	log.Debugf("Importing script_keys=%v", limitSpewer.Sdump(keysToImport))

	ctxb := context.Background()
	for _, key := range keysToImport {
		err := a.cfg.AddrBook.InsertScriptKey(
			ctxb, key, asset.ScriptKeyScriptPathChannel,
		)
		if err != nil {
			return fmt.Errorf("unable to insert script "+
				"key: %w", err)
		}
	}

	return nil
}

// importOutputScriptKey imports the output script key that this scriptDesc can
// spend into the local addr book.
func (a *AuxSweeper) importOutputScriptKeys(desc tapscriptSweepDescs) error {
	ctxb := context.Background()

	importScriptKey := func(desc tapscriptSweepDesc) error {
		scriptTree := desc.scriptTree.Tree()

		outputKey := asset.NewScriptKey(scriptTree.TaprootKey).PubKey
		scriptKey := asset.ScriptKey{
			PubKey: outputKey,
			TweakedScriptKey: &asset.TweakedScriptKey{
				RawKey: keychain.KeyDescriptor{
					PubKey: scriptTree.InternalKey,
				},
				Tweak: scriptTree.TapscriptRoot,
			},
		}

		log.Debugf("Importing script_keys=%v",
			limitSpewer.Sdump(scriptKey))

		return a.cfg.AddrBook.InsertScriptKey(
			ctxb, scriptKey, asset.ScriptKeyScriptPathChannel,
		)
	}

	if err := importScriptKey(desc.firstLevel); err != nil {
		return err
	}

	return lfn.MapOptionZ(
		desc.secondLevel,
		func(secondary tapscriptSweepDesc) error {
			return importScriptKey(secondary)
		},
	)
}

// importOutputProofs imports the output proofs into the pending asset funding
// into our local database. This preps us to be able to detect force closes.
func importOutputProofs(scid lnwire.ShortChannelID,
	outputProofs []*proof.Proof, courierAddr *url.URL,
	proofDispatch proof.CourierDispatch, chainBridge tapgarden.ChainBridge,
	headerVerifier proof.HeaderVerifier, groupVerifier proof.GroupVerifier,
	proofArchive proof.Archiver) error {

	// TODO(roasbeef): should be part of post confirmation funding validate
	// (chanvalidate)

	log.Infof("Importing %v proofs for ChannelPoint(%v)",
		len(outputProofs), outputProofs[0].OutPoint())

	// With the fetcher created, we'll have it fetch each of the proofs for
	// the funding outputs we need.
	//
	// TODO(roasbeef): assume single asset for now, also additional inputs
	for _, proofToImport := range outputProofs {
		proofPrevID, err := proofToImport.Asset.PrimaryPrevID()
		if err != nil {
			return fmt.Errorf("unable to get primary prev "+
				"ID: %w", err)
		}

		scriptKey, err := proofPrevID.ScriptKey.ToPubKey()
		if err != nil {
			return fmt.Errorf("unable to convert script key to "+
				"pubkey: %w", err)
		}

		inputProofLocator := proof.Locator{
			AssetID:   &proofPrevID.ID,
			ScriptKey: *scriptKey,
			OutPoint:  &proofPrevID.OutPoint,
		}
		if proofToImport.Asset.GroupKey != nil {
			groupKey := proofToImport.Asset.GroupKey.GroupPubKey
			inputProofLocator.GroupKey = &groupKey
		}

		log.Infof("Fetching funding input proof, locator=%v",
			limitSpewer.Sdump(inputProofLocator))

		// First, we'll make a courier to use in fetching the proofs we
		// need.
		ctxb := context.Background()
		proofFetcher, err := proofDispatch.NewCourier(
			ctxb, courierAddr, true,
		)
		if err != nil {
			return fmt.Errorf("unable to create proof courier: %w",
				err)
		}

		recipient := proof.Recipient{
			ScriptKey: scriptKey,
			AssetID:   proofPrevID.ID,
			Amount:    proofToImport.Asset.Amount,
		}
		prefixProof, err := proofFetcher.ReceiveProof(
			ctxb, recipient, inputProofLocator,
		)

		// Always attempt to close the courier, even if we encounter an
		// error.
		_ = proofFetcher.Close()

		// Handle any error that occurred during the proof fetch.
		if err != nil {
			return fmt.Errorf("unable to fetch prefix "+
				"proof: %w", err)
		}

		log.Infof("All proofs fetched, importing locator=%v",
			limitSpewer.Sdump(inputProofLocator))

		// Before we combine the proofs below, we'll be sure to update
		// the transition proof to include the proper block+merkle proof
		// information.
		blockHash, err := chainBridge.GetBlockHash(
			ctxb, int64(scid.BlockHeight),
		)
		if err != nil {
			return fmt.Errorf("unable to get block hash: %w", err)
		}
		block, err := chainBridge.GetBlock(ctxb, blockHash)
		if err != nil {
			return fmt.Errorf("unable to get block: %w", err)
		}
		err = proofToImport.UpdateTransitionProof(
			&proof.BaseProofParams{
				Block:       block,
				BlockHeight: scid.BlockHeight,
				Tx:          block.Transactions[scid.TxIndex],
				TxIndex:     int(scid.TxIndex),
			},
		)
		if err != nil {
			return fmt.Errorf("error updating transition "+
				"proof: %w", err)
		}

		// Now that we have the entire prefix proof, we'll append the
		// New funding output, then import it into our archive.
		//
		// TODO(roasbeef): way to do this w/o decoding again?
		var proofFile proof.File
		err = proofFile.Decode(bytes.NewReader(prefixProof.Blob))
		if err != nil {
			return fmt.Errorf("unable to decode proof: %w", err)
		}
		if err := proofFile.AppendProof(*proofToImport); err != nil {
			return fmt.Errorf("unable to append proof: %w", err)
		}

		// With the proof append, we'll serialize the proof file, then
		// import it into our archive.
		var finalProofBuf bytes.Buffer
		if err := proofFile.Encode(&finalProofBuf); err != nil {
			return fmt.Errorf("unable to encode proof: %w", err)
		}

		vCtx := proof.VerifierCtx{
			HeaderVerifier: headerVerifier,
			MerkleVerifier: proof.DefaultMerkleVerifier,
			GroupVerifier:  groupVerifier,
			ChainLookupGen: chainBridge,
		}

		fundingUTXO := proofToImport.Asset
		err = proofArchive.ImportProofs(
			ctxb, vCtx, false, &proof.AnnotatedProof{
				//nolint:lll
				Locator: proof.Locator{
					AssetID:   fn.Ptr(fundingUTXO.ID()),
					ScriptKey: *fundingUTXO.ScriptKey.PubKey,
					OutPoint: fn.Ptr(
						proofToImport.OutPoint(),
					),
				},
				Blob: finalProofBuf.Bytes(),
			},
		)
		if err != nil {
			return err
		}
	}

	return nil
}

// importCommitTx imports the commitment transaction into the wallet. This is
// called after a force close to ensure that we can properly spend outputs
// created by the commitment transaction at a later step.
func (a *AuxSweeper) importCommitTx(req lnwallet.ResolutionReq,
	commitState *cmsg.Commitment, fundingInfo *cmsg.OpenChannel) error {

	// Just in case we don't know about it already, we'll import the
	// funding script key.
	fundingScriptTree := tapscript.NewChannelFundingScriptTree()
	fundingTaprootKey, _ := schnorr.ParsePubKey(
		schnorr.SerializePubKey(fundingScriptTree.TaprootKey),
	)
	fundingScriptKey := asset.ScriptKey{
		PubKey: fundingTaprootKey,
		TweakedScriptKey: &asset.TweakedScriptKey{
			RawKey: keychain.KeyDescriptor{
				PubKey: fundingScriptTree.InternalKey,
			},
			Tweak: fundingScriptTree.TapscriptRoot,
		},
	}

	// We'll also need to import the funding script key into the wallet so
	// the asset will be materialized in the asset table and show up in the
	// balance correctly.
	ctxb := context.Background()
	err := a.cfg.AddrBook.InsertScriptKey(
		ctxb, fundingScriptKey, asset.ScriptKeyScriptPathChannel,
	)
	if err != nil {
		return fmt.Errorf("unable to insert script key: %w", err)
	}

	// Depending on the close type, we'll import one or both of the script
	// keys generated above.
	if err := a.importCommitScriptKeys(req); err != nil {
		return fmt.Errorf("unable to import script keys: %w", err)
	}

	// To start, we'll re-create vPackets for all of the outputs of the
	// commitment transaction.
	//
	// We'll use the fundingInfo proofs to create a vIn for each of them.
	fundingInputProofs := make(map[asset.ID]*proof.Proof)
	for _, fundingInput := range fundingInfo.FundedAssets.Val.Outputs {
		inputProof := &fundingInput.Proof.Val
		fundingInputProofs[inputProof.Asset.ID()] = inputProof
	}

	// If we're the responder, then we'll also fetch+complete the proofs
	// for the funding transaction here so we can properly recognize the
	// spent input below.
	if !req.Initiator {
		err := importOutputProofs(
			req.ShortChanID, maps.Values(fundingInputProofs),
			a.cfg.DefaultCourierAddr, a.cfg.ProofFetcher,
			a.cfg.ChainBridge, a.cfg.HeaderVerifier,
			a.cfg.GroupVerifier, a.cfg.ProofArchive,
		)
		if err != nil {
			return fmt.Errorf("unable to import output "+
				"proofs: %w", err)
		}
	}

	// With the funding proof for each asset ID known, we can now make the
	// vPackets for each of the outputs.
	vPktsByAssetID := make(map[asset.ID]*tappsbt.VPacket)
	for _, localAsset := range commitState.LocalAssets.Val.Outputs {
		err := assetOutputToVPacket(
			fundingInputProofs, vPktsByAssetID, localAsset,
			&a.cfg.ChainParams, req.CommitTx,
			a.cfg.DefaultCourierAddr,
		)
		if err != nil {
			return err
		}
	}
	for _, remoteAsset := range commitState.RemoteAssets.Val.Outputs {
		err := assetOutputToVPacket(
			fundingInputProofs, vPktsByAssetID, remoteAsset,
			&a.cfg.ChainParams, req.CommitTx,
			a.cfg.DefaultCourierAddr,
		)
		if err != nil {
			return err
		}
	}
	//nolint:lll
	for _, outgoingHTLCs := range commitState.OutgoingHtlcAssets.Val.HtlcOutputs {
		for _, outgoingHTLC := range outgoingHTLCs.Outputs {
			err := assetOutputToVPacket(
				fundingInputProofs, vPktsByAssetID, outgoingHTLC,
				&a.cfg.ChainParams, req.CommitTx,
				a.cfg.DefaultCourierAddr,
			)
			if err != nil {
				return err
			}
		}
	}
	//nolint:lll
	for _, incomingHTLCs := range commitState.IncomingHtlcAssets.Val.HtlcOutputs {
		for _, incomingHTLC := range incomingHTLCs.Outputs {
			err := assetOutputToVPacket(
				fundingInputProofs, vPktsByAssetID, incomingHTLC,
				&a.cfg.ChainParams, req.CommitTx,
				a.cfg.DefaultCourierAddr,
			)
			if err != nil {
				return err
			}
		}
	}

	// We can now add the witness for the OP_TRUE spend of the commitment
	// output to the vPackets.
	vPackets := maps.Values(vPktsByAssetID)
	if err := signCommitVirtualPackets(ctxb, vPackets); err != nil {
		return fmt.Errorf("error signing commit virtual "+
			"packets: %w", err)
	}

	outCommitments, err := tapsend.CreateOutputCommitments(vPackets)
	if err != nil {
		return fmt.Errorf("unable to create output "+
			"commitments: %w", err)
	}

	// With the output commitments known, we can regenerate the proof suffix
	// for each vPkt.
	anchorAllocations, err := anchorOutputAllocations(req.KeyRing).Unpack()
	if err != nil {
		return fmt.Errorf("unable to create anchor "+
			"allocations: %w", err)
	}
	exclusionCreator := tapsend.NonAssetExclusionProofs(anchorAllocations)
	for idx := range vPackets {
		vPkt := vPackets[idx]
		for outIdx := range vPkt.Outputs {
			proofSuffix, err := tapsend.CreateProofSuffixCustom(
				req.CommitTx, vPkt, outCommitments, outIdx,
				vPackets, exclusionCreator,
			)
			if err != nil {
				return fmt.Errorf("unable to create "+
					"proof suffix for output "+
					"%d: %w", outIdx, err)
			}

			vPkt.Outputs[outIdx].ProofSuffix = proofSuffix
		}
	}

	// TODO(roasbeef): import proof for receiver instead?

	// With all the vPKts created, we can now ship the transaction off to
	// the porter for final delivery.
	return shipChannelTxn(
		a.cfg.TxSender, req.CommitTx, outCommitments, vPackets,
		int64(req.CommitFee),
	)
}

// errNoPayHash is an error returned when no payment hash is provided.
var errNoPayHash = fmt.Errorf("no payment hash provided")

// resolveContract takes in a resolution request and resolves it by creating a
// serialized resolution blob that contains the virtual packets needed to sweep
// the funds from the contract.
func (a *AuxSweeper) resolveContract(
	req lnwallet.ResolutionReq) lfn.Result[tlv.Blob] {

	type returnType = tlv.Blob

	// If there's no commit blob, then there's nothing to resolve.
	if req.CommitBlob.IsNone() {
		return lfn.Err[tlv.Blob](nil)
	}

	log.Infof("Generating resolution_blob for contract_type=%v, "+
		"chan_point=%v", req.Type, req.ChanPoint)

	// As we have a commit blob, we'll decode the commit blob, so we can
	// have access to all the active outputs. We'll also decode the funding
	// blob, so we can make vInt from it.
	commitState, err := tapchannelmsg.DecodeCommitment(
		req.CommitBlob.UnwrapOr(nil),
	)
	if err != nil {
		return lfn.Err[returnType](err)
	}
	fundingInfo, err := tapchannelmsg.DecodeOpenChannel(
		req.FundingBlob.UnwrapOr(nil),
	)
	if err != nil {
		return lfn.Err[returnType](err)
	}

	var (
		sweepDesc        lfn.Result[tapscriptSweepDescs]
		assetOutputs     []*cmsg.AssetOutput
		needsSecondLevel bool
	)

	switch req.Type {
	// A non-delay output. This means the remote party force closed on
	// chain.
	case input.TaprootRemoteCommitSpend:
		// In this case, we'll be resolving the set of remote
		// assets, on the remote party's commitment, which are actually
		// our assets.
		assetOutputs = commitState.RemoteAssets.Val.Outputs

		// First, we'll make a sweep desc for the commitment txn. This
		// contains the tapscript tree, and also the control block
		// needed for a valid spend.
		sweepDesc = commitNoDelaySweepDesc(req.KeyRing, req.CsvDelay)

	// A normal delay output. This means we force closed, so we'll need to
	// mind the CSV when we sweep the output.
	case input.TaprootLocalCommitSpend:
		// In this case, we'll be resolving the set of local assets on
		// our commitment.
		assetOutputs = commitState.LocalAssets.Val.Outputs

		// Next, we'll make a sweep desc for this output. It's
		// dependent on the CSV delay we have in this channel, so we'll
		// pass that in as well.
		sweepDesc = commitDelaySweepDesc(req.KeyRing, req.CsvDelay)

	// The remote party has breached the channel. We'll sweep the revoked
	// key that we learned in the past.
	case input.TaprootCommitmentRevoke:
		// outputs, as they broadcast a revoked commitment. For the
		// In this case, we'll be sweeping the remote party's asset
		// remote party, this is actually their local output.
		assetOutputs = commitState.LocalAssets.Val.Outputs

		// Next, we'll make a sweep desk capable of sweeping the remote
		// party's local output.
		sweepDesc = commitRevokeSweepDesc(req.KeyRing, req.CsvDelay)

	// The remote party broadcasted a commitment transaction which held an
	// HTLC that we can timeout eventually.
	case input.TaprootHtlcOfferedRemoteTimeout:
		// In this case, we're interested in sweeping the incoming
		// assets for the remote party, which are actually the HTLCs we
		// sent outgoing. We only care about this particular HTLC, so
		// we'll filter out the rest.
		htlcID := req.HtlcID.UnwrapOr(math.MaxUint64)
		htlcOutputs := commitState.OutgoingHtlcAssets.Val
		assetOutputs = htlcOutputs.FilterByHtlcIndex(htlcID)

		payHash, err := req.PayHash.UnwrapOrErr(errNoPayHash)
		if err != nil {
			return lfn.Err[tlv.Blob](err)
		}

		// Now that we know which output we'll be sweeping, we'll make a
		// sweep desc for the timeout txn.
		sweepDesc = remoteHtlcTimeoutSweepDesc(
			req.KeyRing, payHash[:], req.CsvDelay,
			req.CltvDelay.UnwrapOr(0), htlcID,
		)

	// The remote party broadcasted a commitment transaction which held an
	// outgoing HTLC that we may claim with a preimage.
	case input.TaprootHtlcAcceptedRemoteSuccess:
		// In this case, it's an outgoing HTLC from the PoV of the
		// remote party, which is incoming for us. We'll only sweep this
		// HTLC, so we'll filter out the rest.
		htlcID := req.HtlcID.UnwrapOr(math.MaxUint64)
		htlcOutputs := commitState.IncomingHtlcAssets.Val
		assetOutputs = htlcOutputs.FilterByHtlcIndex(htlcID)

		payHash, err := req.PayHash.UnwrapOrErr(errNoPayHash)
		if err != nil {
			return lfn.Err[tlv.Blob](err)
		}

		// Now that we know which output we'll be sweeping, we'll make a
		// sweep desc for the timeout txn.
		sweepDesc = remoteHtlcSuccessSweepDesc(
			req.KeyRing, payHash[:], req.CsvDelay, htlcID,
		)

	// In this case, we broadcast a commitment transaction which held an
	// HTLC that we may need to time out in the future. This is the
	// second-level case, so we'll actually be creating+signing two sets of
	// vPkts later (1st + 2nd level).
	case input.TaprootHtlcLocalOfferedTimeout:
		// Like the other HTLC cases, there's only a single output we
		// care about here.
		htlcID := req.HtlcID.UnwrapOr(math.MaxUint64)
		htlcOutputs := commitState.OutgoingHtlcAssets.Val
		assetOutputs = htlcOutputs.FilterByHtlcIndex(htlcID)

		// With the output and pay desc located, we'll now create the
		// sweep desc.
		sweepDesc = localHtlcTimeoutSweepDesc(req, htlcID)

		needsSecondLevel = true

	// In this case, we've broadcast a commitment, with an incoming HTLC
	// that we can sweep. We'll annotate the sweepDesc with the information
	// needed to sweep both this output, as well as the second level
	// output it creates.
	case input.TaprootHtlcAcceptedLocalSuccess:
		htlcID := req.HtlcID.UnwrapOr(math.MaxUint64)
		htlcOutputs := commitState.IncomingHtlcAssets.Val
		assetOutputs = htlcOutputs.FilterByHtlcIndex(htlcID)

		// With the output and pay desc located, we'll now create the
		// sweep desc.
		sweepDesc = localHtlcSuccessSweepDesc(req, htlcID)

		needsSecondLevel = true

	default:
		// TODO(guggero): Need to do HTLC revocation cases here.
		// IMPORTANT: Remember that we applied the HTLC index as a tweak
		// to the revocation key on the asset level! That means the
		// tweak to the first-level HTLC script key's internal key
		// (which is the revocation key) MUST be applied when creating
		// a breach sweep transaction!

		return lfn.Errf[returnType]("unknown resolution type: %v",
			req.Type)
	}

	tapSweepDesc, err := sweepDesc.Unpack()
	if err != nil {
		return lfn.Err[tlv.Blob](err)
	}

	// Now that we know what output we're sweeping, before we proceed, we'll
	// import the relevant script key to disk. This way, we'll properly
	// recognize spends of it.
	if err := a.importOutputScriptKeys(tapSweepDesc); err != nil {
		return lfn.Errf[tlv.Blob]("unable to import output script "+
			"key: %w", err)
	}

	// To be able to construct all the proofs we need to spend later, we'll
	// make sure that this commitment transaction exists in our database. If
	// not, then we'll complete the proof, register the script keys, and
	// ship the pre-signed commitment transaction.
	ctx := context.Background()
	commitParcel, err := a.cfg.TxSender.QueryParcels(
		ctx, fn.Some(req.CommitTx.TxHash()), false,
	)
	if err != nil {
		return lfn.Err[returnType](err)
	}
	if len(commitParcel) == 0 {
		log.Infof("First time seeing commit_txid=%v, importing",
			req.CommitTx.TxHash())

		err := a.importCommitTx(req, commitState, fundingInfo)
		if err != nil {
			return lfn.Errf[returnType]("unable to import "+
				"commitment txn: %w", err)
		}
	} else {
		log.Infof("Commitment commit_txid=%v already imported, "+
			"skipping", req.CommitTx.TxHash())
	}

	// The input proofs above were made originally using the fake commit tx
	// as an anchor. We now know the real commit tx, so we'll swap that in
	// to ensure the outpoints used below are correct.
	for _, assetOut := range assetOutputs {
		assetOut.Proof.Val.AnchorTx = *req.CommitTx
	}

	log.Infof("Sweeping %v asset outputs (second_level=%v): %v",
		len(assetOutputs), needsSecondLevel,
		limitSpewer.Sdump(assetOutputs))

	// With the sweep desc constructed above, we'll create vPackets for each
	// of the local assets, then sign them all.
	firstLevelPkts, err := a.createAndSignSweepVpackets(
		assetOutputs, req, lfn.Ok(tapSweepDesc.firstLevel),
	).Unpack()
	if err != nil {
		return lfn.Err[tlv.Blob](err)
	}

	type packetList = []*tappsbt.VPacket
	var (
		secondLevelPkts    packetList
		secondLevelSigDesc lfn.Option[cmsg.TapscriptSigDesc]
	)

	// We'll only need a set of second level packets if we're sweeping a set
	// of HTLC outputs on the local party's commitment transaction.
	if needsSecondLevel {
		log.Infof("Creating+signing 2nd level vPkts")

		// We'll make a placeholder for the second level output based
		// on the assetID+value tuples.
		secondLevelInputs := fn.Map(
			assetOutputs,
			func(a *cmsg.AssetOutput) *cmsg.AssetOutput {
				return cmsg.NewAssetOutput(
					a.AssetID.Val, a.Amount.Val,
					a.Proof.Val,
				)
			},
		)

		// Unlike the first level packets, we can't yet sign the second
		// level packets yet, as we don't know what the sweeping
		// transaction will look like. So we'll just create them.
		secondLevelPkts, err = lfn.MapOption(
			//nolint:lll
			func(desc tapscriptSweepDesc) lfn.Result[packetList] {
				return a.createSweepVpackets(
					secondLevelInputs, lfn.Ok(desc), req,
				)
			},
		)(tapSweepDesc.secondLevel).UnwrapOr(
			lfn.Ok[packetList](nil),
		).Unpack()
		if err != nil {
			return lfn.Errf[tlv.Blob]("unable to make "+
				"second level pkts: %w", err)
		}

		// We'll update some of the details of the 2nd level pkt based
		// on the first lvl packet created above (as we don't yet have
		// the full proof for the first lvl packet above).
		for pktIdx, vPkt := range secondLevelPkts {
			prevAsset := firstLevelPkts[pktIdx].Outputs[0].Asset

			for inputIdx, vIn := range vPkt.Inputs {
				//nolint:lll
				prevScriptKey := prevAsset.ScriptKey
				vIn.PrevID.ScriptKey = asset.ToSerialized(
					prevScriptKey.PubKey,
				)

				vPkt.SetInputAsset(inputIdx, prevAsset)
			}
		}

		// With the vPackets fully generated and signed above, we'll
		// serialize it into a resolution blob to return.
		secondLevelSigDesc = lfn.MapOption(
			func(d tapscriptSweepDesc) cmsg.TapscriptSigDesc {
				return cmsg.NewTapscriptSigDesc(
					d.scriptTree.TapTweak(),
					d.ctrlBlockBytes,
				)
			},
		)(tapSweepDesc.secondLevel)
	}

	res := cmsg.NewContractResolution(
		firstLevelPkts, secondLevelPkts, secondLevelSigDesc,
	)

	var b bytes.Buffer
	if err := res.Encode(&b); err != nil {
		return lfn.Err[tlv.Blob](err)
	}

	return lfn.Ok(b.Bytes())
}

// preimageDesc is a helper struct that contains the preimage and the witness
// index that the preimage should be placed within the witness stack. This is
// useful as in an earlier step, we've already pre-signed the witness, but will
// learn of the preimage later.
type preimageDesc struct {
	// preimage is the preimage that we'll use to update the witness stack.
	preimage lntypes.Preimage

	// witnessIndex is the index within the witness stack that the preimage
	// should be placed at.
	witnessIndex int
}

// blobWithWitnessInfo is a helper struct that contains a resolution blob, along
// with optional preimage information. If the preimage information is present,
// then we'll use this to update the witness stack of the final vPacket before
// we anchor it into the sweep output.
type blobWithWitnessInfo struct {
	// resolutionBlob is the serialized resolution blob that contains the
	// vPackets.
	resolutionBlob tlv.Blob

	// input is the sweep input that we created this blob using.
	input input.Input

	// preimageInfo is an optional field that contains the preimage and info
	// w.r.t where to place it in the witness stack.
	preimageInfo lfn.Option[preimageDesc]

	// secondLevel indicates if this is a second level sweep.
	secondLevel bool
}

// newBlobWithWitnessInfo creates a new blobWithWitnessInfo struct from a passed
// input.Input, which stores the resolution blob and other information.
func newBlobWithWitnessInfo(i input.Input) blobWithWitnessInfo {
	// If this is a success input, then we'll need to extract the preimage
	// from the inner struct, so we can update the witness stack.
	var (
		preimageInfo lfn.Option[preimageDesc]
		secondLevel  bool
	)
	switch i.WitnessType() {
	// This is the case when we're sweeping the HTLC output on our local

	// commitment transaction via a second level HTLC.
	//
	// The final witness stack is:
	//  * <sender sig> <receiver sig> <preimage> <success_script>
	//    <control_block>
	//
	// So we'll place the preimage at index 2.
	case input.TaprootHtlcAcceptedLocalSuccess:
		preimage := i.Preimage()

		preimageInfo = lfn.MapOption(
			func(p lntypes.Preimage) preimageDesc {
				return preimageDesc{
					preimage:     p,
					witnessIndex: 2,
				}
			},
		)(preimage)

	// This is the case when we're sweeping the HTLC output we received on
	// the remote party's version of the commitment transaction.
	//
	// The final witness stack is:
	//  <receiver sig> <preimage> <success_script> <control_block>
	//
	//  So we'll place the preimage at index 1.
	case input.TaprootHtlcAcceptedRemoteSuccess:
		preimage := i.Preimage()

		preimageInfo = lfn.MapOption(
			func(p lntypes.Preimage) preimageDesc {
				return preimageDesc{
					preimage:     p,
					witnessIndex: 1,
				}
			},
		)(preimage)

	// For second level sweeps, we don't need to note anything about a
	// preimage, but will note that this is a second level output.
	case input.TaprootHtlcOfferedTimeoutSecondLevel:
		fallthrough
	case input.TaprootHtlcAcceptedSuccessSecondLevel:
		secondLevel = true
	}

	// We already know this has a blob from the filter in an earlier step.
	return blobWithWitnessInfo{
		resolutionBlob: i.ResolutionBlob().UnwrapOr(nil),
		input:          i,
		preimageInfo:   preimageInfo,
		secondLevel:    secondLevel,
	}
}

// prepVpkts decodes the set of vPkts, supplementing them as needed to ensure
// all inputs can be swept properly.
func prepVpkts(bRes blobWithWitnessInfo,
	secondLevel bool) (*vPktsWithInput, error) {

	var res cmsg.ContractResolution
	err := res.Decode(bytes.NewReader(bRes.resolutionBlob))
	if err != nil {
		return nil, err
	}

	// For each vPacket, if we have a preimage to insert, then we'll we'll
	// update the witness to insert the preimage at the correct index.
	var tapSigDesc lfn.Option[cmsg.TapscriptSigDesc]
	pkts := res.Vpkts1()
	if secondLevel {
		pkts = res.Vpkts2()
		tapSigDesc = res.SigDescs()
	}

	err = lfn.MapOptionZ(bRes.preimageInfo, func(p preimageDesc) error {
		for _, pkt := range pkts {
			newAsset := pkt.Outputs[0].Asset

			prevWitness := newAsset.PrevWitnesses[0].TxWitness
			prevWitness = slices.Insert(
				prevWitness, p.witnessIndex,
				p.preimage[:],
			)
			err := newAsset.UpdateTxWitness(0, prevWitness)
			if err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return &vPktsWithInput{
		vPkts:      pkts,
		btcInput:   bRes.input,
		tapSigDesc: tapSigDesc,
	}, nil
}

// extractInputVPackets extracts the vPackets from the inputs passed in. If
// none of the inputs have any resolution blobs. Then an empty slice will be
// returned.
func extractInputVPackets(inputs []input.Input) lfn.Result[sweepVpkts] {
	// First, we'll extract the set of resolution blobs from the inputs
	// passed in.
	relevantInputs := fn.Filter(inputs, func(i input.Input) bool {
		return i.ResolutionBlob().IsSome()
	})
	resolutionInfo := fn.Map(
		relevantInputs, newBlobWithWitnessInfo,
	)

	firstLevelSweeps := lfn.Filter(
		resolutionInfo,
		func(info blobWithWitnessInfo) bool {
			return !info.secondLevel
		},
	)
	secondLevelSweeps := lfn.Filter(
		resolutionInfo,
		func(info blobWithWitnessInfo) bool {
			return info.secondLevel
		},
	)

	// With our set of resolution inputs extracted, we'll now decode them in
	// the vPackets we'll use to generate the output to addr.
	var vPkts1 []vPktsWithInput
	for _, bRes := range firstLevelSweeps {
		vpkt, err := prepVpkts(bRes, false)
		if err != nil {
			return lfn.Err[sweepVpkts](err)
		}

		vPkts1 = append(vPkts1, *vpkt)
	}

	var vPkts2 []vPktsWithInput
	for _, bRes := range secondLevelSweeps {
		vpkt, err := prepVpkts(bRes, true)
		if err != nil {
			return lfn.Err[sweepVpkts](err)
		}

		vPkts2 = append(vPkts2, *vpkt)
	}

	return lfn.Ok(sweepVpkts{
		firstLevel:  vPkts1,
		secondLevel: vPkts2,
	})
}

// sweepContracts takes a set of inputs, and the change address we'd use to
// sweep then, then maybe generate an extra sweep output that we should add to
// the sweeping transaction.
func (a *AuxSweeper) sweepContracts(inputs []input.Input,
	change lnwallet.AddrWithKey) lfn.Result[sweep.SweepOutput] {

	type returnType = sweep.SweepOutput

	// If none of the inputs have a resolution blob, then we have nothing
	// to generate.
	if fn.NotAny(inputs, func(i input.Input) bool {
		return !i.ResolutionBlob().IsNone()
	}) {

		return lfn.Err[returnType](nil)
	}

	// TODO(roasbeef): can pipline entire thing instead?

	// Now that we know we have a relevant input set, extract all the
	// vPackets from the inputs.
	sPkts, err := extractInputVPackets(inputs).Unpack()
	if err != nil {
		return lfn.Err[returnType](err)
	}

	log.Infof("Generating anchor output for vpkts=%v",
		limitSpewer.Sdump(sPkts))

	// If this is a sweep from the local commitment transaction. Then we'll
	// have both the first and second level sweeps. However for the first
	// sweep, it's a broadcast of a pre-signed transaction, so we don't need
	// an anchor output for those.
	directPkts := sPkts.directSpendPkts()

	// If there're no direct level vPkts, then we can just return a nil
	// error as we don't have a real sweep output to create.
	if len(directPkts) == 0 {
		return lfn.Err[sweep.SweepOutput](nil)
	}

	// At this point, now that we're about to generate a new output, we'll
	// need an internal key, so we can update all the vPkts.
	//
	// TODO(roasbeef); cache used internal key to prevent addr inflation
	// equiv?
	internalKey, err := a.cfg.AddrBook.NextInternalKey(
		context.Background(), asset.TaprootAssetsKeyFamily,
	)
	if err != nil {
		return lfn.Err[returnType](err)
	}
	for idx := range directPkts {
		for _, vOut := range directPkts[idx].Outputs {
			vOut.SetAnchorInternalKey(
				internalKey, a.cfg.ChainParams.HDCoinType,
			)
		}
	}

	// For any second level outputs we're sweeping, we'll need to sign for
	// it, as now we know the txid of the sweeping transaction. We'll do
	// this again when we register for the final broadcast, we we need to
	// sign the right prevIDs.
	for _, sweepSet := range sPkts.secondLevel {
		for _, vPkt := range sweepSet.vPkts {
			prevOut := sweepSet.btcInput.OutPoint()
			for _, vIn := range vPkt.Inputs {
				vIn.PrevID.OutPoint = prevOut
			}
			for _, vOut := range vPkt.Outputs {
				//nolint:lll
				vOut.Asset.PrevWitnesses[0].PrevID.OutPoint = prevOut
			}
		}
	}

	// Now that we have our set of resolutions, we'll make a new commitment
	// out of all the vPackets contained.
	outCommitments, err := tapsend.CreateOutputCommitments(directPkts)
	if err != nil {
		return lfn.Errf[returnType]("unable to create "+
			"output commitments: %w", err)
	}

	// We should only have a single output commitment at this point.
	if len(outCommitments) != 1 {
		return lfn.Errf[returnType]("expected a single output "+
			"commitment, got: %v", len(outCommitments))
	}

	// With the output commitments created, we'll now create the anchor
	// output script that commits to all the sweeps we've generated.
	anchorPkScript, _, _, err := tapsend.AnchorOutputScript(
		internalKey.PubKey, nil, outCommitments[0],
	)
	if err != nil {
		return lfn.Err[returnType](err)
	}

	return lfn.Ok(sweep.SweepOutput{
		TxOut: wire.TxOut{
			PkScript: anchorPkScript,
			Value:    int64(tapsend.DummyAmtSats),
		},
		IsExtra:     true,
		InternalKey: lfn.Some(internalKey),
	})
}

// sweepExclusionProofGen is a helper function that generates an exclusion
// proof for the internal key of the change output.
func sweepExclusionProofGen(sweepInternalKey keychain.KeyDescriptor,
	changeOutputIndex uint32) tapsend.ExclusionProofGenerator {

	return func(target *proof.BaseProofParams,
		isAnchor tapsend.IsAnchor) error {

		// We only need to generate an exclusion proof for the second
		// output in the commitment transaction.
		target.ExclusionProofs = append(
			target.ExclusionProofs, proof.TaprootProof{
				OutputIndex: changeOutputIndex,
				InternalKey: sweepInternalKey.PubKey,
				TapscriptProof: &proof.TapscriptProof{
					Bip86: true,
				},
			},
		)

		return nil
	}
}

// registerAndBroadcastSweep finalizes a sweep attempt by generating a
// transition proof for it, then registering the sweep with the porter.
func (a *AuxSweeper) registerAndBroadcastSweep(req *sweep.BumpRequest,
	sweepTx *wire.MsgTx, fee btcutil.Amount,
	outpointToTxIndex map[wire.OutPoint]int) error {

	// TODO(roasbeef): need to handle replacement -- will porter just
	// upsert in place?

	log.Infof("Register broadcast of sweep_tx=%v",
		limitSpewer.Sdump(sweepTx))

	// In order to properly register the sweep, we'll need to first extra a
	// unified set of vPackets from the specified inputs.
	vPkts, err := extractInputVPackets(req.Inputs).Unpack()
	if err != nil {
		return err
	}

	// If we don't have any vPackets that had our resolution data in them,
	// then we can exit early.
	if len(vPkts.firstLevel) == 0 && len(vPkts.secondLevel) == 0 {
		log.Infof("Sweep request had no vPkts, exiting")
		return nil
	}

	// If this is a transaction that's only sweeping HTLC outputs via a
	// pre-signed transaction, then we won't actually have an extra sweep
	// output.
	err = lfn.MapOptionZ(
		req.ExtraTxOut,
		func(extraTxOut sweep.SweepOutput) error {
			ourSweepOutput, err := req.ExtraTxOut.UnwrapOrErr(
				fmt.Errorf("extra tx out not populated"),
			)
			if err != nil {
				return err
			}
			iKey, err := ourSweepOutput.InternalKey.UnwrapOrErr(
				fmt.Errorf("internal key not populated"),
			)
			if err != nil {
				return err
			}

			// We'll also use the passed in context to set the
			// anchor key again for all the vOuts, but only for
			// first level vPkts, as second level packets already
			// commit to the internal key of the vOut.
			vPkts := vPkts.directSpendPkts()
			for idx := range vPkts {
				for _, vOut := range vPkts[idx].Outputs {
					vOut.SetAnchorInternalKey(
						iKey,
						a.cfg.ChainParams.HDCoinType,
					)
				}
			}

			return nil
		},
	)
	if err != nil {
		return err
	}

	// For any second level outputs we're sweeping, we'll need to sign for
	// it, as now we know the txid of the sweeping transaction.
	for _, sweepSet := range vPkts.secondLevel {
		for _, vPkt := range sweepSet.vPkts {
			prevOut := sweepSet.btcInput.OutPoint()
			for _, vIn := range vPkt.Inputs {
				vIn.PrevID.OutPoint = prevOut
			}

			for _, vOut := range vPkt.Outputs {
				//nolint:lll
				vOut.Asset.PrevWitnesses[0].PrevID.OutPoint = prevOut
			}
		}
	}

	// For pre-signed HTLC txns we'll need to make sure we update the output
	// index in the vPkt. As the ordering is only determined at broadcast
	// time.
	if outpointToTxIndex != nil {
		for _, sweepPkt := range vPkts.allVpktsWithInput() {
			op := sweepPkt.btcInput.OutPoint()
			finalOutputIndex, ok := outpointToTxIndex[op]
			if !ok {
				continue
			}

			for _, vPkt := range sweepPkt.vPkts {
				for _, vOut := range vPkt.Outputs {
					vOut.AnchorOutputIndex = uint32(
						finalOutputIndex,
					)
				}
			}
		}
	}

	// If we have second level vPkts, then we'll need to sign them here, as
	// now we know the input we're spending which was set above.
	for _, sweepSet := range vPkts.secondLevel {
		tapSigDesc, err := sweepSet.tapSigDesc.UnwrapOrErr(
			fmt.Errorf("tap sig desc not populated"),
		)
		if err != nil {
			return err
		}

		err = a.signSweepVpackets(
			sweepSet.vPkts, *sweepSet.btcInput.SignDesc(),
			tapSigDesc.TapTweak.Val, tapSigDesc.CtrlBlock.Val,
			lfn.None[lnwallet.AuxSigDesc](),
			lfn.None[uint32](),
		)
		if err != nil {
			return fmt.Errorf("unable to sign second level "+
				"vPkts: %w", err)
		}
	}

	// Now that we have our vPkts, we'll re-create the output commitments.
	outCommitments, err := tapsend.CreateOutputCommitments(vPkts.allPkts())
	if err != nil {
		return fmt.Errorf("unable to create output "+
			"commitments: %w", err)
	}

	// We need to find out what the highest output index of any asset output
	// commitments is, so we know the change output will be one higher.
	highestOutputIndex := uint32(0)
	for outIdx := range outCommitments {
		if outIdx > highestOutputIndex {
			highestOutputIndex = outIdx
		}
	}

	changeInternalKey, err := req.DeliveryAddress.InternalKey.UnwrapOrErr(
		fmt.Errorf("change internal key not populated"),
	)
	if err != nil {
		return err
	}

	log.Infof("Generating exclusion proofs using change_internal_key=%x",
		changeInternalKey.PubKey.SerializeCompressed())

	// Before we ship off the packet, we'll update the transition proof for
	// all the relevant outputs. We use a custom proof suffix generator as
	// we have only a single non-asset output.
	//
	// TODO(roasbeef): base off allocations? then can serialize, then
	// re-use the logic
	allVpkts := vPkts.allPkts()
	for idx := range allVpkts {
		vPkt := allVpkts[idx]
		for outIdx := range vPkt.Outputs {
			// The change output is always the last output in the
			// commitment transaction, one index higher than the
			// highest asset commitment output index.
			exclusionCreator := sweepExclusionProofGen(
				changeInternalKey, highestOutputIndex+1,
			)

			proofSuffix, err := tapsend.CreateProofSuffixCustom(
				sweepTx, vPkt, outCommitments, outIdx, allVpkts,
				exclusionCreator,
			)
			if err != nil {
				return fmt.Errorf("unable to create proof "+
					"suffix for output %d: %w", outIdx, err)
			}

			vPkt.Outputs[outIdx].ProofSuffix = proofSuffix
		}
	}

	log.Infof("Proofs generated for sweep_tx=%v",
		limitSpewer.Sdump(sweepTx))

	// With the output commitments re-created, we have all we need to log
	// and ship the transaction.
	//
	// We pass false for the last arg as we already updated our suffix
	// proofs here.
	return shipChannelTxn(
		a.cfg.TxSender, sweepTx, outCommitments, allVpkts, int64(fee),
	)
}

// contractResolver is the main loop that resolves contract resolution
// requests.
//
// NOTE: This MUST be run as a goroutine.
func (a *AuxSweeper) contractResolver() {
	defer a.wg.Done()

	for {
		select {
		case req := <-a.resolutionReqs:
			req.resp <- a.resolveContract(req.req)

		case req := <-a.sweepAddrReqs:
			req.resp <- a.sweepContracts(req.inputs, req.change)

		case req := <-a.broadcastReqs:
			req.resp <- a.registerAndBroadcastSweep(
				req.req, req.tx, req.fee,
				req.outpointToTxIndex,
			)

		case <-a.quit:
			return
		}
	}
}

// ResolveContract attempts to obtain a resolution blob for the specified
// contract.
func (a *AuxSweeper) ResolveContract(
	req lnwallet.ResolutionReq) lfn.Result[tlv.Blob] {

	type returnType = tlv.Blob

	auxReq := &resolutionReq{
		req:  req,
		resp: make(chan lfn.Result[tlv.Blob], 1),
	}

	if !fn.SendOrQuit(a.resolutionReqs, auxReq, a.quit) {
		return lfn.Errf[returnType]("aux sweeper stopped")
	}

	resp, quitErr := fn.RecvResp(auxReq.resp, nil, a.quit)
	if quitErr != nil {
		return lfn.Err[returnType](quitErr)
	}

	return resp
}

// DeriveSweepAddr takes a set of inputs, and the change address we'd use to
// sweep them, and maybe results an extra sweep output that we should add to
// the sweeping transaction.
func (a *AuxSweeper) DeriveSweepAddr(inputs []input.Input,
	change lnwallet.AddrWithKey) lfn.Result[sweep.SweepOutput] {

	type returnType = sweep.SweepOutput

	auxReq := &sweepAddrReq{
		inputs: inputs,
		change: change,
		resp:   make(chan lfn.Result[sweep.SweepOutput], 1),
	}

	if !fn.SendOrQuit(a.sweepAddrReqs, auxReq, a.quit) {
		return lfn.Err[returnType](fmt.Errorf("aux sweeper stopped"))
	}

	resp, quitErr := fn.RecvResp(auxReq.resp, nil, a.quit)
	if quitErr != nil {
		return lfn.Err[returnType](quitErr)
	}

	return resp
}

// ExtraBudgetForInputs takes a set of inputs and maybe returns an extra budget
// that should be added to the sweep transaction.
func (a *AuxSweeper) ExtraBudgetForInputs(
	inputs []input.Input) lfn.Result[btcutil.Amount] {

	inputsWithBlobs := fn.Filter(inputs, func(i input.Input) bool {
		return i.ResolutionBlob().IsSome()
	})

	var extraBudget btcutil.Amount
	if len(inputsWithBlobs) != 0 {
		// In this case, just 1k sats (tapsend.DummyAmtSats) may not be
		// enough budget to pay for sweeping. So instead, we'll use a
		// multiple of this to ensure that any time we care about an
		// output, we're pretty much always able to sweep it.
		//
		// TODO(roasbeef): return the sats equiv budget of the asset
		// amount
		extraBudget = tapsend.DummyAmtSats * btcutil.Amount(
			sweeperBudgetMultiplier*len(inputsWithBlobs),
		)
	}

	return lfn.Ok(extraBudget)
}

// NotifyBroadcast is used to notify external callers of the broadcast of a
// sweep transaction, generated by the passed BumpRequest.
func (a *AuxSweeper) NotifyBroadcast(req *sweep.BumpRequest,
	tx *wire.MsgTx, fee btcutil.Amount,
	outpointToTxIndex map[wire.OutPoint]int) error {

	auxReq := &broadcastReq{
		req:               req,
		tx:                tx,
		fee:               fee,
		outpointToTxIndex: outpointToTxIndex,
		resp:              make(chan error, 1),
	}

	if !fn.SendOrQuit(a.broadcastReqs, auxReq, a.quit) {
		return fmt.Errorf("aux sweeper stopped")
	}

	resp, err := fn.RecvResp(auxReq.resp, nil, a.quit)
	if err != nil {
		return err
	}

	return resp
}

// TweakedRevocationKeyRing returns a new commitment key ring with the
// revocation key tweaked by the given HTLC index. The revocation key is tweaked
// in order to achieve uniqueness for each HTLC output on the asset level. This
// same tweak will need to be applied to the revocation private key in case of
// a breach.
func TweakedRevocationKeyRing(keyRing *lnwallet.CommitmentKeyRing,
	index input.HtlcIndex) *lnwallet.CommitmentKeyRing {

	return &lnwallet.CommitmentKeyRing{
		CommitPoint:         keyRing.CommitPoint,
		LocalCommitKeyTweak: keyRing.LocalCommitKeyTweak,
		LocalHtlcKeyTweak:   keyRing.LocalHtlcKeyTweak,
		LocalHtlcKey:        keyRing.LocalHtlcKey,
		RemoteHtlcKey:       keyRing.RemoteHtlcKey,
		ToLocalKey:          keyRing.ToLocalKey,
		ToRemoteKey:         keyRing.ToRemoteKey,
		RevocationKey: TweakPubKeyWithIndex(
			keyRing.RevocationKey, index,
		),
	}
}
