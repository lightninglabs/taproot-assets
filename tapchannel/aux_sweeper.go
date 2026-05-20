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
	"github.com/lightninglabs/taproot-assets/commitment"
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

	// IgnoreChecker is an optional function that can be used to check if
	// a proof should be ignored.
	IgnoreChecker lfn.Option[proof.IgnoreChecker]
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
	secondLevelSigIndex lfn.Option[uint32],
	witnessScript []byte) error {

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
		virtualSignDesc := signDesc
		virtualSignDesc.WitnessScript = witnessScript
		virtualSignDesc.ControlBlock = ctrlBlock

		signingKey, leafToSign := applySignDescToVIn(
			virtualSignDesc, vIn, &a.cfg.ChainParams, tapTweak,
		)

		// In this case, the witness isn't special, so we'll set the
		// control block now for it.
		vIn.TaprootLeafScript[0].ControlBlock = ctrlBlock

		log.Debugf("signing vPacket for input=%v",
			limitSpewer.Sdump(vIn.PrevID))

		// With everything set, we can now sign the new leaf we'll
		// sweep into.
		ctxb := context.Background()
		signed, err := a.cfg.Signer.SignVirtualPacket(
			ctxb, vPacket, tapfreighter.SkipInputProofVerify(),
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
		var err error

		witnessScript := desc.witnessScript
		if len(witnessScript) == 0 {
			witnessScript, err =
				desc.scriptTree.WitnessScriptForPath(
					desc.scriptPath,
				)
			if err != nil {
				return lfn.Errf[returnType](
					"unable to derive witness script: %w",
					err,
				)
			}
		}

		ctrlBlockBytes := desc.ctrlBlockBytes
		tapTweak := desc.scriptTree.TapTweak()
		if len(ctrlBlockBytes) != 0 && len(desc.witnessScript) != 0 {
			ctrlBlock, err := txscript.ParseControlBlock(
				ctrlBlockBytes,
			)
			if err != nil {
				return lfn.Errf[returnType](
					"unable to parse control block: %w",
					err,
				)
			}

			tapTweak = ctrlBlock.RootHash(witnessScript)
		}

		err = a.signSweepVpackets(
			vPkts, signDesc, tapTweak, ctrlBlockBytes,
			desc.auxSigInfo,
			desc.secondLevelSigIndex, witnessScript,
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

	scriptPath input.ScriptPath

	ctrlBlockBytes []byte

	witnessScript []byte

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
			scriptPath:     input.ScriptPathSuccess,
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
			scriptPath:     input.ScriptPathSuccess,
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
			scriptPath:     input.ScriptPathRevocation,
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
			scriptPath:     input.ScriptPathTimeout,
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
			scriptPath:     input.ScriptPathSuccess,
		},
	})
}

// localHtlcTimeoutSweepDesc creates a sweep desc for an HTLC output that is
// present on our local commitment transaction. These are second level HTLCs, so
// we'll need to perform two stages of sweeps.
func localHtlcTimeoutSweepDesc(req lnwallet.ResolutionReq,
	keyRing *lnwallet.CommitmentKeyRing,
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
	tweakedKeyRing := TweakedRevocationKeyRing(keyRing, index)

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
		tweakedKeyRing.RevocationKey, keyRing.ToLocalKey,
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
		scriptPath:     input.ScriptPathSuccess,
		relativeDelay:  lfn.Some(uint64(req.CommitCsvDelay)),
		ctrlBlockBytes: secondLevelCtrlBlockBytes,
	}

	return lfn.Ok(tapscriptSweepDescs{
		firstLevel: tapscriptSweepDesc{
			scriptTree:          htlcScriptTree,
			scriptPath:          input.ScriptPathTimeout,
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
	keyRing *lnwallet.CommitmentKeyRing,
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
	tweakedKeyRing := TweakedRevocationKeyRing(keyRing, index)

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
		tweakedKeyRing.RevocationKey, keyRing.ToLocalKey,
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
		scriptPath:     input.ScriptPathSuccess,
		relativeDelay:  lfn.Some(uint64(req.CommitCsvDelay)),
		ctrlBlockBytes: secondLevelCtrlBlockBytes,
	}

	return lfn.Ok(tapscriptSweepDescs{
		firstLevel: tapscriptSweepDesc{
			scriptTree:          htlcScriptTree,
			scriptPath:          input.ScriptPathSuccess,
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

// reanchorAssetOutputs updates each asset output proof so that it references
// the actual commitment transaction output. Proofs are initially built using
// a synthetic commitment template. Once the real commitment transaction is
// known, we rewrite the proof's anchor transaction and output indexes.
func reanchorAssetOutputs(ctx context.Context,
	chainBridge tapgarden.ChainBridge, commitTx wire.MsgTx,
	commitTxBlockHeight uint32, outputs []*cmsg.AssetOutput) error {

	if len(outputs) == 0 {
		return nil
	}

	// Only fetch block data if any proof is missing it.
	proofBlockParams, err := proofParamsForCommitTx(
		ctx, chainBridge, commitTxBlockHeight, commitTx,
	)
	if err != nil {
		return fmt.Errorf("constructing proof block params: %w", err)
	}

	for _, output := range outputs {
		p := &output.Proof.Val

		// Derive the Taproot output script for this proof so we can
		// locate the correct output index in the real commitment
		// transaction.
		pkScript, tapKey, err := p.TaprootOutputScript()
		if err != nil {
			return err
		}

		var idx = -1
		for outIdx, txOut := range commitTx.TxOut {
			if bytes.Equal(txOut.PkScript, pkScript) {
				idx = outIdx
				break
			}
		}

		if idx < 0 {
			return fmt.Errorf("no matching commit output found "+
				"for asset %x (tap_key=%x)", output.AssetID.Val,
				schnorr.SerializePubKey(tapKey))
		}

		err = p.UpdateTransitionProof(&proofBlockParams)
		if err != nil {
			return fmt.Errorf("failed to populate proof block: %w",
				err)
		}

		// Ensure the anchor transaction actually spends the previous
		// asset outpoint. Return an error if the stored PrevOut doesn't
		// match any input.
		if len(commitTx.TxIn) == 0 {
			return fmt.Errorf("commit tx %v has no inputs",
				commitTx.TxHash())
		}
		prevMatches := false
		for _, txIn := range commitTx.TxIn {
			if txIn.PreviousOutPoint == p.PrevOut {
				prevMatches = true
				break
			}
		}
		if !prevMatches {
			return fmt.Errorf("commit tx does not spend PrevOut "+
				"(txid=%s, prev_out=%s)",
				commitTx.TxHash().String(), p.PrevOut.String())
		}

		p.AnchorTx = commitTx
		p.InclusionProof.OutputIndex = uint32(idx)
	}

	return nil
}

// syncCommitOutputProofs updates the stored commitment-state proofs for a set
// of local/remote commitment outputs to use the actual tapscript tree that
// backs that output on the commitment transaction.
func syncCommitOutputProofs(outputs []*cmsg.AssetOutput,
	scriptDesc input.ScriptDescriptor) error {

	if len(outputs) == 0 {
		return nil
	}

	leaves, tree, err := LeavesFromTapscriptScriptTree(scriptDesc)
	if err != nil {
		return err
	}

	var siblingPreimage *commitment.TapscriptPreimage
	switch len(leaves) {
	case 0:
		// No sibling tapscript tree.

	case 1:
		siblingPreimage, err = commitment.NewPreimageFromLeaf(leaves[0])
		if err != nil {
			return err
		}

	default:
		rootNode := txscript.AssembleTaprootScriptTree(
			leaves...,
		).RootNode
		branch, ok := rootNode.(txscript.TapBranch)
		if !ok {
			return fmt.Errorf(
				"expected tapscript root branch, got %T",
				rootNode,
			)
		}

		preimage := commitment.NewPreimageFromBranch(branch)
		siblingPreimage = &preimage
	}

	for _, output := range outputs {
		p := &output.Proof.Val
		p.InclusionProof.InternalKey = tree.InternalKey
		if p.InclusionProof.CommitmentProof != nil {
			p.InclusionProof.CommitmentProof.TapSiblingPreimage =
				siblingPreimage
		}
	}

	return nil
}

// commitOutputAllocations creates exclusion-proof allocations for the actual
// pure-BTC outputs of the commitment transaction. This must reflect the real
// commitment tx outputs instead of assuming only anchor outputs exist.
func commitOutputAllocations(req lnwallet.ResolutionReq,
	keyRing *lnwallet.CommitmentKeyRing,
	vPackets []*tappsbt.VPacket) lfn.Result[[]*tapsend.Allocation] {

	if req.CommitTx == nil {
		return lfn.Err[[]*tapsend.Allocation](
			fmt.Errorf("commit tx not set"),
		)
	}

	assetOutputs := make(map[uint32]struct{})
	for _, vPkt := range vPackets {
		for _, output := range vPkt.Outputs {
			assetOutputs[output.AnchorOutputIndex] = struct{}{}
		}
	}

	findOutputIndex := func(pkScript []byte) (uint32, bool) {
		for idx, txOut := range req.CommitTx.TxOut {
			if bytes.Equal(txOut.PkScript, pkScript) {
				return uint32(idx), true
			}
		}

		return 0, false
	}

	newNoAssetAlloc := func(desc input.ScriptDescriptor) (
		[]*tapsend.Allocation, error,
	) {

		sibling, scriptTree, err := LeavesFromTapscriptScriptTree(desc)
		if err != nil {
			return nil, err
		}

		pkScript, err := txscript.PayToTaprootScript(
			scriptTree.TaprootKey,
		)
		if err != nil {
			return nil, err
		}

		outputIndex, ok := findOutputIndex(pkScript)
		if !ok {
			return nil, nil
		}

		if _, hasAssets := assetOutputs[outputIndex]; hasAssets {
			return nil, nil
		}

		return []*tapsend.Allocation{{
			Type:        tapsend.AllocationTypeNoAssets,
			OutputIndex: outputIndex,
			BtcAmount: btcutil.Amount(
				req.CommitTx.TxOut[outputIndex].Value,
			),
			InternalKey:    scriptTree.InternalKey,
			NonAssetLeaves: sibling,
			SortTaprootKeyBytes: schnorr.SerializePubKey(
				scriptTree.TaprootKey,
			),
		}}, nil
	}

	toLocalTree, err := input.NewLocalCommitScriptTree(
		req.CsvDelay, keyRing.ToLocalKey, keyRing.RevocationKey,
		input.NoneTapLeaf(),
	)
	if err != nil {
		return lfn.Err[[]*tapsend.Allocation](err)
	}

	toRemoteTree, err := input.NewRemoteCommitScriptTree(
		keyRing.ToRemoteKey, input.NoneTapLeaf(),
	)
	if err != nil {
		return lfn.Err[[]*tapsend.Allocation](err)
	}

	localAnchorTree, err := input.NewAnchorScriptTree(keyRing.ToLocalKey)
	if err != nil {
		return lfn.Err[[]*tapsend.Allocation](err)
	}

	remoteAnchorTree, err := input.NewAnchorScriptTree(keyRing.ToRemoteKey)
	if err != nil {
		return lfn.Err[[]*tapsend.Allocation](err)
	}

	allocations := make([]*tapsend.Allocation, 0, 4)
	for _, desc := range []input.ScriptDescriptor{
		toLocalTree, toRemoteTree, localAnchorTree, remoteAnchorTree,
	} {
		allocs, err := newNoAssetAlloc(desc)
		if err != nil {
			return lfn.Err[[]*tapsend.Allocation](err)
		}

		allocations = append(allocations, allocs...)
	}

	return lfn.Ok(allocations)
}

func commitScriptKeyForRing(req lnwallet.ResolutionReq,
	keyRing *lnwallet.CommitmentKeyRing) lfn.Result[asset.ScriptKey] {

	switch req.Type {
	case input.TaprootLocalCommitSpend:
		return localCommitScriptKey(
			keyRing.ToLocalKey, keyRing.RevocationKey, req.CsvDelay,
		)

	case input.TaprootRemoteCommitSpend:
		return remoteCommitScriptKey(keyRing.ToRemoteKey)

	case input.TaprootCommitmentRevoke:
		csvDelay := req.BreachCsvDelay.UnwrapOr(req.CsvDelay)
		return localCommitScriptKey(
			keyRing.ToLocalKey, keyRing.RevocationKey, csvDelay,
		)

	default:
		return lfn.Errf[asset.ScriptKey]("unsupported commit witness "+
			"type: %v", req.Type)
	}
}

func selectCommitmentKeyRing(req lnwallet.ResolutionReq,
	outputs []*cmsg.AssetOutput) *lnwallet.CommitmentKeyRing {

	if req.InitialKeyRing == nil || len(outputs) == 0 {
		return req.KeyRing
	}

	currentKey, err := commitScriptKeyForRing(req, req.KeyRing).Unpack()
	if err != nil {
		return req.KeyRing
	}

	initialKey, err := commitScriptKeyForRing(
		req, req.InitialKeyRing,
	).Unpack()
	if err != nil {
		return req.KeyRing
	}

	targetKey := outputs[0].Proof.Val.Asset.ScriptKey.PubKey
	switch {
	case targetKey.IsEqual(initialKey.PubKey):
		return req.InitialKeyRing

	case targetKey.IsEqual(currentKey.PubKey):
		return req.KeyRing

	default:
		return req.KeyRing
	}
}

func fetchStoredCommitSweepMetadata(outputs []*cmsg.AssetOutput) ([]byte,
	[]byte, bool) {

	for _, output := range outputs {
		unknownOddTypes := output.Proof.Val.UnknownOddTypes
		if len(unknownOddTypes) == 0 {
			continue
		}

		witnessScriptType := commitSweepWitnessScriptType
		witnessScript, ok := unknownOddTypes[witnessScriptType]
		if !ok {
			continue
		}

		controlBlock, ok := unknownOddTypes[commitSweepControlBlockType]
		if !ok {
			continue
		}

		return bytes.Clone(witnessScript),
			bytes.Clone(controlBlock), true
	}

	return nil, nil, false
}

func activeOutputsNeedReanchor(activeOutputs []*cmsg.AssetOutput,
	commitTx *wire.MsgTx) bool {

	if commitTx == nil {
		return false
	}

	for _, activeOutput := range activeOutputs {
		if activeOutput.Proof.Val.InclusionProof.OutputIndex >=
			uint32(len(commitTx.TxOut)) {

			return true
		}
	}

	return false
}

func selectResolveCommitmentKeyRing(req lnwallet.ResolutionReq,
	outputs []*cmsg.AssetOutput) *lnwallet.CommitmentKeyRing {

	if req.InitialKeyRing != nil &&
		activeOutputsNeedReanchor(outputs, req.CommitTx) {

		return req.InitialKeyRing
	}

	return selectCommitmentKeyRing(req, outputs)
}

func isCommitmentOutputResolution(witnessType input.WitnessType) bool {
	switch witnessType {
	case input.TaprootLocalCommitSpend,
		input.TaprootRemoteCommitSpend,
		input.TaprootCommitmentRevoke:
		return true

	default:
		return false
	}
}

func syncActiveVPacketProofsFromOutputs(
	vPktsByAssetID map[asset.ID]*tappsbt.VPacket,
	activeOutputs []*cmsg.AssetOutput) {

	for _, activeOutput := range activeOutputs {
		vPkt := vPktsByAssetID[activeOutput.AssetID.Val]
		if vPkt == nil {
			continue
		}

		// Prefer an exact match on amount+anchor index. In immediate
		// force-close flows, the vPacket can still carry a stale anchor
		// index before we sync from re-anchored active outputs, so we
		// also allow a fallback to a unique amount-only match.
		strictIdx := -1
		fallbackIdx := -1
		fallbackCount := 0

		for outIdx := range vPkt.Outputs {
			vOut := vPkt.Outputs[outIdx]
			if vOut.Amount != activeOutput.Amount.Val {
				continue
			}

			fallbackIdx = outIdx
			fallbackCount++

			targetIndex := activeOutput.Proof.Val.InclusionProof.
				OutputIndex
			if vOut.AnchorOutputIndex != targetIndex {
				continue
			}

			strictIdx = outIdx
			break
		}

		matchIdx := strictIdx
		if matchIdx == -1 && fallbackCount == 1 {
			matchIdx = fallbackIdx
		}
		if matchIdx == -1 {
			continue
		}

		vOut := vPkt.Outputs[matchIdx]
		updatedProof := activeOutput.Proof.Val
		vOut.ProofSuffix = &updatedProof
		if vOut.Asset != nil {
			vOut.Asset = updatedProof.Asset.Copy()
		}

		inclusionProof := updatedProof.InclusionProof
		vOut.AnchorOutputIndex = inclusionProof.OutputIndex
		vOut.AnchorOutputInternalKey = inclusionProof.InternalKey
		vOut.AnchorOutputTapscriptSibling = inclusionProof.
			CommitmentProof.TapSiblingPreimage
		vOut.ScriptKey = updatedProof.Asset.ScriptKey
	}
}

func syncActiveOutputProofsFromVPackets(
	vPktsByAssetID map[asset.ID]*tappsbt.VPacket,
	activeOutputs []*cmsg.AssetOutput) {

	for _, activeOutput := range activeOutputs {
		vPkt := vPktsByAssetID[activeOutput.AssetID.Val]
		if vPkt == nil {
			continue
		}

		for outIdx := range vPkt.Outputs {
			vOut := vPkt.Outputs[outIdx]
			if vOut.ProofSuffix == nil {
				continue
			}
			if vOut.Amount != activeOutput.Amount.Val {
				continue
			}
			targetIndex := activeOutput.Proof.Val.InclusionProof.
				OutputIndex
			if vOut.AnchorOutputIndex != targetIndex {
				continue
			}

			updatedProof := activeOutput.Proof.Val
			updatedProof.Asset = *vOut.ProofSuffix.Asset.Copy()
			updatedProof.InclusionProof =
				vOut.ProofSuffix.InclusionProof
			updatedProof.ExclusionProofs = fn.CopySlice(
				vOut.ProofSuffix.ExclusionProofs,
			)
			updatedProof.SplitRootProof =
				vOut.ProofSuffix.SplitRootProof
			updatedProof.AdditionalInputs = fn.CopySlice(
				vOut.ProofSuffix.AdditionalInputs,
			)
			updatedProof.ChallengeWitness = slices.Clone(
				vOut.ProofSuffix.ChallengeWitness,
			)
			updatedProof.AltLeaves = asset.CopyAltLeaves(
				vOut.ProofSuffix.AltLeaves,
			)
			updatedProof.UnknownOddTypes =
				vOut.ProofSuffix.UnknownOddTypes
			activeOutput.Proof.Val = updatedProof
			break
		}
	}
}

func (a *AuxSweeper) importActiveProofScriptKeys(
	activeOutputs []*cmsg.AssetOutput) error {

	ctxb := context.Background()

	for _, activeOutput := range activeOutputs {
		scriptKey := activeOutput.Proof.Val.Asset.ScriptKey
		if scriptKey.TweakedScriptKey == nil {
			scriptKey.TweakedScriptKey = &asset.TweakedScriptKey{
				RawKey: keychain.KeyDescriptor{
					PubKey: scriptKey.PubKey,
				},
			}
		}
		if scriptKey.RawKey.PubKey == nil {
			scriptKey.RawKey = keychain.KeyDescriptor{
				PubKey: scriptKey.PubKey,
			}
		}

		err := a.cfg.AddrBook.InsertScriptKey(
			ctxb, scriptKey, asset.ScriptKeyScriptPathChannel,
		)
		if err != nil {
			return fmt.Errorf("unable to import active proof "+
				"script key: %w", err)
		}
	}

	return nil
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
func deriveCommitKeys(req lnwallet.ResolutionReq,
	keyRing *lnwallet.CommitmentKeyRing) (*asset.ScriptKey,
	*asset.ScriptKey, error) {

	// This might be a breach case we need to handle. In this case, our
	// output is the remote output and their output is local here.
	// Therefore, we'll try to use the BreachCsvDelay if present,
	// otherwise, we'll stick with the main one specified.
	toLocalCsvDelay := req.BreachCsvDelay.UnwrapOr(req.CsvDelay)
	localScriptTree, err := localCommitScriptKey(
		keyRing.ToLocalKey, keyRing.RevocationKey,
		toLocalCsvDelay,
	).Unpack()
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create local "+
			"script key: %w", err)
	}

	remoteScriptTree, err := remoteCommitScriptKey(
		keyRing.ToRemoteKey,
	).Unpack()
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create remote "+
			"script key: %w", err)
	}

	return &localScriptTree, &remoteScriptTree, nil
}

// importCommitScriptKeys imports the script keys for the commitment outputs
// into the local addr book.
func (a *AuxSweeper) importCommitScriptKeys(req lnwallet.ResolutionReq,
	keyRing *lnwallet.CommitmentKeyRing) error {
	// Generate the local and remote script key, so we can properly import
	// into the addr book, like we did above.
	localCommitScriptKey, remoteCommitScriptKey, err := deriveCommitKeys(
		req, keyRing,
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
func importOutputProofs(ctx context.Context, scid lnwire.ShortChannelID,
	outputProofs []*proof.Proof, courierAddr *url.URL,
	proofDispatch proof.CourierDispatch, chainBridge tapgarden.ChainBridge,
	vCtx proof.VerifierCtx, proofArchive proof.Archiver) error {

	// TODO(roasbeef): should be part of post confirmation funding validate
	// (chanvalidate)

	log.Infof("Importing %v proofs for ChannelPoint(%v)",
		len(outputProofs), outputProofs[0].OutPoint())

	// With the fetcher created, we'll have it fetch each of the proofs for
	// the funding outputs we need.
	//
	// TODO(roasbeef): assume single asset for now, also additional inputs
	for _, proofToImport := range outputProofs {
		// Check if the proof is already imported to avoid redundant
		// work.
		fundingLocator := proof.Locator{
			AssetID:   fn.Ptr(proofToImport.Asset.ID()),
			ScriptKey: *proofToImport.Asset.ScriptKey.PubKey,
			OutPoint:  fn.Ptr(proofToImport.OutPoint()),
		}
		proofExists, err := proofArchive.HasProof(ctx, fundingLocator)
		if err != nil {
			return fmt.Errorf("unable to check if proof "+
				"exists: %w", err)
		}
		if proofExists {
			log.Infof("Proof already imported for %v, skipping",
				limitSpewer.Sdump(fundingLocator))
			continue
		}

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
		proofFetcher, err := proofDispatch.NewCourier(
			ctx, courierAddr, true,
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
			ctx, recipient, inputProofLocator,
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
		err = updateProofsFromShortChanID(
			ctx, chainBridge, scid, []*proof.Proof{proofToImport},
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

		err = proofArchive.ImportProofs(
			ctx, vCtx, false, &proof.AnnotatedProof{
				Locator: fundingLocator,
				Blob:    finalProofBuf.Bytes(),
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
	commitState *cmsg.Commitment, fundingInfo *cmsg.OpenChannel,
	activeOutputs []*cmsg.AssetOutput,
	activeScriptTree input.ScriptDescriptor) error {

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
	commitKeyRing := selectCommitmentKeyRing(req, activeOutputs)
	useInitialCommitState := req.InitialKeyRing != nil &&
		commitKeyRing == req.InitialKeyRing

	// To start, we'll re-create vPackets for all of the outputs of the
	// commitment transaction.
	//
	// We'll use the fundingInfo proofs to create a vIn for each of them.
	fundingInputProofs := make(map[asset.ID]*proof.Proof)
	for _, fundingInput := range fundingInfo.FundedAssets.Val.Outputs {
		inputProof := &fundingInput.Proof.Val
		fundingInputProofs[inputProof.Asset.ID()] = inputProof
	}

	// We'll always attempt to import the proof for the funding outputs.
	// It's possible that the initiator failed to do so after the funding
	// transaction confirmed.
	vCtx := proof.VerifierCtx{
		HeaderVerifier: a.cfg.HeaderVerifier,
		MerkleVerifier: proof.DefaultMerkleVerifier,
		GroupVerifier:  a.cfg.GroupVerifier,
		ChainLookupGen: a.cfg.ChainBridge,
		IgnoreChecker:  a.cfg.IgnoreChecker,
	}
	err = importOutputProofs(
		ctxb, req.ShortChanID, maps.Values(fundingInputProofs),
		a.cfg.DefaultCourierAddr, a.cfg.ProofFetcher,
		a.cfg.ChainBridge, vCtx, a.cfg.ProofArchive,
	)
	if err != nil {
		return fmt.Errorf("unable to import output "+
			"proofs: %w", err)
	}

	err = updateProofsFromShortChanID(
		ctxb, a.cfg.ChainBridge, req.ShortChanID,
		maps.Values(fundingInputProofs),
	)
	if err != nil {
		return fmt.Errorf("unable to update funding proofs: %w", err)
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

	if req.CommitTx == nil {
		return fmt.Errorf("no commitment transaction found for "+
			"chan_point=%v", req.ChanPoint)
	}
	if req.InitialKeyRing != nil &&
		activeOutputsNeedReanchor(activeOutputs, req.CommitTx) {

		useInitialCommitState = true
		commitKeyRing = req.InitialKeyRing
	}
	if err := a.importCommitScriptKeys(req, commitKeyRing); err != nil {
		return fmt.Errorf("unable to import script keys: %w", err)
	}

	if useInitialCommitState {
		toLocalScriptTree, err := input.NewLocalCommitScriptTree(
			req.CsvDelay, commitKeyRing.ToLocalKey,
			commitKeyRing.RevocationKey, input.NoneTapLeaf(),
		)
		if err != nil {
			return fmt.Errorf(
				"unable to derive to-local script tree: %w",
				err,
			)
		}
		err = syncCommitOutputProofs(
			commitState.LocalAssets.Val.Outputs, toLocalScriptTree,
		)
		if err != nil {
			return fmt.Errorf(
				"unable to sync local commit proofs: %w",
				err,
			)
		}

		toRemoteScriptTree, err := input.NewRemoteCommitScriptTree(
			commitKeyRing.ToRemoteKey, input.NoneTapLeaf(),
		)
		if err != nil {
			return fmt.Errorf(
				"unable to derive to-remote script tree: %w",
				err,
			)
		}
		err = syncCommitOutputProofs(
			commitState.RemoteAssets.Val.Outputs,
			toRemoteScriptTree,
		)
		if err != nil {
			return fmt.Errorf(
				"unable to sync remote commit proofs: %w",
				err,
			)
		}
		if len(activeOutputs) > 0 {
			err = syncCommitOutputProofs(
				activeOutputs, activeScriptTree,
			)
			if err != nil {
				return fmt.Errorf("unable to sync active "+
					"commit proofs: %w", err)
			}
		}

		// Only the first live post-funding commitment state needs this
		// proof refresh before re-anchoring to the unilateral-close tx.
		for _, outputs := range [][]*cmsg.AssetOutput{
			commitState.LocalAssets.Val.Outputs,
			commitState.RemoteAssets.Val.Outputs,
		} {
			err = reanchorAssetOutputs(
				ctxb, a.cfg.ChainBridge, *req.CommitTx,
				req.CommitTxBlockHeight, outputs,
			)
			if err != nil {
				return fmt.Errorf("unable to re-anchor "+
					"commit outputs: %w", err)
			}
		}
		if len(activeOutputs) > 0 {
			err = reanchorAssetOutputs(
				ctxb, a.cfg.ChainBridge, *req.CommitTx,
				req.CommitTxBlockHeight, activeOutputs,
			)
			if err != nil {
				return fmt.Errorf("unable to re-anchor active "+
					"commit outputs: %w", err)
			}
		}

		if _, err := commitScriptKeyForRing(
			req, commitKeyRing,
		).Unpack(); err == nil && len(activeOutputs) > 0 {
			syncActiveVPacketProofsFromOutputs(
				vPktsByAssetID, activeOutputs,
			)
		}
	}

	for _, vPkt := range vPktsByAssetID {
		for _, vOut := range vPkt.Outputs {
			if vOut.ProofSuffix == nil {
				continue
			}

			inclusionProof := vOut.ProofSuffix.InclusionProof
			vOut.AnchorOutputIndex = inclusionProof.OutputIndex
			vOut.AnchorOutputInternalKey =
				inclusionProof.InternalKey
			vOut.AnchorOutputTapscriptSibling = inclusionProof.
				CommitmentProof.TapSiblingPreimage
			vOut.ScriptKey = vOut.ProofSuffix.Asset.ScriptKey
		}
	}

	supportSTXO := commitState.STXO.Val

	// We can now add the witness for the OP_TRUE spend of the commitment
	// output to the vPackets.
	vPackets := maps.Values(vPktsByAssetID)
	if err := signCommitVirtualPackets(ctxb, vPackets); err != nil {
		return fmt.Errorf("error signing commit virtual "+
			"packets: %w", err)
	}

	var (
		opts      []tapsend.OutputCommitmentOption
		proofOpts []proof.GenOption
	)

	if !supportSTXO {
		opts = append(opts, tapsend.WithNoSTXOProofs())
		proofOpts = append(proofOpts, proof.WithNoSTXOProofs())
	}

	outCommitments, err := tapsend.CreateOutputCommitments(
		vPackets, opts...,
	)
	if err != nil {
		return fmt.Errorf("unable to create output "+
			"commitments: %w", err)
	}

	anchorAllocations, err := commitOutputAllocations(
		req, commitKeyRing, vPackets,
	).Unpack()
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
				vPackets, exclusionCreator, proofOpts...,
			)
			if err != nil {
				return fmt.Errorf("unable to create "+
					"proof suffix for output "+
					"%d: %w", outIdx, err)
			}

			if vPkt.Outputs[outIdx].ProofSuffix != nil {
				*vPkt.Outputs[outIdx].ProofSuffix = *proofSuffix
			} else {
				vPkt.Outputs[outIdx].ProofSuffix = proofSuffix
			}
		}
	}

	// For the first live post-funding commitment state, the active output
	// will later be swept directly from the imported commitment proof. Make
	// sure we keep the final proof suffix, including the regenerated
	// exclusion proofs, in sync with the active output we hand back to the
	// resolver and archive as ours.
	if useInitialCommitState && len(activeOutputs) > 0 {
		syncActiveOutputProofsFromVPackets(
			vPktsByAssetID, activeOutputs,
		)

		err = a.importActiveProofScriptKeys(activeOutputs)
		if err != nil {
			return err
		}
	}

	// TODO(roasbeef): import proof for receiver instead?

	// With all the vPKts created, we can now ship the transaction off to
	// the porter for final delivery. We use the commitment tx's block
	// height as the height hint so that the chain notifier can find the
	// confirmation even if the transaction was confirmed while we were
	// offline.
	heightHint := fn.None[uint32]()
	if req.CommitTxBlockHeight > 0 {
		heightHint = fn.Some(req.CommitTxBlockHeight)
	}

	return shipChannelTxn(
		a.cfg.TxSender, req.CommitTx, outCommitments, vPackets,
		int64(req.CommitFee), heightHint, true,
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
		commitKeyRing := selectResolveCommitmentKeyRing(
			req, assetOutputs,
		)
		sweepDesc = commitNoDelaySweepDesc(commitKeyRing, req.CsvDelay)

	// A normal delay output. This means we force closed, so we'll need to
	// mind the CSV when we sweep the output.
	case input.TaprootLocalCommitSpend:
		// In this case, we'll be resolving the set of local assets on
		// our commitment.
		assetOutputs = commitState.LocalAssets.Val.Outputs

		// Next, we'll make a sweep desc for this output. It's
		// dependent on the CSV delay we have in this channel, so we'll
		// pass that in as well.
		commitKeyRing := selectResolveCommitmentKeyRing(
			req, assetOutputs,
		)
		sweepDesc = commitDelaySweepDesc(commitKeyRing, req.CsvDelay)

	// The remote party has breached the channel. We'll sweep the revoked
	// key that we learned in the past.
	case input.TaprootCommitmentRevoke:
		// outputs, as they broadcast a revoked commitment. For the
		// In this case, we'll be sweeping the remote party's asset
		// remote party, this is actually their local output.
		assetOutputs = commitState.LocalAssets.Val.Outputs

		// Next, we'll make a sweep desk capable of sweeping the remote
		// party's local output.
		commitKeyRing := selectResolveCommitmentKeyRing(
			req, assetOutputs,
		)
		sweepDesc = commitRevokeSweepDesc(commitKeyRing, req.CsvDelay)

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
		resolveKeyRing := selectResolveCommitmentKeyRing
		commitKeyRing := resolveKeyRing(req, assetOutputs)

		payHash, err := req.PayHash.UnwrapOrErr(errNoPayHash)
		if err != nil {
			return lfn.Err[tlv.Blob](err)
		}

		// Now that we know which output we'll be sweeping, we'll make a
		// sweep desc for the timeout txn.
		sweepDesc = remoteHtlcTimeoutSweepDesc(
			commitKeyRing, payHash[:], req.CsvDelay,
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
		resolveKeyRing := selectResolveCommitmentKeyRing
		commitKeyRing := resolveKeyRing(req, assetOutputs)

		payHash, err := req.PayHash.UnwrapOrErr(errNoPayHash)
		if err != nil {
			return lfn.Err[tlv.Blob](err)
		}

		// Now that we know which output we'll be sweeping, we'll make a
		// sweep desc for the timeout txn.
		sweepDesc = remoteHtlcSuccessSweepDesc(
			commitKeyRing, payHash[:], req.CsvDelay, htlcID,
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
		resolveKeyRing := selectResolveCommitmentKeyRing
		commitKeyRing := resolveKeyRing(req, assetOutputs)

		// With the output and pay desc located, we'll now create the
		// sweep desc.
		sweepDesc = localHtlcTimeoutSweepDesc(
			req, commitKeyRing, htlcID,
		)

		needsSecondLevel = true

	// In this case, we've broadcast a commitment, with an incoming HTLC
	// that we can sweep. We'll annotate the sweepDesc with the information
	// needed to sweep both this output, as well as the second level
	// output it creates.
	case input.TaprootHtlcAcceptedLocalSuccess:
		htlcID := req.HtlcID.UnwrapOr(math.MaxUint64)
		htlcOutputs := commitState.IncomingHtlcAssets.Val
		assetOutputs = htlcOutputs.FilterByHtlcIndex(htlcID)
		resolveKeyRing := selectResolveCommitmentKeyRing
		commitKeyRing := resolveKeyRing(req, assetOutputs)

		// With the output and pay desc located, we'll now create the
		// sweep desc.
		sweepDesc = localHtlcSuccessSweepDesc(
			req, commitKeyRing, htlcID,
		)

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
	// Only reuse stored commit-sweep metadata for the first post-funding
	// commitment path where outputs still need re-anchoring to the real
	// unilateral close transaction. For later commitment states we derive
	// fresh sweep descriptors from the resolver context.
	if activeOutputsNeedReanchor(assetOutputs, req.CommitTx) {
		fetchSweepMetadata := fetchStoredCommitSweepMetadata
		witnessScript, controlBlock, ok := fetchSweepMetadata(
			assetOutputs,
		)
		if ok {
			tapSweepDesc.firstLevel.witnessScript = witnessScript
			tapSweepDesc.firstLevel.ctrlBlockBytes = controlBlock
		}
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

		err := a.importCommitTx(
			req, commitState, fundingInfo, assetOutputs,
			tapSweepDesc.firstLevel.scriptTree,
		)
		if err != nil {
			return lfn.Errf[returnType]("unable to import "+
				"commitment txn: %w", err)
		}
	} else {
		log.Infof("Commitment commit_txid=%v already imported, "+
			"skipping", req.CommitTx.TxHash())
	}
	if req.CommitTx == nil {
		return lfn.Errf[returnType]("no commitment transaction "+
			"found for chan_point=%v", req.ChanPoint)
	}
	commitTx := *req.CommitTx

	if isCommitmentOutputResolution(req.Type) {
		if err := syncCommitOutputProofs(
			assetOutputs, tapSweepDesc.firstLevel.scriptTree,
		); err != nil {
			return lfn.Errf[returnType](
				"unable to sync asset output proofs: %w", err,
			)
		}
	}
	if err := reanchorAssetOutputs(
		ctx, a.cfg.ChainBridge, commitTx,
		req.CommitTxBlockHeight, assetOutputs,
	); err != nil {
		return lfn.Errf[returnType]("unable to re-anchor asset "+
			"outputs: %w", err)
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
			sweepSet.btcInput.SignDesc().WitnessScript,
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

	// Sweep transactions are externally broadcast by lnd first, then
	// handed to the porter for proof archival. Use a historical hint so
	// the porter can still detect a confirmation if the sweep makes it on
	// chain before the porter registers its notifier. lnd requires the hint
	// to be strictly greater than zero.
	heightHint := fn.Some[uint32](1)

	// With the output commitments re-created, we have all we need to log
	// and ship the transaction.
	//
	// Sweep transactions are assembled by lnd before they reach this path.
	// We still run the porter's proof checks here so malformed proofs fail
	// loudly and deterministically.
	skipOutputProofVerify := false
	return shipChannelTxn(
		a.cfg.TxSender, sweepTx, outCommitments, allVpkts, int64(fee),
		heightHint, skipOutputProofVerify,
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
func ExtraBudgetForInputs(inputs []input.Input) lfn.Result[btcutil.Amount] {
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

// ExtraBudgetForInputs takes a set of inputs and maybe returns an extra budget
// that should be added to the sweep transaction.
func (a *AuxSweeper) ExtraBudgetForInputs(
	inputs []input.Input) lfn.Result[btcutil.Amount] {

	return ExtraBudgetForInputs(inputs)
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
