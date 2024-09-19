package tapchannel

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"sync"
	"sync/atomic"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
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
	lfn "github.com/lightningnetwork/lnd/fn"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/sweep"
	"github.com/lightningnetwork/lnd/tlv"
	"golang.org/x/exp/maps"
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
) lfn.Result[[]*tappsbt.VPacket] {

	type returnType = []*tappsbt.VPacket

	log.Infof("Creating sweep packets for %v inputs", len(sweepInputs))

	// Unpack the tapscript desc, as we need it to be able to continue
	// forward.
	sweepDesc, err := tapscriptDesc.Unpack()
	if err != nil {
		return lfn.Err[returnType](err)
	}

	// For each out we want to sweep, we'll construct an allocation that
	// we'll use to deliver the funds back to the wallet.
	ctx := context.Background()
	allocs := make([]*Allocation, 0, len(sweepInputs))
	for _, localAsset := range sweepInputs {
		// For each output, we'll need to create a new script key to
		// use for the sweep transaction.
		scriptKey, err := a.cfg.AddrBook.NextScriptKey(
			ctx, asset.TaprootAssetsKeyFamily,
		)
		if err != nil {
			return lfn.Err[returnType](err)
		}

		// With the script key created, we can make a new allocation
		// that will be used to sweep the funds back to our wallet.
		//
		// We leave out the internal key here, as we'll make it later
		// once we actually have the other set of inputs we need to
		// sweep.
		allocs = append(allocs, &Allocation{
			Type: CommitAllocationToLocal,
			// We don't need to worry about sorting, as we'll
			// always be the first output index in the transaction.
			OutputIndex:  0,
			Amount:       localAsset.Amount.Val,
			AssetVersion: asset.V1,
			BtcAmount:    tapsend.DummyAmtSats,
			ScriptKey:    scriptKey,
			SortTaprootKeyBytes: schnorr.SerializePubKey(
				scriptKey.PubKey,
			),
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
	vPackets, err := DistributeCoins(
		inputProofs, allocs, &a.cfg.ChainParams,
	)
	if err != nil {
		return lfn.Errf[returnType]("error distributing coins: %w", err)
	}

	log.Infof("Created %v sweep packets: %v", len(vPackets),
		limitSpewer.Sdump(vPackets))

	fundingWitness, err := fundingSpendWitness().Unpack()
	if err != nil {
		return lfn.Errf[returnType]("unable to make funding witness: "+
			"%w", err)
	}

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

		err := tapsend.PrepareOutputAssets(ctx, vPackets[idx])
		if err != nil {
			return lfn.Errf[returnType]("unable to prepare output "+
				"assets: %w", err)
		}

		// Next before we sign, we'll make sure to update the witness
		// of the prev asset's root asset. Otherwise, we'll be signing
		// the wrong input leaf.
		vIn := vPackets[idx].Inputs[0]
		if vIn.Asset().HasSplitCommitmentWitness() {
			//nolint:lll
			rootAsset := vIn.Asset().PrevWitnesses[0].SplitCommitment.RootAsset
			rootAsset.PrevWitnesses[0].TxWitness = fundingWitness
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
	signDesc input.SignDescriptor, tapscriptDesc tapscriptSweepDesc) error {

	// Before we sign below, we also need to generate the tapscript With
	// the vPackets prepared, we can now sign the output asset we'll create
	// at a later step.
	for _, vPacket := range vPackets {
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
			signDesc, vIn, &a.cfg.ChainParams,
			tapscriptDesc.scriptTree.TapTweak(),
		)

		// In this case, the witness isn't special, so we'll set the
		// control block now for it.
		ctrlBlock := tapscriptDesc.ctrlBlockBytes
		vIn.TaprootLeafScript[0].ControlBlock = ctrlBlock

		log.Debugf("signing vPacket for input=%v",
			spew.Sdump(vIn.PrevID))

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
	}

	return nil
}

// createAndSignSweepVpackets creates vPackets that sweep the funds from the
// channel to the wallet, and then signs them as well.
func (a *AuxSweeper) createAndSignSweepVpackets(
	sweepInputs []*cmsg.AssetOutput, signDesc input.SignDescriptor,
	sweepDesc lfn.Result[tapscriptSweepDesc],
) lfn.Result[[]*tappsbt.VPacket] {

	type returnType = []*tappsbt.VPacket

	// Based on the sweep inputs, make vPackets that sweep all the inputs
	// into a new output with a fresh script key. They won't have an
	// internal key set, we'll do that when we go to make the output to
	// anchor them all. We'll then take those, then sign all the vPackets
	// based on the specified sweepDesc.
	signPkts := func(vPkts []*tappsbt.VPacket,
		desc tapscriptSweepDesc) lfn.Result[[]*tappsbt.VPacket] {

		err := a.signSweepVpackets(vPkts, signDesc, desc)
		if err != nil {
			return lfn.Err[returnType](err)
		}

		return lfn.Ok(vPkts)
	}

	return lfn.AndThen2(
		a.createSweepVpackets(sweepInputs, sweepDesc), sweepDesc,
		signPkts,
	)
}

// tapscriptSweepDesc is a helper struct that contains the tapscript tree and
// the control block needed to generate a valid spend.
//
// TODO(roasbeef): only needs the merkle root?
type tapscriptSweepDesc struct {
	scriptTree input.TapscriptDescriptor

	ctrlBlockBytes []byte

	relativeDelay fn.Option[uint64]

	absoluteDelay fn.Option[uint64] //nolint:unused
}

// commitNoDelaySweepDesc creates a sweep desc for a commitment output that
// resides on the remote party's commitment transaction. This output is a
// non-delay output, so we don't need to worry about the CSV delay when
// sweeping it.
func commitNoDelaySweepDesc(keyRing *lnwallet.CommitmentKeyRing,
	csvDelay uint32) lfn.Result[tapscriptSweepDesc] {

	type returnType = tapscriptSweepDesc

	// We'll make the script tree for the to remote script (we're remote as
	// this is their commitment transaction). We don't have an auxLeaf here
	// as we're on the TAP layer.
	toRemoteScriptTree, err := input.NewRemoteCommitScriptTree(
		keyRing.ToRemoteKey, input.NoneTapLeaf(),
	)
	if err != nil {
		return lfn.Errf[returnType]("unable to make remote script "+
			"tree: %w", err)
	}

	// Now that we have the script tree, we'll make the control block
	// needed to spend it.
	ctrlBlock, err := toRemoteScriptTree.CtrlBlockForPath(
		input.ScriptPathSuccess,
	)
	if err != nil {
		return lfn.Errf[returnType]("unable to make ctrl block: %w",
			err)
	}
	ctrlBlockBytes, err := ctrlBlock.ToBytes()
	if err != nil {
		return lfn.Errf[returnType]("unable to encode ctrl block: %w",
			err)
	}

	return lfn.Ok(tapscriptSweepDesc{
		scriptTree:     toRemoteScriptTree,
		relativeDelay:  fn.Some(uint64(csvDelay)),
		ctrlBlockBytes: ctrlBlockBytes,
	})
}

// commitDelaySweepDesc creates a sweep desc for a commitment output that
// resides on our local commitment transaction. This output is a delay output,
// so we need to mind the CSV delay when sweeping it.
func commitDelaySweepDesc(keyRing *lnwallet.CommitmentKeyRing,
	csvDelay uint32) lfn.Result[tapscriptSweepDesc] {

	type returnType = tapscriptSweepDesc

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

	return lfn.Ok(tapscriptSweepDesc{
		scriptTree:     toLocalScriptTree,
		relativeDelay:  fn.Some(uint64(csvDelay)),
		ctrlBlockBytes: ctrlBlockBytes,
	})
}

// commitRevokeSweepDesc creates a sweep desc for a commitment output that is
// the local output on the remote party's commitment transaction. We can seep
// this in the case of a revoked commitment.
func commitRevokeSweepDesc(keyRing *lnwallet.CommitmentKeyRing,
	csvDelay uint32) lfn.Result[tapscriptSweepDesc] {

	type returnType = tapscriptSweepDesc

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
		return lfn.Err[returnType](err)
	}

	return lfn.Ok(tapscriptSweepDesc{
		scriptTree:     toLocalScriptTree,
		ctrlBlockBytes: ctrlBlockBytes,
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
	keyRing *lnwallet.CommitmentKeyRing) lfn.Result[[]*Allocation] {

	anchorAlloc := func(k *btcec.PublicKey) lfn.Result[*Allocation] {
		anchorTree, err := input.NewAnchorScriptTree(k)
		if err != nil {
			return lfn.Err[*Allocation](err)
		}

		sibling, scriptTree, err := LeavesFromTapscriptScriptTree(
			anchorTree,
		)
		if err != nil {
			return lfn.Err[*Allocation](err)
		}

		return lfn.Ok(&Allocation{
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

	localAnchor := anchorAlloc(keyRing.ToLocalKey)
	remoteAnchor := anchorAlloc(keyRing.ToRemoteKey)

	return lfn.AndThen2(
		localAnchor, remoteAnchor,
		func(a1, a2 *Allocation) lfn.Result[[]*Allocation] {
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

			return lfn.Ok([]*Allocation{a1, a2})
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

	log.Debugf("Importing script_keys=%v", spew.Sdump(keysToImport))

	ctxb := context.Background()
	for _, key := range keysToImport {
		err := a.cfg.AddrBook.InsertScriptKey(ctxb, key, true)
		if err != nil {
			return fmt.Errorf("unable to insert script "+
				"key: %w", err)
		}
	}

	return nil
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
			spew.Sdump(inputProofLocator))

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
			spew.Sdump(inputProofLocator))

		// Before we combine the proofs below, we'll be sure to update
		// the transition proof to include the proper block+merkle
		// proof information.
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

		fundingUTXO := proofToImport.Asset
		err = proofArchive.ImportProofs(
			ctxb, headerVerifier, proof.DefaultMerkleVerifier,
			groupVerifier, chainBridge, false,
			&proof.AnnotatedProof{
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
	err := a.cfg.AddrBook.InsertScriptKey(ctxb, fundingScriptKey, true)
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

	// Now that we've added all the relevant vPackets, we'll prepare the
	// funding witness which includes the OP_TRUE ctrl block.
	fundingWitness, err := fundingSpendWitness().Unpack()
	if err != nil {
		return fmt.Errorf("unable to make funding witness: %w", err)
	}

	// With all the vPackets created, we'll create output commitments from
	// them, as we'll need them to ship the transaction off to the porter.
	vPkts := maps.Values(vPktsByAssetID)
	ctx := context.Background()
	for idx := range vPkts {
		err := tapsend.PrepareOutputAssets(ctx, vPkts[idx])
		if err != nil {
			return fmt.Errorf("unable to prepare output "+
				"assets: %w", err)
		}

		// With the packets prepared, we'll swap in the correct witness
		// for each of them.
		for outIdx := range vPkts[idx].Outputs {
			outAsset := vPkts[idx].Outputs[outIdx].Asset

			// There is always only a single input, as we're
			// sweeping a single contract w/ each vPkt.
			const inputIndex = 0
			err := outAsset.UpdateTxWitness(
				inputIndex, fundingWitness,
			)
			if err != nil {
				return fmt.Errorf("error updating "+
					"witness: %w", err)
			}
		}
	}
	outCommitments, err := tapsend.CreateOutputCommitments(vPkts)
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
	exclusionCreator := NonAssetExclusionProofs(anchorAllocations)
	for idx := range vPkts {
		vPkt := vPkts[idx]
		for outIdx := range vPkt.Outputs {
			proofSuffix, err := tapsend.CreateProofSuffixCustom(
				req.CommitTx, vPkt, outCommitments, outIdx,
				vPkts, exclusionCreator,
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
		a.cfg.TxSender, req.CommitTx, outCommitments, vPkts,
		int64(req.CommitFee),
	)
}

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

	// To be able to construct all the proofs we need to spend later, we'll
	// make sure that this commitment transaction exists in our database.
	// If not, then we'll complete the proof, register the script keys, and
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

	var (
		sweepDesc    lfn.Result[tapscriptSweepDesc]
		assetOutputs []*cmsg.AssetOutput
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
		// In this case, we'll be sweeping the remote party's asset
		// outputs, as they broadcast a revoked commitment. For the
		// remote party, this is actually their local output.
		assetOutputs = commitState.LocalAssets.Val.Outputs

		// As we have multiple outputs to sweep above, we'll also have
		// two sweep descs.
		sweepDesc = commitRevokeSweepDesc(req.KeyRing, req.CsvDelay)

	default:
		return lfn.Errf[returnType]("unknown resolution type: %v",
			req.Type)
	}

	// The input proofs above were made originally using the fake commit tx
	// as an anchor. We now know the real commit tx, so we'll swap that in
	// to ensure the outpoints used below are correct.
	for _, assetOut := range assetOutputs {
		assetOut.Proof.Val.AnchorTx = *req.CommitTx
	}

	log.Infof("Sweeping %v asset outputs: %v", len(assetOutputs),
		limitSpewer.Sdump(assetOutputs))

	// With the sweep desc constructed above, we'll create vPackets for
	// each of the local assets, then sign them all.
	sPkts := a.createAndSignSweepVpackets(
		assetOutputs, req.SignDesc, sweepDesc,
	)

	// With the vPackets fully generated and signed above, we'll serialize
	// it into a resolution blob to return.
	return lfn.AndThen(
		sPkts, func(vPkts []*tappsbt.VPacket) lfn.Result[tlv.Blob] {
			res := cmsg.NewContractResolution(vPkts)

			var b bytes.Buffer
			if err := res.Encode(&b); err != nil {
				return lfn.Err[returnType](err)
			}

			return lfn.Ok(b.Bytes())
		},
	)
}

// extractInputVPackets extracts the vPackets from the inputs passed in. If
// none of the inputs have any resolution blobs. Then an empty slice will be
// returned.
func extractInputVPackets(inputs []input.Input) lfn.Result[[]*tappsbt.VPacket] {
	type returnType = []*tappsbt.VPacket

	// Otherwise, we'll extract the set of resolution blobs from the inputs
	// passed in.
	relevantInputs := fn.Filter(inputs, func(i input.Input) bool {
		return i.ResolutionBlob().IsSome()
	})
	resolutionBlobs := fn.Map(relevantInputs, func(i input.Input) tlv.Blob {
		// We already know this has a blob from the filter above.
		return i.ResolutionBlob().UnwrapOr(nil)
	})

	// With our set of resolution inputs extracted, we'll now decode them
	// in the vPackets we'll use to generate the output to addr.
	vPkts, err := fn.FlatMapErr(
		resolutionBlobs,
		func(b tlv.Blob) ([]*tappsbt.VPacket, error) {
			var res cmsg.ContractResolution
			if err := res.Decode(bytes.NewReader(b)); err != nil {
				return nil, err
			}

			return res.VPkts(), nil
		},
	)
	if err != nil {
		return lfn.Err[returnType](err)
	}

	return lfn.Ok(vPkts)
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
	vPkts, err := extractInputVPackets(inputs).Unpack()
	if err != nil {
		return lfn.Err[returnType](err)
	}

	log.Infof("Generating anchor output for vpkts=%v",
		limitSpewer.Sdump(vPkts))

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
	for idx := range vPkts {
		for _, vOut := range vPkts[idx].Outputs {
			vOut.SetAnchorInternalKey(
				internalKey, a.cfg.ChainParams.HDCoinType,
			)
		}
	}

	// Now that we have our set of resolutions, we'll make a new commitment
	// out of all the vPackets contained.
	outCommitments, err := tapsend.CreateOutputCommitments(vPkts)
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
) tapsend.ExclusionProofGenerator {

	return func(target *proof.BaseProofParams,
		isAnchor tapsend.IsAnchor) error {

		tsProof, err := proof.CreateTapscriptProof(nil)
		if err != nil {
			return fmt.Errorf("error creating tapscript proof: %w",
				err)
		}

		// We only need to generate an exclusion proof for the second
		// output in the commitment transaction.
		//
		// TODO(roasbeef): case of no change?
		target.ExclusionProofs = append(
			target.ExclusionProofs, proof.TaprootProof{
				OutputIndex:    1,
				InternalKey:    sweepInternalKey.PubKey,
				TapscriptProof: tsProof,
			},
		)

		return nil
	}
}

// registerAndBroadcastSweep finalizes a sweep attempt by generating a
// transition proof for it, then registering the sweep with the porter.
func (a *AuxSweeper) registerAndBroadcastSweep(req *sweep.BumpRequest,
	sweepTx *wire.MsgTx, fee btcutil.Amount) error {

	// TODO(roasbeef): need to handle replacement -- will porter just
	// upsert in place?

	log.Infof("Register broadcast of sweep_tx=%v", spew.Sdump(sweepTx))

	// In order to properly register the sweep, we'll need to first extra a
	// unified set of vPackets from the specified inputs.
	vPkts, err := extractInputVPackets(req.Inputs).Unpack()
	if err != nil {
		return err
	}

	// If we don't have any vPackets that had our resolution data in them,
	// then we can exit early.
	if len(vPkts) == 0 {
		log.Infof("Sweep request had no vPkts, exiting")
		return nil
	}

	ourSweepOutput, err := req.ExtraTxOut.UnwrapOrErr(
		fmt.Errorf("extra tx out not populated"),
	)
	if err != nil {
		return err
	}
	internalKey, err := ourSweepOutput.InternalKey.UnwrapOrErr(
		fmt.Errorf("internal key not populated"),
	)
	if err != nil {
		return err
	}

	log.Infof("Using %x for internal key: ",
		internalKey.PubKey.SerializeCompressed())

	// We'll also use the passed in context to set the anchor key again for
	// all the vOuts.
	for idx := range vPkts {
		for _, vOut := range vPkts[idx].Outputs {
			vOut.SetAnchorInternalKey(
				internalKey, a.cfg.ChainParams.HDCoinType,
			)
		}
	}

	// Now that we have our vPkts, we'll re-create the output commitments.
	outCommitments, err := tapsend.CreateOutputCommitments(vPkts)
	if err != nil {
		return fmt.Errorf("unable to create output "+
			"commitments: %w", err)
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
	for idx := range vPkts {
		vPkt := vPkts[idx]
		for outIdx := range vPkt.Outputs {
			exclusionCreator := sweepExclusionProofGen(
				changeInternalKey,
			)

			proofSuffix, err := tapsend.CreateProofSuffixCustom(
				sweepTx, vPkt, outCommitments, outIdx, vPkts,
				exclusionCreator,
			)
			if err != nil {
				return fmt.Errorf("unable to create proof "+
					"suffix for output %d: %w", outIdx, err)
			}

			vPkt.Outputs[outIdx].ProofSuffix = proofSuffix
		}
	}

	log.Infof("Proofs generated for sweep_tx=%v", spew.Sdump(sweepTx))

	// With the output commitments re-created, we have all we need to log
	// and ship the transaction.
	//
	// We pass false for the last arg as we already updated our suffix
	// proofs here.
	return shipChannelTxn(
		a.cfg.TxSender, sweepTx, outCommitments, vPkts, int64(fee),
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

// NotifyBroadcast is used to notify external callers of the broadcast of a
// sweep transaction, generated by the passed BumpRequest.
func (a *AuxSweeper) NotifyBroadcast(req *sweep.BumpRequest,
	tx *wire.MsgTx, fee btcutil.Amount) error {

	auxReq := &broadcastReq{
		req:  req,
		tx:   tx,
		fee:  fee,
		resp: make(chan error, 1),
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
