package tapchannel

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/rfq"
	cmsg "github.com/lightninglabs/taproot-assets/tapchannelmsg"
	"github.com/lightninglabs/taproot-assets/tapdb"
	"github.com/lightninglabs/taproot-assets/tapfreighter"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/lightninglabs/taproot-assets/vm"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/funding"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/msgmux"
)

const (
	// MsgEndpointName is the name of the endpoint that we'll use to
	// register the funding controller with the peer message handler.
	MsgEndpointName = "taproot assets channel funding"

	// ackTimeout is the amount of time we'll wait to receive the protocol
	// level ACK from the remote party before timing out.
	ackTimeout = time.Second * 30

	// proofCourierCheckTimeout is the amount of time we'll wait before we
	// time out an attempt to connect to a proof courier when checking the
	// configured address.
	proofCourierCheckTimeout = time.Second * 5

	// maxNumAssetIDs is the maximum number of fungible asset pieces (asset
	// IDs) that can be committed to a single channel. The number needs to
	// be limited to prevent the number of required HTLC signatures to be
	// too large for a single CommitSig wire message to carry them. This
	// value is tightly coupled with the number of HTLCs that can be added
	// to a channel at the same time (maxNumHTLCs). The values were
	// determined with the TestMaxCommitSigMsgSize test in
	// aux_leaf_signer_test.go then a set was chosen that would allow for
	// a decent number of HTLCs (and also a number that is divisible by two
	// because each side will only be allowed to add half of the total).
	maxNumAssetIDs = 3

	// maxNumHTLCs is the maximum number of HTLCs there can be in an asset
	// channel to avoid the number of signatures exceeding the maximum
	// message size of a CommitSig message. See maxNumAssetIDs for more
	// information.
	maxNumHTLCs = 166

	// maxNumHTLCsPerParty is the maximum number of HTLCs that can be added
	// by a single party to a channel.
	maxNumHTLCsPerParty = maxNumHTLCs / 2

	// proofChunk size is the chunk size of proofs, in the case that a proof
	// is too large to be sent in a single message. Since the max lnwire
	// message is 64k bytes, we leave some breathing room for the chunk
	// metadata.
	proofChunkSize = 60_000
)

// ErrorReporter is used to report an error back to the caller and/or peer that
// we're communicating with.
type ErrorReporter interface {
	// ReportError reports an error that occurred during the funding
	// process.
	ReportError(ctx context.Context, peer btcec.PublicKey,
		pid funding.PendingChanID, err error)
}

// PeerMessenger is an interface that allows us to send messages to a remote LN
// peer.
type PeerMessenger interface {
	// SendMessage sends a message to a remote peer.
	SendMessage(ctx context.Context, peer btcec.PublicKey,
		msg lnwire.Message) error
}

// ErrNoPeer is returned when a peer can't be found.
var ErrNoPeer = errors.New("peer not found")

// FeatureBitVerifer is an interface that allows us to verify that a peer has a
// given feature bit set.
type FeatureBitVerifer interface {
	// HasFeature returns true if the peer has the given feature bit set.
	// If the peer can't be found, then ErrNoPeer is returned.
	HasFeature(ctx context.Context, peerPub btcec.PublicKey,
		bit lnwire.FeatureBit) (bool, error)
}

// OpenChanReq is a request to open a new asset channel with a remote peer.
type OpenChanReq struct {
	// ChanAmt is the amount of BTC to put into the channel. Some BTC is
	// required atm to pay on chain fees for the channel. Note that
	// additional fees can be added in the event of a force close by using
	// CPFP with the channel anchor outputs.
	ChanAmt btcutil.Amount

	// PushAmt is the amount of BTC to push to the remote peer.
	PushAmt btcutil.Amount

	// RemoteMaxHtlc is the maximum number of HTLCs we allow the remote to
	// add to the channel. If this is zero, then the default value defined
	// by lnd (and dependent on the channel capacity) will be used.
	RemoteMaxHtlc uint32

	// PeerPub is the identity public key of the remote peer we wish to
	// open the channel with.
	PeerPub btcec.PublicKey

	// TempPID is the temporary channel ID to use for this channel.
	TempPID funding.PendingChanID

	// PsbtTemplate is the PSBT template that we'll use to fund the channel.
	// This should already have all the inputs spending asset UTXOs added.
	PsbtTemplate *psbt.Packet
}

// AssetChanIntent is a handle returned by the PsbtChannelFunder that can be
// used to drive the new asset channel to completion. The intent includes the
// PSBT template returned by lnd which has the funding output for the new
// channel already populated.
type AssetChanIntent interface {
	// FundingPsbt is the original PsbtTemplate, plus the P2TR funding
	// output that'll create the channel.
	FundingPsbt() (*psbt.Packet, error)

	// BindPsbt accepts a new *unsigned* PSBT with any additional inputs or
	// outputs (for change) added. This PSBT is still unsigned. This step
	// performs final verification to ensure the PSBT is crafted in a manner
	// that'll properly open the channel once broadcaster.
	BindPsbt(context.Context, *psbt.Packet) error
}

// PsbtChannelFunder is an interface that abstracts the necessary steps needed
// fund a PSBT channel on using lnd.
type PsbtChannelFunder interface {
	// OpenChannel attempts to open a new asset holding private channel
	// using the backing lnd node. The PSBT flow is by default. An
	// AssetChanIntent is returned that includes the updated PSBT template
	// that includes the funding output. Once all other inputs+outputs have
	// been added, then BindPsbt should be called to progress the funding
	// process. Afterward, the funding transaction should be signed and
	// broadcast.
	OpenChannel(context.Context, OpenChanReq) (AssetChanIntent, error)

	// ChannelAcceptor is used to accept and potentially influence
	// parameters of incoming channels.
	ChannelAcceptor(ctx context.Context,
		acceptor lndclient.AcceptorFunction) (chan error, error)
}

// TxPublisher is an interface used to publish transactions.
type TxPublisher interface {
	// PublishTransaction attempts to publish a new transaction to the
	// network.
	PublishTransaction(context.Context, *wire.MsgTx, string) error
}

// AssetSyncer is used to ensure that we know of the set of assets that'll be
// used as funding input to an accepted channel.
type AssetSyncer interface {
	// QueryAssetInfo attempts to locate asset genesis information by
	// querying geneses already known to this node. If asset issuance was
	// not previously verified, we then query universes in our federation
	// for issuance proofs.
	QueryAssetInfo(ctx context.Context,
		id asset.ID) (*asset.AssetGroup, error)

	// FetchAssetMetaForAsset attempts to fetch an asset meta based on an
	// asset ID.
	FetchAssetMetaForAsset(ctx context.Context,
		assetID asset.ID) (*proof.MetaReveal, error)
}

// FundingControllerCfg is a configuration struct that houses the necessary
// abstractions needed to drive funding.
type FundingControllerCfg struct {
	// HeaderVerifier is used to verify headers in a proof.
	HeaderVerifier proof.HeaderVerifier

	// GroupVerifier is used to verify group keys in a proof.
	GroupVerifier proof.GroupVerifier

	// ErrReporter is used to report errors back to the caller and/or peer.
	ErrReporter ErrorReporter

	// AssetWallet is the wallet that we'll use to handle the asset
	// specific steps of the funding process.
	AssetWallet tapfreighter.Wallet

	// CoinSelector is used to select assets for funding.
	CoinSelector tapfreighter.CoinSelector

	// AddrBook is used to manage script keys and addresses.
	AddrBook *tapdb.TapAddressBook

	// ChainParams is the chain params of the chain we operate on.
	ChainParams address.ChainParams

	// ChainBridge provides access to the chain for confirmation
	// notification, and other block related actions.
	ChainBridge tapfreighter.ChainBridge

	// GroupKeyIndex is used to query the group key for an asset ID.
	GroupKeyIndex tapsend.AssetGroupQuerier

	// PeerMessenger is used to send messages to a remote peer.
	PeerMessenger PeerMessenger

	// ChannelFunder is used to fund a new channel using a PSBT template.
	ChannelFunder PsbtChannelFunder

	// TxPublisher is used to publish transactions.
	TxPublisher TxPublisher

	// ChainWallet is the wallet that we'll use to handle the chain
	// specific
	ChainWallet tapfreighter.WalletAnchor

	// TxSender is what we'll use to broadcast a transaction to the
	// network, while ensuring we also update all our asset and UTXO state
	// on disk (insert a proper transfer, etc., etc.).
	TxSender tapfreighter.Porter

	// RfqManager is used to manage RFQs.
	RfqManager *rfq.Manager

	// DefaultCourierAddr is the default address the funding controller uses
	// to deliver the funding output proofs to the channel peer.
	DefaultCourierAddr *url.URL

	// AssetSyncer is used to ensure that we've already verified the asset
	// genesis for any assets used within channels.
	AssetSyncer AssetSyncer

	// FeatureBits is used to verify that the peer has the required feature
	// to fund asset channels.
	FeatureBits FeatureBitVerifer

	// ErrChan is used to report errors back to the main server.
	ErrChan chan<- error
}

// bindFundingReq is a request to bind a pending channel ID to a complete aux
// funding desc. This is used by the initiator+responder after the pre-funding
// messages and interaction is complete.
type bindFundingReq struct {
	initiator bool

	pendingChanID funding.PendingChanID

	openChan lnwallet.AuxChanState

	keyRing lntypes.Dual[lnwallet.CommitmentKeyRing]

	resp chan lfn.Option[lnwallet.AuxFundingDesc]
}

// assetRootReq is a message sent by lnd once we've sent or received the
// OpenChannel message. We'll reply with a tapscript root if we know of one for
// this pid, which lets lnd derive the proper funding output.
type assetRootReq struct {
	pendingChanID funding.PendingChanID

	resp chan lfn.Option[chainhash.Hash]
}

// FundingController is used to drive TAP aware channel funding using a backing
// lnd node and an active connection to a tapd instance.
type FundingController struct {
	started atomic.Bool
	stopped atomic.Bool

	cfg FundingControllerCfg

	msgs chan msgmux.PeerMsg

	bindFundingReqs chan *bindFundingReq

	newFundingReqs chan *FundReq

	rootReqs chan *assetRootReq

	finalizedChans chan funding.PendingChanID

	// ContextGuard provides a wait group and main quit channel that can be
	// used to create guarded contexts.
	*fn.ContextGuard
}

// NewFundingController creates a new instance of the FundingController.
func NewFundingController(cfg FundingControllerCfg) *FundingController {
	return &FundingController{
		cfg:             cfg,
		msgs:            make(chan msgmux.PeerMsg, 10),
		bindFundingReqs: make(chan *bindFundingReq, 10),
		newFundingReqs:  make(chan *FundReq, 10),
		rootReqs:        make(chan *assetRootReq, 10),
		finalizedChans:  make(chan funding.PendingChanID, 10),
		ContextGuard: &fn.ContextGuard{
			DefaultTimeout: DefaultTimeout,
			Quit:           make(chan struct{}),
		},
	}
}

// Start starts the funding controller.
func (f *FundingController) Start() error {
	if !f.started.CompareAndSwap(false, true) {
		return nil
	}

	log.Infof("Starting FundingController")

	f.Wg.Add(1)
	go f.chanFunder()

	f.Wg.Add(1)
	go func() {
		defer f.Wg.Done()

		ctx, cancel := f.WithCtxQuitNoTimeout()
		defer cancel()

		errChan, err := f.cfg.ChannelFunder.ChannelAcceptor(
			ctx, f.channelAcceptor,
		)
		if err != nil {
			err = fmt.Errorf("unable to start channel acceptor: %w",
				err)
			f.cfg.ErrChan <- err
			return
		}

		// We'll accept channels for as long as the funding controller
		// is running or until we receive an error.
		select {
		case err := <-errChan:
			err = fmt.Errorf("channel acceptor error: %w", err)
			f.cfg.ErrChan <- err

		case <-f.Quit:
			log.Infof("Stopping channel acceptor, funding " +
				"controller shutting down")
		}
	}()

	return nil
}

// Stop stops the funding controller.
func (f *FundingController) Stop() error {
	if !f.stopped.CompareAndSwap(true, false) {
		return nil
	}

	log.Infof("Stopping FundingController")

	close(f.Quit)
	f.Wg.Wait()

	return nil
}

// newPendingChanID generates a new pending channel ID using a CSPRG.
func newPendingChanID() (funding.PendingChanID, error) {
	var id funding.PendingChanID
	if _, err := io.ReadFull(crand.Reader, id[:]); err != nil {
		return id, err
	}

	return id, nil
}

// pendingAssetFunding represents all the state needed to keep track of a
// pending asset channel funding flow.
type pendingAssetFunding struct {
	chainParams *address.ChainParams

	peerPub btcec.PublicKey

	pid funding.PendingChanID

	initiator bool

	amt uint64

	pushAmt btcutil.Amount

	inputProofs []*proof.Proof

	feeRate chainfee.SatPerVByte

	lockedInputs []wire.OutPoint

	lockedAssetInputs []wire.OutPoint

	fundingAssetCommitment *commitment.TapCommitment

	fundingOutputProofs []*proof.Proof

	fundingAckChan chan bool

	fundingFinalizedSignal chan struct{}

	finalizedCloseOnce sync.Once
	inputProofChunks   map[chainhash.Hash][]cmsg.ProofChunk
}

// addInputProof adds a new proof to the set of proofs that'll be used to fund
// the new channel.
func (p *pendingAssetFunding) addInputProof(proof *proof.Proof) {
	p.inputProofs = append(p.inputProofs, proof)
}

// assetOutputs returns the set of asset outputs that'll be used to fund the
// new asset channel.
func (p *pendingAssetFunding) assetOutputs() []*cmsg.AssetOutput {
	return fn.Map(
		p.fundingOutputProofs, func(p *proof.Proof) *cmsg.AssetOutput {
			return cmsg.NewAssetOutput(
				p.Asset.ID(), p.Asset.Amount, *p,
			)
		},
	)
}

// addToFundingCommitment adds a new asset to the funding commitment.
func (p *pendingAssetFunding) addToFundingCommitment(a *asset.Asset) error {
	newCommitment, err := commitment.FromAssets(
		fn.Ptr(commitment.TapCommitmentV2), a,
	)
	if err != nil {
		return fmt.Errorf("unable to create commitment: %w", err)
	}

	// If we don't already have a commitment, then we'll use the one created
	// just now and don't need to merge anything.
	if p.fundingAssetCommitment == nil {
		p.fundingAssetCommitment = newCommitment
		return nil
	}

	// If we've already got one, then we need to merge the two.
	return p.fundingAssetCommitment.Merge(newCommitment)
}

// addInputProofChunk adds a new proof chunk to the set of proof chunks that'll
// be processed. If this is the last chunk for this proof, then true is
// returned.
func (p *pendingAssetFunding) addInputProofChunk(
	chunk cmsg.ProofChunk) lfn.Result[lfn.Option[proof.Proof]] {

	type ret = proof.Proof

	// Collect this proof chunk with the rest of the proofs.
	chunkID := chunk.ChunkSumID.Val

	proofChunks := p.inputProofChunks[chunkID]
	proofChunks = append(proofChunks, chunk)
	p.inputProofChunks[chunkID] = proofChunks

	// If this isn't the last chunk, then we can just return None and exit.
	if !chunk.Last.Val {
		return lfn.Ok(lfn.None[ret]())
	}

	// Otherwise, this is the last chunk, so we'll extract all the chunks
	// and assemble the final proof.
	finalProof, err := cmsg.AssembleProofChunks(proofChunks)
	if err != nil {
		return lfn.Errf[lfn.Option[ret]]("unable to "+
			"assemble proof chunks: %w", err)
	}

	return lfn.Ok(lfn.Some(*finalProof))
}

// newCommitBlobAndLeaves creates a new commitment blob that'll be stored in
// the channel state for the specified party.
func newCommitBlobAndLeaves(pendingFunding *pendingAssetFunding,
	lndOpenChan lnwallet.AuxChanState, assetOpenChan *cmsg.OpenChannel,
	keyRing lntypes.Dual[lnwallet.CommitmentKeyRing],
	whoseCommit lntypes.ChannelParty) ([]byte, lnwallet.CommitAuxLeaves,
	error) {

	chanAssets := assetOpenChan.FundedAssets.Val.Outputs

	var (
		localAssets, remoteAssets []*cmsg.AssetOutput
	)

	// Only assign the balances according to whether this is our commit or
	// not. The balances will be used correctly in the generateAllocations
	// call. This is required to mirror the case where we create a
	// commitment from a previous state. If it's not our commitment, then
	// the balances in the previous state are reversed and
	// generateAllocations will flip them back.
	switch {
	case pendingFunding.initiator && whoseCommit.IsLocal():
		localAssets = chanAssets

	case pendingFunding.initiator && whoseCommit.IsRemote():
		remoteAssets = chanAssets

	case !pendingFunding.initiator && whoseCommit.IsLocal():
		remoteAssets = chanAssets

	case !pendingFunding.initiator && whoseCommit.IsRemote():
		localAssets = chanAssets
	}

	var localSatBalance, remoteSatBalance lnwire.MilliSatoshi

	// We don't have a real prev state at this point, the leaf creator only
	// needs the sum of the remote+local assets, so we'll populate that.
	fakePrevState := cmsg.NewCommitment(
		localAssets, remoteAssets, nil, nil, lnwallet.CommitAuxLeaves{},
	)

	// Just like above, we don't have a real HTLC view here, so we'll pass
	// in a blank view.
	var fakeView lnwallet.AuxHtlcView

	// With all the above, we'll generate the first commitment that'll be
	// stored
	_, firstCommit, err := GenerateCommitmentAllocations(
		fakePrevState, lndOpenChan, assetOpenChan, whoseCommit,
		localSatBalance, remoteSatBalance, fakeView,
		pendingFunding.chainParams, keyRing.GetForParty(whoseCommit),
	)
	if err != nil {
		return nil, lnwallet.CommitAuxLeaves{}, err
	}

	var b bytes.Buffer
	if err := firstCommit.Encode(&b); err != nil {
		return nil, lnwallet.CommitAuxLeaves{}, err
	}

	auxLeaves := firstCommit.Leaves()

	return b.Bytes(), auxLeaves, nil
}

// toAuxFundingDesc converts the pending asset funding into a full aux funding
// desc. This is the final step in the modified funding process, as after this,
// both sides are able to construct the funding output, and will be able to
// store the appropriate funding blobs.
func (p *pendingAssetFunding) toAuxFundingDesc(req *bindFundingReq,
	decimalDisplay uint8,
	groupKey *btcec.PublicKey) (*lnwallet.AuxFundingDesc, error) {

	// First, we'll map all the assets into asset outputs that'll be stored
	// in the open channel struct on the lnd side.
	assetOutputs := p.assetOutputs()

	// With all the outputs assembled, we'll now map that to the open
	// channel wrapper that'll go in the set of TLV blobs.
	openChanDesc := cmsg.NewOpenChannel(
		assetOutputs, decimalDisplay, groupKey,
	)

	// Now we'll encode the 3 TLV blobs that lnd will store: the main one
	// for the funding details, and then the blobs for the local and remote
	// commitment
	customFundingBlob := openChanDesc.Bytes()

	// Encode the commitment blobs for both the local and remote party.
	// This will be the information for the very first state (state 0).
	localCommitBlob, localAuxLeaves, err := newCommitBlobAndLeaves(
		p, req.openChan, openChanDesc, req.keyRing, lntypes.Local,
	)
	if err != nil {
		return nil, err
	}
	remoteCommitBlob, remoteAuxLeaves, err := newCommitBlobAndLeaves(
		p, req.openChan, openChanDesc, req.keyRing, lntypes.Remote,
	)
	if err != nil {
		return nil, err
	}

	return &lnwallet.AuxFundingDesc{
		CustomFundingBlob:      customFundingBlob,
		CustomLocalCommitBlob:  localCommitBlob,
		CustomRemoteCommitBlob: remoteCommitBlob,
		LocalInitAuxLeaves:     localAuxLeaves,
		RemoteInitAuxLeaves:    remoteAuxLeaves,
	}, nil
}

// unlockInputs unlocks any inputs that were locked during the funding process.
func (p *pendingAssetFunding) unlockInputs(ctx context.Context,
	wallet tapgarden.WalletAnchor) error {

	for _, outpoint := range p.lockedInputs {
		if err := wallet.UnlockInput(ctx, outpoint); err != nil {
			return fmt.Errorf("unable to unlock outpoint %v: %w",
				outpoint, err)
		}
	}

	return nil
}

// unlockAssetInputs unlocks any asset inputs that were locked during the
// funding process.
func (p *pendingAssetFunding) unlockAssetInputs(ctx context.Context,
	coinSelect tapfreighter.CoinSelector) error {

	log.Debugf("unlocking asset inputs: %v",
		limitSpewer.Sdump(p.lockedAssetInputs))

	err := coinSelect.ReleaseCoins(ctx, p.lockedAssetInputs...)
	if err != nil {
		return fmt.Errorf("unable to unlock asset outpoints %v: %w",
			p.lockedAssetInputs, err)
	}

	return nil
}

// msgToAssetProof converts a wire message to an assetProof.
func msgToAssetProof(msg lnwire.Message) (cmsg.AssetFundingMsg, error) {
	switch msg := msg.(type) {
	case *lnwire.Custom:
		switch msg.Type {
		case cmsg.TxAssetInputProofType:
			var assetProof cmsg.TxAssetInputProof
			err := assetProof.Decode(bytes.NewReader(msg.Data), 0)
			if err != nil {
				return nil, fmt.Errorf("error decoding as "+
					"tx asset input proof: %w", err)
			}

			return &assetProof, nil

		case cmsg.TxAssetOutputProofType:
			var assetProof cmsg.TxAssetOutputProof
			err := assetProof.Decode(bytes.NewReader(msg.Data), 0)
			if err != nil {
				return nil, fmt.Errorf("error decoding as "+
					"tx asset output proof: %w", err)
			}

			return &assetProof, nil

		case cmsg.AssetFundingCreatedType:
			var assetProof cmsg.AssetFundingCreated
			err := assetProof.Decode(bytes.NewReader(msg.Data), 0)
			if err != nil {
				return nil, fmt.Errorf("error decoding as "+
					"asset funding created: %w", err)
			}

			return &assetProof, nil

		case cmsg.AssetFundingAckType:
			var fundingAck cmsg.AssetFundingAck
			err := fundingAck.Decode(bytes.NewReader(msg.Data), 0)
			if err != nil {
				return nil, fmt.Errorf("error decoding as "+
					"asset funding created: %w", err)
			}

			return &fundingAck, nil

		default:
			return nil, fmt.Errorf("unknown custom message "+
				"type: %v", msg.Type)
		}

	case *cmsg.TxAssetInputProof:
		return msg, nil

	case *cmsg.TxAssetOutputProof:
		return msg, nil

	case *cmsg.AssetFundingCreated:
		return msg, nil

	case *cmsg.AssetFundingAck:
		return msg, nil

	default:
		return nil, fmt.Errorf("unknown message type: %T", msg)
	}
}

// fundingFlowIndex is a map from pending channel ID to the current state of
// the funding flow.
type fundingFlowIndex map[funding.PendingChanID]*pendingAssetFunding

// fromMsg attempts to match an incoming message to the pending funding flow,
// and extracts the asset proof from the message.
func (f *fundingFlowIndex) fromMsg(chainParams *address.ChainParams,
	msg msgmux.PeerMsg) (cmsg.AssetFundingMsg, *pendingAssetFunding,
	error) {

	assetProof, err := msgToAssetProof(msg.Message)
	if err != nil {
		return nil, nil, fmt.Errorf("error converting to asset proof: "+
			"%w", err)
	}

	pid := assetProof.PID()

	// Next, we'll see if this is already part of an active funding flow.
	// If not, then we'll make a new one to accumulate this new proof.
	assetFunding, ok := (*f)[pid]
	if !ok {
		assetFunding = &pendingAssetFunding{
			chainParams:            chainParams,
			pid:                    pid,
			peerPub:                msg.PeerPub,
			amt:                    assetProof.Amt().UnwrapOr(0),
			fundingAckChan:         make(chan bool, 1),
			fundingFinalizedSignal: make(chan struct{}),
			inputProofChunks: make(
				map[chainhash.Hash][]cmsg.ProofChunk,
			),
		}
		(*f)[pid] = assetFunding
	}

	return assetProof, assetFunding, nil
}

// fundVirtualPacket attempts to fund a new vPacket using the asset wallet to
// find the asset inputs required to satisfy a funding request.
func (f *FundingController) fundVirtualPacket(ctx context.Context,
	specifier asset.Specifier, amt uint64) (*tapfreighter.FundedVPacket,
	error) {

	log.Infof("Funding new vPacket channel, asset=%s, amt=%v", &specifier,
		amt)

	// Our funding script key will be the OP_TRUE addr that we'll use as
	// the funding script on the asset level. We start with this one in case
	// there is only a single asset ID in the channel. This is to remain
	// backward compatible with previous versions of the channel funding
	// process, so updated users can still fund channels with a single asset
	// ID with older clients. Also, we don't know what asset IDs we're going
	// to be using, so we couldn't derive a unique funding script key for
	// each asset ID yet anyway.
	fundingScriptKey, err := deriveFundingScriptKey(
		ctx, f.cfg.AddrBook, nil,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to derive script key: %w", err)
	}

	// Next, we'll use the asset wallet to fund a new vPSBT which'll be
	// used as the asset level funding output for this transaction. In this
	// case our destination will just be the OP_TRUE tapscript that we use
	// for the funding output.
	pktTemplate := &tappsbt.VPacket{
		Outputs: []*tappsbt.VOutput{{
			Amount:            amt,
			AssetVersion:      asset.V1,
			Interactive:       true,
			AnchorOutputIndex: 0,
			ScriptKey:         fundingScriptKey,
		}},
		ChainParams: &f.cfg.ChainParams,
		Version:     tappsbt.V1,
	}
	fundDesc := &tapsend.FundingDescriptor{
		AssetSpecifier:    specifier,
		Amount:            amt,
		ScriptKeyType:     fn.Some(asset.ScriptKeyBip86),
		DistinctSpecifier: true,
	}

	// Fund the packet. This will derive an anchor internal key for us, but
	// we'll overwrite that later on.
	fundedPkt, err := f.cfg.AssetWallet.FundPacket(
		ctx, fundDesc, pktTemplate,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to fund vPacket: %w", err)
	}

	// If there was just a single virtual packet created, it means we only
	// have a single asset ID in the channel, and we can proceed without any
	// workarounds.
	if len(fundedPkt.VPackets) == 1 {
		return fundedPkt, nil
	}

	// For channels with multiple asset IDs, we'll need to create unique
	// funding script keys for each asset ID. Otherwise, the proofs for the
	// assets will collide in the universe because of group key, script key
	// and outpoint all being equal.
	for _, vPkt := range fundedPkt.VPackets {
		assetID, err := vPkt.AssetID()
		if err != nil {
			return nil, fmt.Errorf("unable to get asset ID: %w",
				err)
		}

		// If there's change from the funding output, it'll be in the
		// split root output. If there's no change, there will be no
		// split root output, since the virtual transfer is interactive.
		// So in either case we just need to get the first non-root
		// output.
		fundingOut, err := vPkt.FirstNonSplitRootOutput()
		if err != nil {
			return nil, fmt.Errorf("unable to get first non split "+
				"root output: %w", err)
		}

		fundingScriptKey, err := deriveFundingScriptKey(
			ctx, f.cfg.AddrBook, &assetID,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to derive script key: "+
				"%w", err)
		}

		// We now set the unique script key. This requires us to
		// re-calculate the split commitments, so we'll do that right
		// afterward.
		fundingOut.ScriptKey = fundingScriptKey

		if err := tapsend.PrepareOutputAssets(ctx, vPkt); err != nil {
			return nil, fmt.Errorf("unable to prepare output "+
				"assets after funding key update: %w", err)
		}
	}

	return fundedPkt, nil
}

// sendInputOwnershipProofs sends the input ownership proofs to the remote
// party during the validation phase of the funding process.
func (f *FundingController) sendInputOwnershipProofs(peerPub btcec.PublicKey,
	vPackets []*tappsbt.VPacket, fundingState *pendingAssetFunding) error {

	ctx, done := f.WithCtxQuit()
	defer done()

	log.Infof("Generating input ownership proofs for %v packets",
		len(vPackets))

	// For each of the inputs we selected, we'll create a new ownership
	// proof for each of them. We'll send this to the peer, so they can
	// verify that we actually own the inputs we're using to fund
	// the channel.
	for _, vPkt := range vPackets {
		for _, assetInput := range vPkt.Inputs {
			// First, we'll grab the proof for the asset input, then
			// generate the challenge witness to place in the proof
			// so it can be sent over.
			wallet := f.cfg.AssetWallet
			challengeWitness, err := wallet.SignOwnershipProof(
				assetInput.Asset(), fn.None[[32]byte](),
			)
			if err != nil {
				return fmt.Errorf("error signing ownership "+
					"proof: %w", err)
			}

			// TODO(roasbeef): use the temp chan ID above? as part
			// of challenge

			// With the witness obtained, we'll emplace it, then add
			// this to our set of relevant input proofs. But we
			// create a copy of the proof first, to make sure we
			// don't modify the vPacket.
			var proofBuf bytes.Buffer
			err = assetInput.Proof.Encode(&proofBuf)
			if err != nil {
				return fmt.Errorf("error serializing proof: %w",
					err)
			}

			proofCopy := &proof.Proof{}
			if err := proofCopy.Decode(&proofBuf); err != nil {
				return fmt.Errorf("error decoding proof: %w",
					err)
			}

			proofCopy.ChallengeWitness = challengeWitness
			fundingState.inputProofs = append(
				fundingState.inputProofs, proofCopy,
			)
		}
	}

	// With all our proofs assembled, we'll now send each of them to the
	// remote peer in series.
	for i := range fundingState.inputProofs {
		proofBytes, _ := fundingState.inputProofs[i].Bytes()
		log.Tracef("Sending input ownership proof to remote party: %x",
			proofBytes)

		inputProof := fundingState.inputProofs[i]
		inputAsset := inputProof.Asset

		// For each proof, we'll chunk them up optimistically to make
		// sure we'll never exceed the upper message limit.
		proofChunks, err := cmsg.CreateProofChunks(
			*inputProof, proofChunkSize,
		)
		if err != nil {
			return fmt.Errorf("unable to create proof "+
				"chunks: %w", err)
		}

		for _, proofChunk := range proofChunks {
			inputProof := cmsg.NewTxAssetInputProof(
				fundingState.pid, inputAsset.ID(),
				inputAsset.Amount, proofChunk,
			)

			// Finally, we'll send the proof to the remote peer.
			err := f.cfg.PeerMessenger.SendMessage(
				ctx, peerPub, inputProof,
			)
			if err != nil {
				return fmt.Errorf("unable to send "+
					"proof to peer: %w", err)
			}
		}
	}

	// Now that we've sent the proofs for the input assets, we'll send them
	// a fully signed asset funding output. We can send this safely as they
	// can't actually broadcast this without our signed Bitcoin inputs.
	for idx := range vPackets {
		vPkt := vPackets[idx]
		signedInputs, err := f.cfg.AssetWallet.SignVirtualPacket(vPkt)
		if err != nil {
			return fmt.Errorf("unable to sign funding inputs: %w",
				err)
		}
		if len(signedInputs) != len(vPkt.Inputs) {
			return fmt.Errorf("expected %v signed inputs, got %v",
				len(vPkt.Inputs), len(signedInputs))
		}
	}

	// We'll now send the signed inputs to the remote party.
	for idx, vPkt := range vPackets {
		fundingOut, err := vPkt.FirstNonSplitRootOutput()
		if err != nil {
			return fmt.Errorf("unable to get funding asset: %w",
				err)
		}

		assetOutputMsg := cmsg.NewTxAssetOutputProof(
			fundingState.pid, *fundingOut.Asset,
			idx == len(vPackets)-1,
		)

		log.Debugf("Sending TLV for funding asset output to remote "+
			"party: %v", limitSpewer.Sdump(fundingOut.Asset))

		err = f.cfg.PeerMessenger.SendMessage(
			ctx, peerPub, assetOutputMsg,
		)
		if err != nil {
			return fmt.Errorf("unable to send proof to peer: %w",
				err)
		}
	}

	return nil
}

// fundPsbt takes our PSBT anchor template and has lnd fund the PSBT with
// enough inputs and a proper change output.
func (f *FundingController) fundPsbt(
	ctx context.Context, psbtPkt *psbt.Packet,
	feeRate chainfee.SatPerKWeight) (*tapsend.FundedPsbt, error) {

	// We set the change index to be a new, 3rd output by specifying -1
	// (which means: please add change output). We could instead have it be
	// the second output, but that would mingle lnd's funds with outputs
	// that mainly store assets.
	changeIndex := int32(-1)
	return f.cfg.ChainWallet.FundPsbt(ctx, psbtPkt, 1, feeRate, changeIndex)
}

// signAllVPackets takes the funding vPSBT, signs all the explicit transfer,
// and then derives all the passive transfers that also needs to be signed, and
// then signs those. A single slice of all the passive and active assets signed
// is returned.
func (f *FundingController) signAllVPackets(ctx context.Context,
	fundingVpkt *tapfreighter.FundedVPacket) ([]*tappsbt.VPacket,
	[]*tappsbt.VPacket, []*tappsbt.VPacket, error) {

	log.Infof("Signing all funding vPackets")

	activePackets := fundingVpkt.VPackets
	for idx := range activePackets {
		encoded, err := tappsbt.Encode(activePackets[idx])
		if err != nil {
			return nil, nil, nil, fmt.Errorf("unable to encode "+
				"active packet: %w", err)
		}

		log.Debugf("Active packet %d: %x", idx, encoded)

		_, err = f.cfg.AssetWallet.SignVirtualPacket(activePackets[idx])
		if err != nil {
			return nil, nil, nil, fmt.Errorf("unable to sign and "+
				"commit virtual packet: %w", err)
		}
	}

	passivePkts, err := f.cfg.AssetWallet.CreatePassiveAssets(
		ctx, activePackets, fundingVpkt.InputCommitments,
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("unable to create passive "+
			"assets: %w", err)
	}
	err = f.cfg.AssetWallet.SignPassiveAssets(passivePkts)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("unable to sign passive "+
			"assets: %w", err)
	}

	allPackets := append([]*tappsbt.VPacket{}, activePackets...)
	allPackets = append(allPackets, passivePkts...)

	err = tapsend.ValidateVPacketVersions(allPackets)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("signed packets: %w", err)
	}

	return allPackets, activePackets, passivePkts, nil
}

// anchorVPackets anchors the vPackets to the funding PSBT, creating a
// complete, but unsigned PSBT packet that can be used to create out asset
// channel.
func (f *FundingController) anchorVPackets(fundedPkt *tapsend.FundedPsbt,
	allPackets []*tappsbt.VPacket) ([]*proof.Proof, error) {

	log.Infof("Anchoring funding vPackets to funding PSBT")

	// Given the set of vPackets we've created, we'll now merge them all to
	// create a map from output index to final tap commitment.
	outputCommitments, err := tapsend.CreateOutputCommitments(allPackets)
	if err != nil {
		return nil, fmt.Errorf("unable to create new output "+
			"commitments: %w", err)
	}

	// Now that we know all the output commitments, we can modify the
	// Bitcoin PSBT to have the proper pkScript that commits to the newly
	// anchored assets.
	for _, vPkt := range allPackets {
		err = tapsend.UpdateTaprootOutputKeys(
			fundedPkt.Pkt, vPkt, outputCommitments,
		)
		if err != nil {
			return nil, fmt.Errorf("error updating taproot output "+
				"keys: %w", err)
		}
	}

	var fundingProofs []*proof.Proof

	// We're done creating the output commitments, we can now create the
	// transition proof suffixes. This'll be the new proof we submit to
	// relevant universe (or not) to update the new resting place of these
	// assets.
	for idx := range allPackets {
		vPkt := allPackets[idx]

		for vOutIdx := range vPkt.Outputs {
			proofSuffix, err := tapsend.CreateProofSuffix(
				fundedPkt.Pkt.UnsignedTx, fundedPkt.Pkt.Outputs,
				vPkt, outputCommitments, vOutIdx, allPackets,
			)
			if err != nil {
				return nil, fmt.Errorf("unable to create "+
					"proof suffix for output %d of vPSBT "+
					"%d: %w", vOutIdx, idx, err)
			}

			vPkt.Outputs[vOutIdx].ProofSuffix = proofSuffix

			// Any output that isn't a split root output is a
			// channel funding output, so we'll store the proofs
			// for those outputs. If there is change, that will be
			// the split root output. And if there is no change,
			// there is no split root output, as it's an interactive
			// transfer.
			if vPkt.Outputs[vOutIdx].Type == tappsbt.TypeSimple {
				fundingProofs = append(
					fundingProofs, proofSuffix,
				)
			}
		}
	}

	return fundingProofs, nil
}

// signAndFinalizePsbt signs and finalizes the PSBT, then returns the finalized
// transaction, but only after sanity checks pass.
func (f *FundingController) signAndFinalizePsbt(ctx context.Context,
	pkt *psbt.Packet) (*wire.MsgTx, error) {

	log.Debugf("Signing and finalizing PSBT w/ lnd: %v",
		limitSpewer.Sdump(pkt))

	// By default, the wallet won't try to finalize output it sees are watch
	// only (like the asset input), so we'll have it sign ourselves first.
	signedPkt, err := f.cfg.ChainWallet.SignPsbt(ctx, pkt)
	if err != nil {
		return nil, fmt.Errorf("unable to sign PSBT: %w", err)
	}

	log.Debugf("Signed PSBT: %v", limitSpewer.Sdump(signedPkt))

	finalizedPkt, err := f.cfg.ChainWallet.SignAndFinalizePsbt(
		ctx, signedPkt,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to finalize PSBT: %w", err)
	}

	log.Debugf("Finalized PSBT: %v", limitSpewer.Sdump(signedPkt))

	// Extra the tx manually, then perform some manual sanity checks to
	// make sure things are ready for broadcast.
	//
	// TODO(roasbeef): could also do testmempoolaccept here
	finalizedTx, err := psbt.Extract(finalizedPkt)
	if err != nil {
		return nil, fmt.Errorf("unable to extract psbt: %w", err)
	}
	err = blockchain.CheckTransactionSanity(btcutil.NewTx(finalizedTx))
	if err != nil {
		return nil, fmt.Errorf("genesis TX failed final checks: "+
			"%w", err)
	}

	return finalizedTx, nil
}

// sendAssetFundingCreated sends the AssetFundingCreated message to the remote
// party.
func (f *FundingController) sendAssetFundingCreated(ctx context.Context,
	fundingState *pendingAssetFunding) error {

	log.Infof("Sending AssetFundingCreated")

	assetFundingCreated := cmsg.NewAssetFundingCreated(
		fundingState.pid, fundingState.assetOutputs(),
	)

	return f.cfg.PeerMessenger.SendMessage(
		ctx, fundingState.peerPub, assetFundingCreated,
	)
}

// completeChannelFunding is the final step in the funding process. This is
// launched as a goroutine after all the input ownership proofs have been sent.
// This method handles the final process of funding+signing the PSBT+vPSBT,
// then presenting the final funding transaction to lnd for validation, before
// ultimately broadcasting the funding transaction.
func (f *FundingController) completeChannelFunding(ctx context.Context,
	fundingState *pendingAssetFunding,
	fundedVpkt *tapfreighter.FundedVPacket) (*wire.OutPoint, error) {

	log.Debugf("Finalizing funding vPackets and PSBT...")

	// Now that we have the initial PSBT template, we can start the funding
	// flow with lnd.
	fundingReq := OpenChanReq{
		ChanAmt:       100_000,
		PushAmt:       fundingState.pushAmt,
		PeerPub:       fundingState.peerPub,
		TempPID:       fundingState.pid,
		RemoteMaxHtlc: maxNumHTLCsPerParty,
	}
	assetChanIntent, err := f.cfg.ChannelFunder.OpenChannel(ctx, fundingReq)
	if err != nil {
		return nil, fmt.Errorf("unable to open channel: %w", err)
	}

	// Now that we have the intent back from lnd, we can use the PSBT
	// information returned to set the proper internal key information for
	// the vPSBT funding output.
	psbtWithFundingOutput, err := assetChanIntent.FundingPsbt()
	if err != nil {
		return nil, fmt.Errorf("unable to get funding PSBT: %w", err)
	}
	internalKeyBytes := psbtWithFundingOutput.Outputs[0].TaprootInternalKey

	log.Debugf("Swapping in true taproot internal key: %x",
		internalKeyBytes)

	fundingInternalKey, err := schnorr.ParsePubKey(internalKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse internal key: %w", err)
	}

	// Overwrite the funding output's anchor information with the on-chain
	// funding output internal key (MuSig2 key).
	fundingPackets := fundedVpkt.VPackets
	for idx := range fundingPackets {
		fundingPkt := fundingPackets[idx]

		// The funding output is the first non-split output (the split
		// output is only present if there is change from the channel
		// funding).
		fundingOut, err := fundingPkt.FirstNonSplitRootOutput()
		if err != nil {
			return nil, fmt.Errorf("unable to find funding output "+
				"in funded packet: %w", err)
		}

		fundingOut.AnchorOutputBip32Derivation = nil
		fundingOut.AnchorOutputTaprootBip32Derivation = nil
		fundingInternalKeyDesc := keychain.KeyDescriptor{
			PubKey: fundingInternalKey,
		}
		fundingOut.SetAnchorInternalKey(
			fundingInternalKeyDesc, f.cfg.ChainParams.HDCoinType,
		)
	}

	// Given the asset inputs selected in the prior step, we'll now
	// construct a template packet that maps our asset inputs to actual
	// inputs in the PSBT packet.
	fundingPsbt, err := tapsend.PrepareAnchoringTemplate(fundingPackets)
	if err != nil {
		return nil, err
	}

	// Now that we have the initial skeleton for our funding PSBT, we'll
	// modify the output value to match the channel amt asked for, which
	// lnd will expect.
	//
	// Later on, after we anchor the vPSBT to the PSBT, we'll then verify
	// with lnd that we arrived at the proper TxOut.
	fundingPsbt.UnsignedTx.TxOut[0].Value = int64(fundingReq.ChanAmt)

	log.Debugf("Funding PSBT pre funding: %s",
		limitSpewer.Sdump(fundingPsbt))

	// With the PSBT template created, we'll now ask lnd to fund the PSBT.
	// This'll add yet another output (lnd's change output) to the
	// template.
	finalFundedPsbt, err := f.fundPsbt(
		ctx, fundingPsbt, fundingState.feeRate.FeePerKWeight(),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to fund PSBT: %w", err)
	}

	log.Infof("Funding PSBT post funding: %s",
		limitSpewer.Sdump(finalFundedPsbt))

	// If we fail at any step in the process, we want to make sure we
	// unlock the inputs, so we'll add them to funding state now.
	fundingState.lockedInputs = finalFundedPsbt.LockedUTXOs

	// TODO(roasbeef): verify the PSBT matches up

	// With the PSBT fully funded, we'll now sign all the vPackets before
	// we finalize anchor them concretely into our PSBt.
	signedPkts, activePkts, passivePkts, err := f.signAllVPackets(
		ctx, fundedVpkt,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to sign vPackets: %w", err)
	}

	// With all the vPackets signed, we'll now anchor them to the funding
	// PSBT. This'll update all the pkScripts for our funding output and
	// change.
	fundingOutputProofs, err := f.anchorVPackets(
		finalFundedPsbt, signedPkts,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to anchor vPackets: %w", err)
	}

	// Now that we've anchored the packets, we'll also set the fundingVOuts
	// which we'll use later to send the AssetFundingCreated message to the
	// responder, and also return the full AuxFundingDesc back to lnd.
	fundingState.fundingOutputProofs = fundingOutputProofs

	// Before we send the finalized PSBT to lnd, we'll send the
	// AssetFundingCreated message which will preceded the normal
	// FundingCreated message.
	if err := f.sendAssetFundingCreated(ctx, fundingState); err != nil {
		return nil, fmt.Errorf("unable to send "+
			"AssetFundingCreated: %w", err)
	}

	log.Debugf("Submitting finalized PSBT to lnd for verification: %s",
		limitSpewer.Sdump(finalFundedPsbt.Pkt))

	// At this point, we're nearly done, we'll now present the final PSBT
	// to lnd to verification. If this passes, then we're clear to
	// sign+broadcast the funding transaction.
	err = assetChanIntent.BindPsbt(ctx, finalFundedPsbt.Pkt)
	if err != nil {
		return nil, fmt.Errorf("unable to bind PSBT: %w", err)
	}

	log.Debugf("PSBT bound, now signing and broadcasting")

	// At this point, we're all clear, so we'll ask lnd to sign the PSBT
	// (all the input information is in place) and also finalize it.
	signedFundingTx, err := f.signAndFinalizePsbt(ctx, finalFundedPsbt.Pkt)
	if err != nil {
		return nil, fmt.Errorf("unable to finalize PSBT: %w", err)
	}

	chainFees, err := finalFundedPsbt.Pkt.GetTxFee()
	if err != nil {
		return nil, fmt.Errorf("unable to get chain fee: %w", err)
	}

	// At this point, we have the fully signed funding transaction ready to
	// go. Before we broadcast, we'll pause here to wait for the signal
	// that it's actually safe to broadcast.
	log.Debugf("Waiting for channel finalized signal...")
	select {
	case <-fundingState.fundingFinalizedSignal:

	case <-time.After(ackTimeout):
		return nil, fmt.Errorf("didn't receive funding ack after %v: "+
			"remote node didn't respond in time or doesn't "+
			"support Taproot Asset Channels", ackTimeout)

	case <-f.Quit:
	}

	log.Debugf("Commit sig received, broadcasting funding tx!")

	// Before we log the transaction, we'll ensure that all the vOuts have
	// a proof courier addr. This ensures the asset funding proof will be
	// found in the target universe.
	for _, vPacket := range activePkts {
		for _, vOut := range vPacket.Outputs {
			vOut.ProofDeliveryAddress = f.cfg.DefaultCourierAddr
		}
	}

	// Rather than publish the final transaction ourselves, we'll instead
	// send it to chain porter, so it can update our on disk UTXO and asset
	// state.
	anchorTx := &tapsend.AnchorTransaction{
		FundedPsbt: &tapsend.FundedPsbt{
			Pkt:               finalFundedPsbt.Pkt,
			ChangeOutputIndex: finalFundedPsbt.ChangeOutputIndex,
			ChainFees:         int64(chainFees),
			LockedUTXOs:       fundingState.lockedInputs,
		},
		ChainFees: int64(chainFees),
		FinalTx:   signedFundingTx,
	}
	preSignedParcel := tapfreighter.NewPreAnchoredParcel(
		activePkts, passivePkts, anchorTx,
	)
	_, err = f.cfg.TxSender.RequestShipment(preSignedParcel)
	if err != nil {
		return nil, fmt.Errorf("error requesting delivery: %w", err)
	}

	fundingTxid := signedFundingTx.TxHash()

	log.Infof("Funding transaction broadcast: %v", fundingTxid)

	// The funding output is always at index 0, because we're using FundPsbt
	// with a change output index of -1, which means we add a change output
	// at the end of the outputs. Meaning the change is always at index 1.
	return &wire.OutPoint{
		Hash:  fundingTxid,
		Index: 0,
	}, nil
}

// processFundingMsg processes a funding message received from the remote peer.
// This is used to advance the state machine of an incoming funding flow.
func (f *FundingController) processFundingMsg(ctx context.Context,
	fundingFlows fundingFlowIndex,
	msg msgmux.PeerMsg) (funding.PendingChanID, error) {

	var tempPID funding.PendingChanID

	// A new proof message has just come in, so we'll extract the real
	// proof wire message from the opaque message.
	proofMsg, assetFunding, err := fundingFlows.fromMsg(
		&f.cfg.ChainParams, msg,
	)
	if err != nil {
		return tempPID, fmt.Errorf("unable to convert msg to "+
			"proof: %w", err)
	}

	log.Infof("Recv'd new message: %T", proofMsg)

	tempPID = assetFunding.pid

	// Whatever the message from the peer is, it's about funding a channel.
	// We can only support asset channels if we have the correct proof
	// courier type configured, so we're ready to receive the channel funds
	// once the channel is (force) closed.
	if err := f.validateLocalProofCourier(ctx); err != nil {
		return tempPID, fmt.Errorf("unable to accept channel funding "+
			"request, local proof courier is invalid: %w", err)
	}

	switch assetProof := proofMsg.(type) {
	// This is input proof, so we'll verify the challenge witness, then
	// store the proof.
	case *cmsg.TxAssetInputProof:
		// By default, we'll get chunks of the proof sent to us. So
		// we'll add this set to the chunks, then proceed but only if we
		// have all the chunks.
		finalProof, err := assetFunding.addInputProofChunk(
			assetProof.ProofChunk.Val,
		).Unpack()
		if err != nil {
			return tempPID, fmt.Errorf("unable to add input proof "+
				"chunk: %w", err)
		}

		// If there's no final proof yet, we can just return early.
		if finalProof.IsNone() {
			return tempPID, nil
		}

		// Otherwise, we have all the proofs we need.
		//
		// Before we proceed, we'll make sure that we already know of
		// the genesis proof for the incoming asset.
		_, err = f.cfg.AssetSyncer.QueryAssetInfo(
			ctx, assetProof.AssetID.Val,
		)
		if err != nil {
			return tempPID, fmt.Errorf("unable to verify genesis "+
				"proof for asset_id=%v: %w",
				assetProof.AssetID.Val, err)
		}
		err = lfn.MapOptionZ(finalProof, func(p proof.Proof) error {
			log.Infof("Validating input proof, prev_out=%v",
				p.OutPoint())

			vCtx := proof.VerifierCtx{
				HeaderVerifier: f.cfg.HeaderVerifier,
				MerkleVerifier: proof.DefaultMerkleVerifier,
				GroupVerifier:  f.cfg.GroupVerifier,
				ChainLookupGen: f.cfg.ChainBridge,
			}

			l, err := f.cfg.ChainBridge.GenProofChainLookup(&p)
			if err != nil {
				return fmt.Errorf("unable to create proof "+
					"lookup: %w", err)
			}

			// Next, we'll validate this proof to make sure that the
			// initiator is actually able to spend these outputs in
			// the funding transaction.
			_, err = p.Verify(ctx, nil, l, vCtx)
			if err != nil {
				return fmt.Errorf("unable to verify "+
					"ownership proof: %w", err)
			}

			// Now that we know the proof is valid, we'll add it to
			// the funding state.
			assetFunding.addInputProof(&p)

			return nil
		})
		if err != nil {
			return tempPID, err
		}

	// This is an output proof, so now we should be able to verify the
	// asset funding output with witness intact.
	case *cmsg.TxAssetOutputProof:
		err := f.validateWitness(
			assetProof.AssetOutput.Val, assetFunding.inputProofs,
		)
		if err != nil {
			return tempPID, fmt.Errorf("unable to verify output "+
				"proof: %w", err)
		}

		// If we reached this point, then the asset output and all
		// inputs are valid, so we'll store the funding asset
		// commitment.
		err = assetFunding.addToFundingCommitment(
			&assetProof.AssetOutput.Val,
		)
		if err != nil {
			return tempPID, fmt.Errorf("unable to create "+
				"commitment: %w", err)
		}

		// Do we expect more proofs to be incoming?
		if !assetProof.Last.Val {
			return tempPID, nil
		}

		// Now that we've validated the funding input and output
		// proofs, we'll send an accept to the remote party.
		assetAck := cmsg.NewAssetFundingAck(tempPID, true)
		err = f.cfg.PeerMessenger.SendMessage(
			ctx, assetFunding.peerPub, assetAck,
		)
		if err != nil {
			return tempPID, fmt.Errorf("unable to send accept "+
				"message: %w", err)
		}

	// As the responder, we'll get this message after we send
	// AcceptChannel. This includes the suffix proofs for the funding
	// output/transaction created by the funding output.
	case *cmsg.AssetFundingCreated:
		log.Infof("Storing funding output proofs")

		fundingProofs := fn.Map(
			assetProof.FundingOutputs.Val.Outputs,
			func(o *cmsg.AssetOutput) *proof.Proof {
				return &o.Proof.Val
			},
		)

		err := f.validateProofs(fundingProofs)
		if err != nil {
			return tempPID, fmt.Errorf("unable to verify funding "+
				"proofs: %w", err)
		}

		// We'll just place this in the internal funding state, so we
		// can derive the funding desc when we need to.
		assetFunding.fundingOutputProofs = append(
			assetFunding.fundingOutputProofs,
			fundingProofs...,
		)

	// The remote party is accepting or rejecting our funding attempt.
	// We'll send the response back to the main goroutine waiting to
	// proceed with funding.
	case *cmsg.AssetFundingAck:
		accept := assetProof.Accept.Val
		assetFunding.fundingAckChan <- accept
	}

	return tempPID, nil
}

// processFundingReq processes a new funding request from the main goroutine.
func (f *FundingController) processFundingReq(fundingFlows fundingFlowIndex,
	fundReq *FundReq) error {

	// Before we even attempt funding, let's make sure that the remote peer
	// actually supports the feature bit.
	supportsAssetChans, err := f.cfg.FeatureBits.HasFeature(
		fundReq.ctx, fundReq.PeerPub,
		lnwire.SimpleTaprootOverlayChansOptional,
	)
	if err != nil {
		return fmt.Errorf("unable to query peer feature bits: %w", err)
	}

	if !supportsAssetChans {
		return fmt.Errorf("peer %x does not support asset channels",
			fundReq.PeerPub.SerializeCompressed())
	}

	// We need to make sure we're ready to receive the channel funds once
	// the channel is (force) closed.
	if err := f.validateLocalProofCourier(fundReq.ctx); err != nil {
		return fmt.Errorf("unable to fund channel, local proof "+
			"courier is invalid: %w", err)
	}

	// Before we proceed, we'll make sure the fee rate we're using is above
	// the min relay fee.
	minRelayFee, err := f.cfg.ChainWallet.MinRelayFee(fundReq.ctx)
	if err != nil {
		return fmt.Errorf("unable to establish min_relay_fee: %w",
			err)
	}
	if fundReq.FeeRate.FeePerKWeight() < minRelayFee {
		return fmt.Errorf("fee rate %v too low, min_relay_fee: %v",
			fundReq.FeeRate.FeePerKWeight(), minRelayFee)
	}

	// To start, we'll make a new pending asset funding desc. This'll be
	// our scratch pad during the asset funding process.
	tempPID, err := newPendingChanID()
	if err != nil {
		return fmt.Errorf("unable to create new pending chan "+
			"ID: %w", err)
	}
	fundingState := &pendingAssetFunding{
		chainParams:            &f.cfg.ChainParams,
		peerPub:                fundReq.PeerPub,
		pid:                    tempPID,
		initiator:              true,
		amt:                    fundReq.AssetAmount,
		pushAmt:                fundReq.PushAmount,
		feeRate:                fundReq.FeeRate,
		fundingAckChan:         make(chan bool, 1),
		fundingFinalizedSignal: make(chan struct{}),
	}

	fundingFlows[tempPID] = fundingState

	// With our initial state created, we'll now attempt to fund the
	// channel on the TAP level with a vPacket.
	fundingVpkt, err := f.fundVirtualPacket(
		fundReq.ctx, fundReq.AssetSpecifier, fundReq.AssetAmount,
	)
	if err != nil {
		return fmt.Errorf("unable to fund vPacket: %w", err)
	}

	// Now that we've funded the vPk, keep track of the set of inputs we
	// locked to ensure we unlock them later.
	fundingState.lockedAssetInputs = fn.FlatMap(
		fundingVpkt.VPackets, func(p *tappsbt.VPacket) []wire.OutPoint {
			return fn.Map(
				p.Inputs,
				func(in *tappsbt.VInput) wire.OutPoint {
					return in.PrevID.OutPoint
				},
			)
		},
	)

	// We'll use this closure to ensure that we'll always unlock the inputs
	// if we encounter an error below.
	unlockLeases := func() {
		ctxb := context.Background()
		err := fundingState.unlockInputs(ctxb, f.cfg.ChainWallet)
		if err != nil {
			log.Errorf("unable to unlock inputs: %v", err)
		}

		err = fundingState.unlockAssetInputs(ctxb, f.cfg.CoinSelector)
		if err != nil {
			log.Errorf("Unable to unlock asset inputs: %v", err)
		}
	}

	// Register a defer to execute if none of the setup below succeeds.
	// This ensures we always unlock the UTXO.
	var setupSuccess bool
	defer func() {
		if !setupSuccess {
			unlockLeases()
		}
	}()

	// We need to limit the number of different fungible assets (asset IDs)
	// we allow to be commited to a single channel. This is to make sure we
	// have a decent number of HTLCs available. See Godoc of maxNumAssetIDs
	// for more information.
	assetIDSet := lfn.NewSet[asset.ID]()
	for _, fundingPacket := range fundingVpkt.VPackets {
		for _, out := range fundingPacket.Outputs {
			assetIDSet.Add(out.Asset.ID())
		}
	}
	if assetIDSet.Size() > maxNumAssetIDs {
		return fmt.Errorf("too many different asset IDs in channel "+
			"funding, got %d, max is %d", len(assetIDSet.ToSlice()),
			maxNumAssetIDs)
	}

	// Now that we know the final funding asset root along with the splits,
	// we can derive the tapscript root that'll be used alongside the
	// internal key (which we'll only learn from lnd later as we finalize
	// the funding PSBT).
	fundingAssets := make([]*asset.Asset, 0, len(fundingVpkt.VPackets))
	for _, pkt := range fundingVpkt.VPackets {
		fundingOut, err := pkt.FirstNonSplitRootOutput()
		if err != nil {
			return fmt.Errorf("unable to find funding output in "+
				"packet: %w", err)
		}

		fundingAssets = append(fundingAssets, fundingOut.Asset.Copy())
	}
	fundingCommitVersion, err := tappsbt.CommitmentVersion(
		fundingVpkt.VPackets[0].Version,
	)
	if err != nil {
		return fmt.Errorf("unable to create commitment: %w", err)
	}

	fundingCommitment, err := commitment.FromAssets(
		fundingCommitVersion, fundingAssets...,
	)
	if err != nil {
		return fmt.Errorf("unable to create commitment: %w", err)
	}

	fundingState.fundingAssetCommitment = fundingCommitment

	tapsend.LogCommitment(
		"funding output", 0, fundingCommitment, &btcec.PublicKey{},
		nil, nil,
	)

	// Before we can send our OpenChannel message, we'll
	// need to derive then send a series of ownership
	// proofs to the remote party.
	err = f.sendInputOwnershipProofs(
		fundReq.PeerPub, fundingVpkt.VPackets, fundingState,
	)
	if err != nil {
		return fmt.Errorf("unable to send input ownership "+
			"proofs: %w", err)
	}

	setupSuccess = true

	// With the ownership proof sent, we'll now spawn a goroutine to take
	// care of the final funding steps.
	f.Wg.Add(1)
	go func() {
		defer f.Wg.Done()

		// If we've failed, then we'll unlock any of the locked
		// UTXOs, so they're free again.
		var completeSuccess bool
		defer func() {
			if !completeSuccess {
				unlockLeases()
			}
		}()

		log.Infof("Waiting for funding ack...")

		// Before we proceed with the channel funding, we'll wait to
		// receive a funding ack from the remote party.
		select {
		case accept := <-fundingState.fundingAckChan:
			log.Infof("funding ack received: accept=%v", accept)
			if !accept {
				return
			}

		case <-time.After(ackTimeout):
			err := fmt.Errorf("didn't receive funding ack after %v",
				ackTimeout)
			log.Error(err)
			fundReq.errChan <- err
			return

		case <-f.Quit:
			return
		}

		chanPoint, err := f.completeChannelFunding(
			fundReq.ctx, fundingState, fundingVpkt,
		)
		if err != nil {
			// If anything went wrong during the funding process,
			// the remote side might have an in-memory state and
			// wouldn't allow us to try again within the next 10
			// minutes (due to only one pending channel per peer
			// default value). To avoid running into this issue, we
			// make sure to inform the remote about us aborting the
			// channel. We don't send them the actual error though,
			// that would give away too much information.
			f.cfg.ErrReporter.ReportError(
				fundReq.ctx, fundReq.PeerPub, tempPID,
				errors.New("internal error"),
			)

			fundReq.errChan <- err
			return
		}

		completeSuccess = true

		fundReq.respChan <- chanPoint
	}()

	return nil
}

// chanFunder is the main event loop that controls the asset specific portions
// of the funding request.
func (f *FundingController) chanFunder() {
	defer f.Wg.Done()

	ctxc, cancel := f.WithCtxQuitNoTimeout()
	defer cancel()

	// All funding related information is only needed until we broadcast
	// the funding transaction. Any state acquired before that can be
	// in-memory only, the same as it works in lnd.
	fundingFlows := make(fundingFlowIndex)

	for {
		select {
		// A new funding request has arrived. We'll set up the funding
		// state, send our input proofs, then kick off the channel
		// funding asynchronously.
		case fundReq := <-f.newFundingReqs:
			err := f.processFundingReq(fundingFlows, fundReq)
			if err != nil {
				log.Error(err)
				fundReq.errChan <- err
				continue
			}

		// The remote party has sent us some upfront proof for channel
		// asset inputs. We'll log this pending chan ID, then validate
		// the proofs included.
		case msg := <-f.msgs:
			tempFundingID, err := f.processFundingMsg(
				ctxc, fundingFlows, msg,
			)
			if err != nil {
				f.cfg.ErrReporter.ReportError(
					ctxc, msg.PeerPub, tempFundingID, err,
				)
				log.Error(err)
			}

		// A new request for a tapscript root has come across. If we
		// know this pid, then we already derived the root before we
		// sent OpenChannel, so we can just send that back to lnd
		case req := <-f.rootReqs:
			pid := req.pendingChanID

			// If there's no funding flow for this pending channel
			// ID, then we have nothing to return.
			fundingFlow, ok := fundingFlows[pid]
			if !ok {
				log.Infof("No funding flow for temp ID %x for "+
					"tapscript root request", pid[:])
				req.resp <- lfn.None[chainhash.Hash]()
				continue
			}

			fundingCommitment := fundingFlow.fundingAssetCommitment
			if fundingCommitment == nil {
				fErr := fmt.Errorf("missing funding commitment")
				f.cfg.ErrReporter.ReportError(
					ctxc, fundingFlow.peerPub, pid,
					fErr,
				)
				continue
			}

			trimmedCommitment, err := commitment.TrimSplitWitnesses(
				&fundingCommitment.Version, fundingCommitment,
			)
			if err != nil {
				fErr := fmt.Errorf("unable to anchor output "+
					"script: %w", err)
				f.cfg.ErrReporter.ReportError(
					ctxc, fundingFlow.peerPub, pid,
					fErr,
				)
				continue
			}

			tapscriptRoot := trimmedCommitment.TapscriptRoot(nil)
			log.Infof("Returning tapscript root: %v", tapscriptRoot)

			req.resp <- lfn.Some(tapscriptRoot)

		// A new request to map a pending channel ID to a complete aux
		// funding desc has just arrived. If we know of the pid, then
		// we'll assemble the full desc now. Otherwise, we return None.
		case req := <-f.bindFundingReqs:
			pid := req.pendingChanID

			// If there's no funding flow for this pending channel
			// ID, then we have nothing to return.
			fundingFlow, ok := fundingFlows[pid]
			if !ok {
				log.Infof("No funding flow for temp ID %x for "+
					"bind funding request", pid[:])
				req.resp <- lfn.None[lnwallet.AuxFundingDesc]()

				continue
			}

			// We'll want to store the decimal display of the asset
			// in the funding blob, so let's determine it now.
			decimalDisplay, err := f.fundingAssetDecimalDisplay(
				ctxc, fundingFlow.assetOutputs(),
			)
			if err != nil {
				fErr := fmt.Errorf("unable to determine "+
					"decimal display: %w", err)
				f.cfg.ErrReporter.ReportError(
					ctxc, fundingFlow.peerPub, pid, fErr,
				)
				continue
			}

			groupKey, err := f.fundingAssetGroupKey(
				ctxc, fundingFlow.assetOutputs(),
			)
			if err != nil {
				fErr := fmt.Errorf("unable to determine group "+
					"key: %w", err)
				f.cfg.ErrReporter.ReportError(
					ctxc, fundingFlow.peerPub, pid, fErr,
				)
				continue
			}

			fundingDesc, err := fundingFlow.toAuxFundingDesc(
				req, decimalDisplay, groupKey,
			)
			if err != nil {
				fErr := fmt.Errorf("unable to create aux "+
					"funding desc: %w", err)
				f.cfg.ErrReporter.ReportError(
					ctxc, fundingFlow.peerPub, pid, fErr,
				)
				continue
			}

			log.Infof("Returning funding desc: %v",
				limitSpewer.Sdump(fundingDesc))

			req.resp <- lfn.Some(*fundingDesc)

		// A prior channel funding we started can now proceed to the
		// broadcast phase.
		case pid := <-f.finalizedChans:
			// We'll look up the funding flow (if it exists), then
			// close the signal that indicates that we're clear to
			// broadcast.
			fundingFlow, ok := fundingFlows[pid]
			if !ok {
				continue
			}

			// We'll use a safe wrapper to ensure that this channel
			// only ever closed once (to avoid a panic).
			fundingFlow.finalizedCloseOnce.Do(func() {
				close(fundingFlow.fundingFinalizedSignal)
			})

		case <-f.Quit:
			return
		}
	}
}

// fundingAssetDecimalDisplay determines the decimal display of the funding
// asset(s). If no specific decimal display value was chosen for the asset, then
// the default value of 0 is returned.
func (f *FundingController) fundingAssetDecimalDisplay(ctx context.Context,
	assetOutputs []*cmsg.AssetOutput) (uint8, error) {

	// We now check the decimal display of each funding asset, to make sure
	// we know the meta information for each asset. And we also verify that
	// each asset tranche has the same decimal display (which should've been
	// verified during the minting process already).
	var decimalDisplay uint8
	for idx, a := range assetOutputs {
		meta, err := f.cfg.AssetSyncer.FetchAssetMetaForAsset(
			ctx, a.AssetID.Val,
		)
		if err != nil {
			return 0, fmt.Errorf("unable to fetch asset meta: %w",
				err)
		}

		decDisplayOpt, err := meta.DecDisplayOption()
		if err != nil {
			return 0, fmt.Errorf("unable to get decimal display "+
				"option: %w", err)
		}

		var thisAssetDecDisplay uint8
		decDisplayOpt.WhenSome(func(decDisplay uint32) {
			// We limit the decimal display value to a maximum of
			// 12, so it should easily fit into an uint8.
			thisAssetDecDisplay = uint8(decDisplay)
		})

		// If this is the first asset we're looking at, we just use the
		// decimal display. Every other asset should have the same
		// decimal display. The value of 0 is a valid decimal display,
		// and we use that if the meta information didn't contain a
		// specific decimal display value, assuming it's either a
		// non-JSON meta information or the value just wasn't set.
		if idx == 0 {
			decimalDisplay = thisAssetDecDisplay
			continue
		}

		// Make sure every subsequent asset has the same decimal display
		// as the first asset.
		if decimalDisplay != thisAssetDecDisplay {
			return 0, fmt.Errorf("decimal display mismatch: "+
				"expected %v, got %v", decimalDisplay,
				thisAssetDecDisplay)
		}
	}

	return decimalDisplay, nil
}

// fundingAssetGroupKey determines the group key of the funding asset(s). If no
// group key was used to fund the channel, then nil is returned.
func (f *FundingController) fundingAssetGroupKey(ctx context.Context,
	assetOutputs []*cmsg.AssetOutput) (*btcec.PublicKey, error) {

	// We now check the group key of each funding asset, to make sure we
	// know the meta information for each asset. And we also verify that
	// each asset tranche has the same group key.
	var groupKey *btcec.PublicKey
	for _, a := range assetOutputs {
		info, err := f.cfg.AssetSyncer.QueryAssetInfo(
			ctx, a.AssetID.Val,
		)
		switch {
		// If the asset isn't a grouped asset (or we don't know the
		// asset), then we just continue.
		case errors.Is(err, address.ErrAssetGroupUnknown):
			continue

		case err != nil:
			return nil, fmt.Errorf("unable to fetch group info: %w",
				err)
		}

		switch {
		// We haven't set the group key before and have found one now,
		// perfect. Let's assume that's our group key we'll use.
		case groupKey == nil && info.GroupKey != nil:
			groupKey = &info.GroupKey.GroupPubKey

		// If we already have a group key, then we need to verify that
		// the group key of this asset matches the one we already have.
		case groupKey != nil && info.GroupKey != nil:
			if !groupKey.IsEqual(&info.GroupKey.GroupPubKey) {
				return nil, fmt.Errorf("group key mismatch: "+
					"expected %x, got %x",
					groupKey.SerializeCompressed(),
					info.GroupPubKey.SerializeCompressed())
			}

		// If a previous asset resulted in a group key, every following
		// one must also result in the same one. If we can't find one
		// now, it means we either don't know about the asset (not
		// synced) or it's not a grouped asset.
		case groupKey != nil && info.GroupKey == nil:
			return nil, fmt.Errorf("group key mismatch: "+
				"expected %x, got nil",
				groupKey.SerializeCompressed())

		// If we don't have a group key yet, and the asset isn't a
		// grouped asset, then we just continue.
		case groupKey == nil && info.GroupKey == nil:
			continue
		}
	}

	return groupKey, nil
}

// channelAcceptor is a callback that's called by the lnd client when a new
// channel is proposed. This function is responsible for deciding whether to
// accept the channel based on the channel parameters, and to also set some
// channel parameters for our own side.
func (f *FundingController) channelAcceptor(_ context.Context,
	req *lndclient.AcceptorRequest) (*lndclient.AcceptorResponse, error) {

	// Avoid nil pointer dereference.
	if req.CommitmentType == nil {
		return nil, fmt.Errorf("commitment type is required")
	}

	// Ignore any non-asset channels, just accept them.
	if *req.CommitmentType != lnwallet.CommitmentTypeSimpleTaprootOverlay {
		return &lndclient.AcceptorResponse{
			Accept: true,
		}, nil
	}

	// Reject custom channels that don't observe the max HTLC limit.
	if req.MaxAcceptedHtlcs > maxNumHTLCsPerParty {
		return &lndclient.AcceptorResponse{
			Accept: false,
			Error: fmt.Sprintf("max accepted HTLCs must be at "+
				"most %d, got %d", maxNumHTLCsPerParty,
				req.MaxAcceptedHtlcs),
		}, nil
	}

	// Everything looks good, we can now set our own max HTLC limit we'll
	// observe for this channel.
	return &lndclient.AcceptorResponse{
		Accept:       true,
		MaxHtlcCount: maxNumHTLCsPerParty,
	}, nil
}

// validateProofs validates the inclusion/exclusion/split proofs and the
// transfer witness of the given proofs.
func (f *FundingController) validateProofs(proofs []*proof.Proof) error {
	for _, p := range proofs {
		_, err := p.VerifyProofs()
		if err != nil {
			return fmt.Errorf("unable to verify proofs: %w", err)
		}
	}

	return nil
}

// validateWitness validates the state transition witness for the given asset.
func (f *FundingController) validateWitness(outAsset asset.Asset,
	inputAssetProofs []*proof.Proof) error {

	// First, we'll populate a map of all the previous inputs. This is like
	// the prev output fetcher for Bitcoin.
	prevAssets := make(commitment.InputSet)
	for _, p := range inputAssetProofs {
		// We validate on the individual vPSBT level, so we will only
		// use the inputs that actually match the current output's asset
		// ID.
		if outAsset.ID() != p.Asset.ID() {
			continue
		}

		prevID := asset.PrevID{
			OutPoint:  p.OutPoint(),
			ID:        p.Asset.ID(),
			ScriptKey: asset.ToSerialized(p.Asset.ScriptKey.PubKey),
		}
		prevAssets[prevID] = &p.Asset
	}

	newAsset := &outAsset
	if outAsset.HasSplitCommitmentWitness() {
		newAsset = &outAsset.PrevWitnesses[0].SplitCommitment.RootAsset
	}

	// We create a file out of the input proofs, even if they aren't a chain
	// of proofs. But the chain lookup will need them to look up transaction
	// and block information in those proofs, so it's easiest to provide
	// them as a single file that can be iterated through.
	derefProofs := fn.Map(inputAssetProofs, fn.DerefPanic)
	proofFile, err := proof.NewFile(proof.V0, derefProofs...)
	if err != nil {
		return fmt.Errorf("unable to create proof file: %w", err)
	}

	// With the inputs specified, we'll now attempt to validate the state
	// transition for the asset funding output.
	chainLookup := f.cfg.ChainBridge.GenFileChainLookup(proofFile)
	verifyOpt := vm.WithChainLookup(chainLookup)
	engine, err := vm.New(newAsset, nil, prevAssets, verifyOpt)
	if err != nil {
		return fmt.Errorf("unable to create VM: %w", err)
	}

	if err := engine.Execute(); err != nil {
		return fmt.Errorf("invalid witness: %w", err)
	}

	return nil
}

// validateLocalProofCourier checks if the local proof courier is supported by
// the funding controller. This is necessary to ensure that we can accept
// incoming asset channel funding requests, which only works if we have a
// universe based proof courier configured. A hashmail based courier can't deal
// with the OP_TRUE funding output script key, as that's the same for asset
// channels out there. So the single mailbox would always be occupied.
func (f *FundingController) validateLocalProofCourier(
	ctx context.Context) error {

	courierURL := f.cfg.DefaultCourierAddr

	flagHelp := "please set a universe based (universerpc://) proof " +
		"courier in the proofcourieraddr configuration option or " +
		"command line flag"

	// There should always be a fallback proof courier, so this case
	// shouldn't be possible. But we check anyway.
	if courierURL == nil {
		return fmt.Errorf("no proof courier configured, %v", flagHelp)
	}

	// We need the courier to be a universe based courier, as the hashmail
	// courier can't deal with channel funding outputs.
	if courierURL.Scheme != proof.UniverseRpcCourierType {
		return fmt.Errorf("unsupported proof courier type '%v', %v",
			courierURL.Scheme, flagHelp)
	}

	return proof.CheckUniverseRpcCourierConnection(
		ctx, proofCourierCheckTimeout, courierURL,
	)
}

// FundReq is a message that's sent to the funding controller to request a new
// asset channel funding.
type FundReq struct {
	// PeerPub is the public key of the peer that we're funding a channel
	// with.
	//
	// TODO(roasbeef): also need p2p address?
	PeerPub btcec.PublicKey

	// AssetSpecifier is the asset that we're funding the channel with.
	AssetSpecifier asset.Specifier

	// AssetAmount is the amount of the asset that we're funding the channel
	// with.
	AssetAmount uint64

	// FeeRate is the fee rate that we'll use to fund the channel.
	FeeRate chainfee.SatPerVByte

	// PushAmount is the amount of satoshis that we'll push to the remote
	// party.
	PushAmount btcutil.Amount

	ctx      context.Context
	respChan chan *wire.OutPoint
	errChan  chan error
}

// FundChannel attempts to fund a new channel with the backing lnd node based
// on the passed funding request. If successful, the TXID of the funding
// transaction is returned.
func (f *FundingController) FundChannel(ctx context.Context,
	req FundReq) (*wire.OutPoint, error) {

	req.ctx = ctx
	req.respChan = make(chan *wire.OutPoint, 1)
	req.errChan = make(chan error, 1)

	if !fn.SendOrQuit(f.newFundingReqs, &req, f.Quit) {
		return nil, fmt.Errorf("funding controller is shutting down")
	}

	return fn.RecvResp(req.respChan, req.errChan, f.Quit)
}

// DescFromPendingChanID takes a pending channel ID, that may already be known
// due to prior custom channel messages, and maybe returns an aux funding desc
// which can be used to modify how a channel is funded.
func (f *FundingController) DescFromPendingChanID(pid funding.PendingChanID,
	openChan lnwallet.AuxChanState,
	keyRing lntypes.Dual[lnwallet.CommitmentKeyRing],
	initiator bool) funding.AuxFundingDescResult {

	type returnType = lfn.Option[lnwallet.AuxFundingDesc]

	req := &bindFundingReq{
		pendingChanID: pid,
		initiator:     initiator,
		openChan:      openChan,
		keyRing:       keyRing,
		resp: make(
			chan lfn.Option[lnwallet.AuxFundingDesc], 1,
		),
	}

	if !fn.SendOrQuit(f.bindFundingReqs, req, f.Quit) {
		return lfn.Err[returnType](fmt.Errorf("timeout when sending " +
			"to funding controller"))
	}

	resp, err := fn.RecvResp(req.resp, nil, f.Quit)
	if err != nil {
		return lfn.Err[returnType](fmt.Errorf("timeout when waiting "+
			"for response: %w", err))
	}

	return lfn.Ok(resp)
}

// DeriveTapscriptRoot returns the tapscript root for the channel identified by
// the pid. If we don't have any information about the channel, we return None.
func (f *FundingController) DeriveTapscriptRoot(
	pid funding.PendingChanID) funding.AuxTapscriptResult {

	type returnType = lfn.Option[chainhash.Hash]

	req := &assetRootReq{
		pendingChanID: pid,
		resp:          make(chan lfn.Option[chainhash.Hash], 1),
	}

	if !fn.SendOrQuit(f.rootReqs, req, f.Quit) {
		return lfn.Err[returnType](fmt.Errorf("timeout when sending " +
			"to funding controller"))
	}

	resp, err := fn.RecvResp(req.resp, nil, f.Quit)
	if err != nil {
		return lfn.Err[returnType](fmt.Errorf("timeout when waiting "+
			"for response: %w", err))
	}

	return lfn.Ok(resp)
}

// ChannelReady is called when a channel has been fully opened and is ready to
// be used. This can be used to perform any final setup or cleanup.
func (f *FundingController) ChannelReady(channel lnwallet.AuxChanState) error {
	// Currently, there is only something we need to do if we are the
	// responder of a channel funding. Since we're going to be swapping
	// assets for BTC, we need to have a buy offer ready for the channel
	// amount.
	if channel.IsInitiator {
		return nil
	}

	// No custom blob means no asset channel, so nothing to do.
	if channel.CustomBlob.IsNone() {
		return nil
	}

	chanAssetState, err := cmsg.DecodeOpenChannel(
		channel.CustomBlob.UnsafeFromSome(),
	)
	if err != nil {
		return fmt.Errorf("unable to decode channel asset state: %w",
			err)
	}

	// TODO: Sell offer as well? Also, what amount to choose? Could be that
	// channel balance is shifted multiple times, exceeding total channel
	// capacity over time. Need to renew the offers(s)?
	for _, fundedAsset := range chanAssetState.Assets() {
		err := f.cfg.RfqManager.UpsertAssetBuyOffer(rfq.BuyOffer{
			AssetID:  &fundedAsset.AssetID.Val,
			MaxUnits: fundedAsset.Amount.Val,
		})
		if err != nil {
			return fmt.Errorf("error inserting asset buy offer: %w",
				err)
		}
	}

	return nil
}

// ChannelFinalized is called once lnd has received a valid commit signature
// for our local commitment. At this point, it's safe to broadcast the funding
// transaction.
func (f *FundingController) ChannelFinalized(pid funding.PendingChanID) error {
	if !fn.SendOrQuit(f.finalizedChans, pid, f.Quit) {
		return fmt.Errorf("timeout when sending to funding controller")
	}

	return nil
}

// Name returns the name of this endpoint. This MUST be unique across all
// registered endpoints.
func (f *FundingController) Name() string {
	return MsgEndpointName
}

// CanHandle returns true if the target message can be routed to this endpoint.
func (f *FundingController) CanHandle(msg msgmux.PeerMsg) bool {
	log.Tracef("Request to handle: %T", msg.Message)
	log.Tracef("Request to handle: %v", int64(msg.MsgType()))

	//nolint:exhaustive
	switch m := msg.Message.(type) {
	case *lnwire.Custom:
		switch m.MsgType() {
		case cmsg.TxAssetInputProofType:
			fallthrough
		case cmsg.TxAssetOutputProofType:
			fallthrough
		case cmsg.AssetFundingCreatedType:
			fallthrough
		case cmsg.AssetFundingAckType:
			return true
		}

	case *cmsg.TxAssetInputProof:
		return true
	case *cmsg.TxAssetOutputProof:
		return true
	case *cmsg.AssetFundingCreated:
		return true
	case *cmsg.AssetFundingAck:
		return true
	}

	log.Tracef("FundingController encountered an unsupported message "+
		"type: %T", msg.Message)
	return false
}

// SendMessage handles the target message, and returns true if the message was
// able being processed.
func (f *FundingController) SendMessage(_ context.Context,
	msg msgmux.PeerMsg) bool {

	return fn.SendOrQuit(f.msgs, msg, f.Quit)
}

// TODO(roasbeef): try to protofsm it?

// A compile-time assertion to ensure FundingController meets the
// funding.AuxFundingController interface.
var _ funding.AuxFundingController = (*FundingController)(nil)
