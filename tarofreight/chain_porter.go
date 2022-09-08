package tarofreight

import (
	"fmt"
	"sync"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/lightninglabs/taro/address"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/chanutils"
	"github.com/lightninglabs/taro/commitment"
	"github.com/lightninglabs/taro/tarogarden"
	"github.com/lightninglabs/taro/taroscript"
)

// enum to define each stage of an asset send
type SendState uint8

// Start with one state per function
// TODO(jhb): add state transition path for modifying locators
// State name signals the state change of the send, within the state
const (
	SendStateInitializing SendState = iota

	// TODO(jhb): Preceding states for input lookup given address input

	SendStateCommitmentSelect

	SendStateValidatedInput

	SendStatePreparedSplit

	SendStatePreparedComplete

	SendStateSigned

	SendStateCommitmentsUpdated

	SendStateValidatedLocators

	SendStateCommitted

	// TODO(jhb): Following states for finalization and broadcast
)

// Config for an instance of the ChainPorter
type ChainPorterConfig struct {
	// Will need to modify Signer and maybe WalletAnchor?
	// tarogarden.GardenKit

	// CoinSelector...
	CoinSelector CommitmentSelector
}

// AssetParcel...
type AssetParcel struct {
	// Dest...
	Dest address.Taro

	// resp...
	//
	// TODO(roasbeef): should be txid w/ complete send info?
	//  * then can log in the command line, et
	respChan chan struct{}

	// errChan...
	errChan chan error
}

// ChainPorter...
type ChainPorter struct {
	startOnce sync.Once
	stopOnce  sync.Once

	cfg *ChainPorterConfig

	exportReqs chan *AssetParcel

	// confEvent + confInfo

	*chanutils.ContextGuard
}

// NewChainPorter...
func NewChainPorter(cfg *ChainPorterConfig) *ChainPorter {
	return &ChainPorter{
		cfg:        cfg,
		exportReqs: make(chan *AssetParcel),
		ContextGuard: &chanutils.ContextGuard{
			DefaultTimeout: tarogarden.DefaultTimeout,
			Quit:           make(chan struct{}),
		},
	}
}

// Start...
func (p *ChainPorter) Start() error {
	var startErr error
	p.startOnce.Do(func() {
		p.Wg.Add(1)
		go p.taroPorter()
	})
	return startErr
}

// Stop...
func (p *ChainPorter) Stop() error {
	var stopErr error
	p.stopOnce.Do(func() {
		close(p.Quit)
		p.Wg.Wait()
	})

	return stopErr
}

// RequestShipment...
func (p *ChainPorter) RequestShipment(req *AssetParcel) (any, error) {
	req.errChan = make(chan error, 1)
	req.respChan = make(chan struct{}, 1)

	if !chanutils.SendOrQuit(p.exportReqs, req, p.Quit) {
		return nil, fmt.Errorf("ChainPorter shutting down")
	}

	select {
	case err := <-req.errChan:
		return nil, err

	case resp := <-req.respChan:
		return resp, nil

	case <-p.Quit:
		return nil, fmt.Errorf("ChainPorter shutting down")
	}
}

// sendPackage...
//
// wrapper for state carried across state transitions
type sendPackage struct {
	SendState SendState

	ChainParams *address.ChainParams

	// Sender, all will be mapped to the change asset leaf
	InternalKey btcec.PublicKey

	// TODO(jhb): Replace with VM signer
	PrivKey btcec.PrivateKey

	ScriptKey btcec.PublicKey

	// TODO(jhb): optional SpendLocators
	// TODO(jhb): map sender state key to PrevID?
	// TODO(jhb): map sender state key to PrevTaroTree?
	// Includes PrevScriptKey
	PrevID asset.PrevID

	PrevAsset asset.Asset

	// PrevTaroTree...
	//
	// TODO(roasbeef): should be filled in by coin selection
	PrevTaroTree commitment.TaroCommitment

	Locators taroscript.SpendLocators

	// signal if we need to recompute the send
	LocatorsUpdated bool

	// signal if we need a split
	NeedsSplit bool

	// Receiver
	Address address.Taro

	// nil at start, then reassigned to match current state
	SendDelta *taroscript.SpendDelta

	SendCommitments taroscript.SpendCommitments

	// TODO(jhb): Wrap the PSBT with extra data?
	SendPacket *psbt.Packet
}

// main state machine goroutine; advance state, wait for TX confirmation
func (p *ChainPorter) taroPorter() {
	defer p.Wg.Done()

	for {
		select {
		case req := <-p.exportReqs:
			var sendPkg sendPackage

			err := p.advanceStateUntil(&sendPkg, SendStateCommitted)
			if err != nil {
				log.Warnf("unable to advance state machine: %v", err)
				req.errChan <- err
				continue
			}

			// TODO(jhb): Logic for waiting on TX confirmation

			req.respChan <- struct{}{}

		case <-p.Quit:
			return
		}
	}

}

// advanceStateUntil...
func (p *ChainPorter) advanceStateUntil(currentPkg *sendPackage,
	targetState SendState) error {

	log.Infof("ChainPorter advancing from state=%v to state=%v",
		currentPkg.SendState, targetState)

	var terminalState bool
	for !terminalState {
		// Before we attempt a state transition, make sure that we
		// aren't trying to shut down.
		select {
		case <-p.Quit:
			return fmt.Errorf("Porter shutting down")

		default:
		}

		updatedPkg, err := p.stateStep(*currentPkg)
		if err != nil {
			return fmt.Errorf("unable to advance "+
				"state machine: %w", err)
		}

		// We've reached a terminal state once the next state is our
		// current state (state machine loops back to the current
		// state).
		terminalState = updatedPkg.SendState == targetState

		currentPkg = updatedPkg
	}

	return nil
}

// goroutine func

// stateStep...
func (p *ChainPorter) stateStep(currentPkg sendPackage) (*sendPackage, error) {
	// big ol' switch statement
	switch currentPkg.SendState {
	// init state
	case SendStateInitializing:
		// Should get PrevID, PrevTaroTree, PrevAsset
		// Everything should be initialized, spendDelta and PSBT are nil
		//
		// TODO(jhb): Accept input, DB access to fill out package
		if currentPkg.ChainParams == nil {
			return nil, fmt.Errorf("network for send unspecified")
		}

		initSpend := taroscript.SpendDelta{
			InputAssets: make(commitment.InputSet),
		}

		currentPkg.SendDelta = &initSpend
		currentPkg.LocatorsUpdated = false

		if currentPkg.Locators != nil {
			currentPkg.SendDelta.Locators = currentPkg.Locators
		}

		currentPkg.NeedsSplit = false

		currentPkg.SendState = SendStateValidatedInput

		return &currentPkg, nil

	// At this point we have the initial package information populated, so
	// we'll perform coin selection to see if the send request is even
	// possible at all.
	case SendStateCommitmentSelect:
		// We need to find a commitment that has enough assets to
		// satisfy this send request. We'll map the address to a set of
		// constraints, so we can use that to do Taro asset coin
		// selection.
		//
		// TODO(roasbeef): should be able to support multiple inputs
		constraints := &CommitmentConstraints{
			FamilyKey: currentPkg.Address.FamilyKey,
			ID:        currentPkg.Address.ID,
			Amt:       currentPkg.Address.Amount,
			AssetType: currentPkg.Address.Type,
		}
		assetInput, err := p.cfg.CoinSelector.SelectCommitment(
			constraints,
		)
		if err != nil {
			return nil, err
		}

		// At this point, we have a valid "coin" to spend in the
		// commitment, so we'll update teh relevant information in the
		// send package.
		//
		// TODO(roasbeef): still need to add family key to PrevID.
		currentPkg.PrevTaroTree = assetInput.Commitment
		currentPkg.PrevID = asset.PrevID{
			OutPoint:  assetInput.AnchorPoint,
			ID:        assetInput.Asset.ID(),
			ScriptKey: *assetInput.Asset.ScriptKey.PubKey,
		}
		currentPkg.PrevAsset = assetInput.Asset

		currentPkg.SendState = SendStateValidatedInput

		return &currentPkg, nil

	// validate input
	case SendStateValidatedInput:
		inputAsset, needsSplit, err := taroscript.IsValidInput(
			currentPkg.PrevTaroTree, currentPkg.Address,
			currentPkg.PrevID.ScriptKey,
			*currentPkg.ChainParams,
		)
		if err != nil {
			return nil, err
		}

		currentPkg.SendDelta.InputAssets[currentPkg.PrevID] = inputAsset

		currentPkg.NeedsSplit = needsSplit

		if needsSplit {
			currentPkg.SendState = SendStatePreparedSplit
		} else {
			currentPkg.SendState = SendStatePreparedComplete
		}

		return &currentPkg, nil

	// prepare split send
	case SendStatePreparedSplit:
		preparedSpend, err := taroscript.PrepareAssetSplitSpend(
			currentPkg.Address, currentPkg.PrevID,
			currentPkg.ScriptKey, *currentPkg.SendDelta,
		)
		if err != nil {
			return nil, err
		}

		currentPkg.SendDelta = preparedSpend

		currentPkg.SendState = SendStateSigned

		return &currentPkg, nil

	// prepare complete send
	case SendStatePreparedComplete:
		preparedSpend := taroscript.PrepareAssetCompleteSpend(
			currentPkg.Address, currentPkg.PrevID,
			*currentPkg.SendDelta,
		)
		currentPkg.SendDelta = preparedSpend

		currentPkg.SendState = SendStateSigned

		return &currentPkg, nil

	// sign / complete the send
	case SendStateSigned:
		completedSpend, err := taroscript.CompleteAssetSpend(
			currentPkg.PrivKey, currentPkg.PrevID,
			*currentPkg.SendDelta,
		)
		if err != nil {
			return nil, err
		}

		currentPkg.SendDelta = completedSpend

		currentPkg.SendState = SendStateCommitmentsUpdated

		return &currentPkg, nil

	// update commitments, check if we updated locators
	case SendStateCommitmentsUpdated:
		SpendCommitments, err := taroscript.CreateSpendCommitments(
			currentPkg.PrevTaroTree, currentPkg.PrevID,
			*currentPkg.SendDelta, currentPkg.Address,
			currentPkg.ScriptKey,
		)
		if err != nil {
			return nil, err
		}

		currentPkg.SendCommitments = SpendCommitments

		if currentPkg.LocatorsUpdated {
			currentPkg.SendState = SendStateValidatedLocators
		}

		currentPkg.SendState = SendStateCommitted

		return &currentPkg, nil

	// validate new locators and jump back to send preparation
	case SendStateValidatedLocators:
		validLocators, err := taroscript.AreValidIndexes(
			currentPkg.Locators,
		)
		if err != nil {
			return nil, err
		}

		if !validLocators {
			return nil, fmt.Errorf("invalid custom locators " +
				"given for send")
		}

		// update SendDelta with new locators
		// clear other fields? May not be needed
		currentPkg.SendDelta.Locators = currentPkg.Locators
		currentPkg.SendDelta.NewAsset = asset.Asset{}
		currentPkg.SendDelta.SplitCommitment = nil

		// Unset locator update flag
		currentPkg.LocatorsUpdated = false

		// jump back to send preparation
		if currentPkg.NeedsSplit {
			currentPkg.SendState = SendStatePreparedSplit
		} else {
			currentPkg.SendState = SendStatePreparedComplete
		}

		return &currentPkg, nil

	// create PSBT outputs
	case SendStateCommitted:
		sendPacket, err := taroscript.CreateSpendOutputs(
			currentPkg.Address, currentPkg.SendDelta.Locators,
			currentPkg.InternalKey, currentPkg.ScriptKey,
			currentPkg.SendCommitments,
		)
		if err != nil {
			return nil, err
		}

		currentPkg.SendPacket = sendPacket

		// terminal, return to this state
		currentPkg.SendState = SendStateCommitted

		return &currentPkg, nil
	default:
		return &currentPkg, fmt.Errorf("unknown state: %v",
			currentPkg.SendState)
	}
}
