package taroscript

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
)

// enum to define each stage of an asset send
type SendState uint8

// Start with one state per function
// TODO(jhb): add state transition path for modifying locators
// State name signals the state change of the send, within the state
const (
	SendStateInitializing SendState = iota

	// TODO(jhb): Preceding states for input lookup given address input

	SendStateValidatedInput

	SendStatePreparedSplit

	SendStatePreparedComplete

	SendStateSigned

	SendStateCommitmentsUpdated

	SendStateValidatedLocators

	SendStateCommitted

	// TODO(jhb): Following states for finalization and broadcast
)

// wrapper for state carried across state transitions
type SendPackage struct {
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

	PrevTaroTree commitment.TaroCommitment

	Locators SpendLocators

	// signal if we need to recompute the send
	LocatorsUpdated bool

	// signal if we need a split
	NeedsSplit bool

	// Receiver
	Address address.Taro

	// nil at start, then reassigned to match current state
	SendDelta *SpendDelta

	SendCommitments SpendCommitments

	// TODO(jhb): Wrap the PSBT with extra data?
	SendPacket *psbt.Packet
}

// Config for an instance of the Porter
type PorterConfig struct {
	// current package
	Package SendPackage

	// Will need to modify Signer and maybe WalletAnchor?
	// tarogarden.GardenKit

	// Something else? Not sure why we need a func()
	CompletionChan chan<- bool

	ErrChan chan<- error
}

type Porter struct {
	startOnce sync.Once
	stopOnce  sync.Once

	cfg *PorterConfig

	// confEvent + confInfo

	*chanutils.ContextGuard
}

func NewPorter(cfg *PorterConfig) *Porter {
	return &Porter{
		cfg: cfg,
		ContextGuard: &chanutils.ContextGuard{
			DefaultTimeout: tarogarden.DefaultTimeout,
			Quit:           make(chan struct{}),
		},
	}
}

func (p *Porter) Start() error {
	var startErr error
	p.startOnce.Do(func() {
		p.Wg.Add(1)
		go p.taroPorter()
	})
	return startErr
}

func (p *Porter) Stop() error {
	var stopErr error
	p.stopOnce.Do(func() {
		close(p.Quit)
		p.Wg.Wait()
	})

	return stopErr
}

func (p *Porter) advanceStateUntil(currentState, targetState SendState) error {
	log.Infof("Porter advancing from state=%v to state=%v",
		currentState, targetState)

	var terminalState bool
	for !terminalState {
		// Before we attempt a state transition, make sure that we
		// aren't trying to shut down.
		select {
		case <-p.Quit:
			return fmt.Errorf("Porter shutting down")

		default:
		}

		nextState, err := p.stateStep(currentState)
		if err != nil {
			return fmt.Errorf("unable to advance "+
				"state machine: %w", err)
		}

		// We've reached a terminal state once the next state is our
		// current state (state machine loops back to the current
		// state).
		terminalState = nextState == currentState

		currentState = nextState

		p.cfg.Package.SendState = currentState
	}

	return nil
}

// main state machine goroutine; advance state, wait for TX confirmation
func (p *Porter) taroPorter() {
	defer p.Wg.Done()

	// TODO(jhb): Handle restart

	err := p.advanceStateUntil(p.cfg.Package.SendState, SendStateCommitted)
	if err != nil {
		log.Errorf("unable to advance state machine: %v", err)
		return
	}

	// TODO(jhb): Logic for waiting on TX confirmation

	p.cfg.CompletionChan <- true
}

// goroutine func

func (p *Porter) stateStep(currentState SendState) (SendState, error) {
	// big ol' switch statement
	switch currentState {
	// init state
	case SendStateInitializing:
		// TODO(jhb): Accept input, DB access to fill out package
		// Should get PrevID, PrevTaroTree, PrevAsset
		// Everything should be initialized, spendDelta and PSBT are nil
		if p.cfg.Package.ChainParams == nil {
			return 0, fmt.Errorf("network for send unspecified")
		}
		initSpend := SpendDelta{
			InputAssets: make(commitment.InputSet),
		}
		p.cfg.Package.SendDelta = &initSpend
		p.cfg.Package.LocatorsUpdated = false
		if p.cfg.Package.Locators != nil {
			p.cfg.Package.SendDelta.
				Locators = p.cfg.Package.Locators
		}
		p.cfg.Package.NeedsSplit = false

		return SendStateValidatedInput, nil
	// validate input
	case SendStateValidatedInput:
		inputAsset, needsSplit, err := isValidInput(
			p.cfg.Package.PrevTaroTree, p.cfg.Package.Address,
			p.cfg.Package.PrevID.ScriptKey,
			*p.cfg.Package.ChainParams)
		if err != nil {
			return 0, err
		}
		p.cfg.Package.SendDelta.
			InputAssets[p.cfg.Package.PrevID] = inputAsset
		p.cfg.Package.NeedsSplit = needsSplit
		if needsSplit {
			return SendStatePreparedSplit, nil
		} else {
			return SendStatePreparedComplete, nil
		}
	// prepare split send
	case SendStatePreparedSplit:
		preparedSpend, err := prepareAssetSplitSpend(
			p.cfg.Package.Address, p.cfg.Package.PrevID,
			p.cfg.Package.ScriptKey, *p.cfg.Package.SendDelta,
		)
		if err != nil {
			return 0, err
		}
		p.cfg.Package.SendDelta = preparedSpend

		return SendStateSigned, nil
	// prepare complete send
	case SendStatePreparedComplete:
		preparedSpend := prepareAssetCompleteSpend(
			p.cfg.Package.Address, p.cfg.Package.PrevID,
			*p.cfg.Package.SendDelta,
		)
		p.cfg.Package.SendDelta = preparedSpend

		return SendStateSigned, nil
	// sign / complete the send
	case SendStateSigned:
		completedSpend, err := completeAssetSpend(
			p.cfg.Package.PrivKey, p.cfg.Package.PrevID,
			*p.cfg.Package.SendDelta,
		)
		if err != nil {
			return 0, err
		}
		p.cfg.Package.SendDelta = completedSpend

		return SendStateCommitmentsUpdated, nil
	// update commitments, check if we updated locators
	case SendStateCommitmentsUpdated:
		SpendCommitments, err := createSpendCommitments(
			p.cfg.Package.PrevTaroTree, p.cfg.Package.PrevID,
			*p.cfg.Package.SendDelta, p.cfg.Package.Address,
			p.cfg.Package.ScriptKey,
		)
		if err != nil {
			return 0, err
		}
		p.cfg.Package.SendCommitments = SpendCommitments

		if p.cfg.Package.LocatorsUpdated {
			return SendStateValidatedLocators, nil
		}

		return SendStateCommitted, nil

	// validate new locators and jump back to send preparation
	case SendStateValidatedLocators:
		validLocators, err := areValidIndexes(p.cfg.Package.Locators)
		if err != nil {
			return 0, err
		}

		if !validLocators {
			return 0, fmt.Errorf(
				"invalid custom locators given for send",
			)
		}

		// update SendDelta with new locators
		// clear other fields? May not be needed
		p.cfg.Package.SendDelta.Locators = p.cfg.Package.Locators
		p.cfg.Package.SendDelta.NewAsset = asset.Asset{}
		p.cfg.Package.SendDelta.SplitCommitment = nil
		// Unset locator update flag
		p.cfg.Package.LocatorsUpdated = false

		// jump back to send preparation
		if p.cfg.Package.NeedsSplit {
			return SendStatePreparedSplit, nil
		} else {
			return SendStatePreparedComplete, nil
		}

	// create PSBT outputs
	case SendStateCommitted:
		sendPacket, err := createSpendOutputs(
			p.cfg.Package.Address, p.cfg.Package.SendDelta.Locators,
			p.cfg.Package.InternalKey, p.cfg.Package.ScriptKey,
			p.cfg.Package.SendCommitments,
		)
		if err != nil {
			return 0, err
		}

		p.cfg.Package.SendPacket = sendPacket

		//terminal, return to this state
		return SendStateCommitted, nil
	default:
		return SendStateInitializing, fmt.Errorf(
			"unknown state: %v", currentState,
		)
	}
}
