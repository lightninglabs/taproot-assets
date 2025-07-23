package supplyverifier

import (
	"fmt"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/lightninglabs/taproot-assets/universe/supplycommit"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/protofsm"
)

var (
	// ErrInvalidStateTransition is returned when we receive an unexpected
	// event for a given state.
	ErrInvalidStateTransition = fmt.Errorf("invalid state transition")
)

// Event is a special interface used to create the equivalent of a sum-type, but
// using a "sealed" interface.
type Event interface {
	eventSealed()
}

// Events is a special type constraint that enumerates all the possible protocol
// events.
type Events interface {
}

// StateTransition is the StateTransition type specific to the supply verifier
// state machine.
type StateTransition = protofsm.StateTransition[Event, *Environment]

// State is our sum-type ish interface that represents the current universe
// commitment verification state.
type State interface {
	stateSealed()
	IsTerminal() bool
	ProcessEvent(Event, *Environment) (*StateTransition, error)
	String() string
}

// StateMachine is a state machine that handles verifying the on-chain supply
// commitment for a given asset.
type StateMachine = protofsm.StateMachine[Event, *Environment]

// Config is a configuration struct that is used to initialize a new supply
// verifier state machine.
type Config = protofsm.StateMachineCfg[Event, *Environment]

// InitEvent is the first event that is sent to the state machine.
type InitEvent struct{}

// eventSealed is a special method that is used to seal the interface.
func (i *InitEvent) eventSealed() {}

// WatchLatestOutputsEvent is an event that prompts the state machine to watch
// for the spend of the latest unspent outputs.
type WatchLatestOutputsEvent struct{}

// eventSealed is a special method that is used to seal the interface.
func (w *WatchLatestOutputsEvent) eventSealed() {}

// WatchOutputsEvent is an event that carries the set of outputs to watch.
type WatchOutputsEvent struct {
	PreCommits   supplycommit.PreCommits
	SupplyCommit *supplycommit.RootCommitment
}

// eventSealed is a special method that is used to seal the interface.
func (e *WatchOutputsEvent) eventSealed() {}

// SpendEvent is sent in response to an intent to be notified of a spend of an
// outpoint.
type SpendEvent struct {
	// SpendDetail is the details of the spend that was observed on-chain.
	SpendDetail *chainntnfs.SpendDetail

	// PreCommitments is the set of all pre-commitments that were being
	// watched for a spend.
	PreCommitments []supplycommit.PreCommitment

	// SpentPreCommitment is the pre-commitment that was spent. This will
	// be non-nil only if the spent output was a pre-commitment.
	SpentPreCommitment *supplycommit.PreCommitment

	// SpentSupplyCommitment is the supply commitment that was spent. This
	// will be non-nil only if the spent output was a supply commitment.
	SpentSupplyCommitment *supplycommit.RootCommitment
}

// eventSealed is a special method that is used to seal the interface.
func (s *SpendEvent) eventSealed() {}

// ProofsSyncedEvent is sent once the proofs for a supply commitment have been
// synced.
type ProofsSyncedEvent struct {
	nextCommitment *supplycommit.RootCommitment
	spendEvent     *SpendEvent
}

// eventSealed is a special method that is used to seal the interface.
func (p *ProofsSyncedEvent) eventSealed() {}

// DefaultState is the initial state of the FSM. In this state we'll perform
// initial sanity checks.
type DefaultState struct {
}

// stateSealed is a special method that is used to seal the interface.
func (d *DefaultState) stateSealed() {}

// IsTerminal returns true if the target state is a terminal state.
func (d *DefaultState) IsTerminal() bool {
	return false
}

// String returns the name of the state.
func (d *DefaultState) String() string {
	return "DefaultState"
}

// WatchOutputsSpendState is a state where we wait for a spend of one of the
// outputs we're watching. The outputs may have already been spent, in which
// case we'll transition forward immediately.
type WatchOutputsSpendState struct{}

// stateSealed is a special method that is used to seal the interface.
func (w *WatchOutputsSpendState) stateSealed() {}

// IsTerminal returns true if the target state is a terminal state.
func (w *WatchOutputsSpendState) IsTerminal() bool {
	return false
}

// String returns the name of the state.
func (w *WatchOutputsSpendState) String() string {
	return "WatchOutputsSpendState"
}

// SyncSupplyProofsState is the state where we sync proofs related to a
// supply commitment transaction.
type SyncSupplyProofsState struct {
	// lastSpendTxID is the transaction ID of the last spend event we
	// processed. This is used to prevent processing the same spend event
	// multiple times when watching multiple inputs that are spent in the
	// same transaction.
	lastSpendTxID *chainhash.Hash
}

// stateSealed is a special method that is used to seal the interface.
func (s *SyncSupplyProofsState) stateSealed() {}

// IsTerminal returns true if the target state is a terminal state.
func (s *SyncSupplyProofsState) IsTerminal() bool {
	return false
}

// String returns the name of the state.
func (s *SyncSupplyProofsState) String() string {
	return "SyncSupplyProofsState"
}

// VerifySupplyCommitState is the state where we verify a supply commitment
// given a spend event and synced proofs.
type VerifySupplyCommitState struct{}

// stateSealed is a special method that is used to seal the interface.
func (v *VerifySupplyCommitState) stateSealed() {}

// IsTerminal returns true if the target state is a terminal state.
func (v *VerifySupplyCommitState) IsTerminal() bool {
	return false
}

// String returns the name of the state.
func (v *VerifySupplyCommitState) String() string {
	return "VerifySupplyCommitState"
}

// IdleState is the state we reach when a valid unspent commitment output is
// observed. We wait for a spend to re-enter the sync state.
type IdleState struct{}

// stateSealed is a special method that is used to seal the interface.
func (i *IdleState) stateSealed() {}

// IsTerminal returns true if the target state is a terminal state.
func (i *IdleState) IsTerminal() bool {
	return false
}

// String returns the name of the state.
func (i *IdleState) String() string {
	return "IdleState"
}

// FsmState is a type alias for the state of the supply verifier state machine.
type FsmState = protofsm.State[Event, *Environment]

// FsmEvent is a type alias for the event type of the supply verifier state
// machine.
type FsmEvent = protofsm.EmittedEvent[Event]

// StateSub is a type alias for the state subscriber of the supply verifier
// state machine.
type StateSub = protofsm.StateSubscriber[Event, *Environment]
