package supplyverifier

import (
	"fmt"

	"github.com/lightningnetwork/lnd/protofsm"
)

var (
	// ErrInvalidStateTransition is returned when we receive an unexpected
	// event for a given state.
	ErrInvalidStateTransition = fmt.Errorf("invalid state transition")
)

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

// InitState is the starting state of the machine. In this state we decide
// whether to start syncing immediately or wait for spends before syncing.
type InitState struct {
}

// stateSealed is a special method that is used to seal the interface.
func (s *InitState) stateSealed() {}

// IsTerminal returns true if the target state is a terminal state.
func (s *InitState) IsTerminal() bool {
	return false
}

// String returns the name of the state.
func (s *InitState) String() string {
	return "InitState"
}

// SyncVerifyState is the state where we sync proofs related to a
// supply commitment transaction.
type SyncVerifyState struct{}

// stateSealed is a special method that is used to seal the interface.
func (s *SyncVerifyState) stateSealed() {}

// IsTerminal returns true if the target state is a terminal state.
func (s *SyncVerifyState) IsTerminal() bool {
	return false
}

// String returns the name of the state.
func (s *SyncVerifyState) String() string {
	return "SyncVerifyState"
}

// WatchOutputsState waits for one of the watched outputs to be spent.
// If an output is already spent, we transition immediately.
// This state avoids wasted sync polling of universe servers.
type WatchOutputsState struct{}

// stateSealed is a special method that is used to seal the interface.
func (s *WatchOutputsState) stateSealed() {}

// IsTerminal returns true if the target state is a terminal state.
func (s *WatchOutputsState) IsTerminal() bool {
	return false
}

// String returns the name of the state.
func (s *WatchOutputsState) String() string {
	return "WatchOutputsState"
}

// StateMachine is a state machine that handles verifying the on-chain supply
// commitment for a given asset.
type StateMachine = protofsm.StateMachine[Event, *Environment]

// Config is a configuration struct that is used to initialize a new supply
// verifier state machine.
type Config = protofsm.StateMachineCfg[Event, *Environment]

// FsmState is a type alias for the state of the supply verifier state machine.
type FsmState = protofsm.State[Event, *Environment]

// StateSub is a type alias for the state subscriber of the supply verifier
// state machine.
type StateSub = protofsm.StateSubscriber[Event, *Environment]
