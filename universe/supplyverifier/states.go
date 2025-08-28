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

// FsmState is a type alias for the state of the supply verifier state machine.
type FsmState = protofsm.State[Event, *Environment]

// FsmEvent is a type alias for the event type of the supply verifier state
// machine.
type FsmEvent = protofsm.EmittedEvent[Event]

// StateSub is a type alias for the state subscriber of the supply verifier
// state machine.
type StateSub = protofsm.StateSubscriber[Event, *Environment]

// InitEvent is the first event that is sent to the state machine.
type InitEvent struct{}

// eventSealed is a special method that is used to seal the interface.
func (i *InitEvent) eventSealed() {}
