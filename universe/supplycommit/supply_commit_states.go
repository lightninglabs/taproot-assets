package supplycommit

import (
	"bytes"
	"fmt"
	"io"

	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/protofsm"
)

var (
	// ErrInvalidStateTransition is returned when we receive an unexpected
	// event for a given state.
	ErrInvalidStateTransition = fmt.Errorf("invalid state transition")

	ErrInvalidState = fmt.Errorf("invalid state")
)

// Event is a special interface used to create the equivalent of a sum-type, but
// using a "sealed" interface. Supply commit events can be used as input to
// trigger a state transition, and also as output to trigger a new set of events
// into the very same state machine.
type Event interface {
	eventSealed()
}

// Events is a special type constraint that enumerates all the possible protocol
// events. This is used mainly as type-level documentation, and may also be
// useful to constraint certain state transition functions.
type Events interface {
}

// StateTransition is the StateTransition type specific to the supply commit
// state machine.
type StateTransition = protofsm.StateTransition[Event, *Environment]

// State is our sum-type ish interface that represents the current universe
// commitment state.
type State interface {
	// stateSealed is a special method that is used to seal the interface
	// (only types in this package can implement it).
	stateSealed()

	// IsTerminal returns true if the target state is a terminal state.
	IsTerminal() bool

	// ProcessEvent takes a supply event event, and implements a state
	// transition for the state.
	//
	// nolint:lll
	ProcessEvent(Event, *Environment) (*StateTransition, error)

	// String returns the name of the state.
	String() string
}

// StateMachine is a state machine that handles creating and updating the
// on-chain universe supply commitment for a given asset.
//
// nolint:lll
type StateMachine = protofsm.StateMachine[Event, *Environment]

// Config is a configuration struct that is used to initialize a new supply
// commit state machine.
type Config = protofsm.StateMachineCfg[Event, *Environment]

// SupplyUpdateEvent is a special interface used to create the equivalent of a
// sum-type, but using a "sealed" interface. This is a super set of the normal
// event, to identify events that are used to update the supply tree.
type SupplyUpdateEvent interface {
	Event

	// ScriptKey returns the script key that is used to identify the target
	// asset.
	ScriptKey() asset.SerializedKey

	// SupplySubTreeType returns the type of sub-tree this update affects.
	SupplySubTreeType() SupplySubTree

	// UniverseLeafKey returns the specific leaf key to use when inserting
	// this update into a universe MS-SMT tree.
	UniverseLeafKey() universe.LeafKey

	// UniverseLeafNode returns the leaf node to use when inserting this
	// update into a universe MS-SMT tree.
	UniverseLeafNode() (*mssmt.LeafNode, error)
}

// NewIgnoreEvent signals that a caller wishes to update the ignore portion of
// the supply tree with a new outpoint + script key combo.
type NewIgnoreEvent struct {
	universe.SignedIgnoreTuple
}

// eventSealed is a special method that is used to seal the interface.
func (n *NewIgnoreEvent) eventSealed() {}

// ScriptKey returns the script key that is used to identify the target asset.
func (n *NewIgnoreEvent) ScriptKey() asset.SerializedKey {
	return n.IgnoreTuple.Val.ScriptKey
}

// SupplySubTreeType returns the type of sub-tree this update affects.
func (n *NewIgnoreEvent) SupplySubTreeType() SupplySubTree {
	return IgnoreTreeType
}

// UniverseLeafKey returns the specific leaf key to use when inserting this
// update into a universe MS-SMT tree.
func (n *NewIgnoreEvent) UniverseLeafKey() universe.LeafKey {
	return &n.SignedIgnoreTuple
}

// UniverseLeafNode returns the leaf node to use when inserting this update
// into a universe MS-SMT tree.
func (n *NewIgnoreEvent) UniverseLeafNode() (*mssmt.LeafNode, error) {
	return n.SignedIgnoreTuple.UniverseLeafNode()
}

// A compile time assertion to ensure that NewIgnoreEvent implements the
// SupplyUpdateEvent interface.
var _ SupplyUpdateEvent = (*NewIgnoreEvent)(nil)

// NewBurnEvent signals that a caller wishes to update the burn portion of
// the supply tree with a new burnt asset.
type NewBurnEvent struct {
	universe.BurnLeaf
}

// eventSealed is a special method that is used to seal the interface.
func (n *NewBurnEvent) eventSealed() {}

// ScriptKey returns the script key that is used to identify the target asset.
func (n *NewBurnEvent) ScriptKey() asset.SerializedKey {
	leafKey := n.BurnLeaf.UniverseKey.LeafScriptKey()
	return asset.ToSerialized(leafKey.PubKey)
}

// SupplySubTreeType returns the type of sub-tree this update affects.
func (n *NewBurnEvent) SupplySubTreeType() SupplySubTree {
	return BurnTreeType
}

// UniverseLeafKey returns the specific leaf key to use when inserting this
// update into a universe MS-SMT tree.
func (n *NewBurnEvent) UniverseLeafKey() universe.LeafKey {
	return n.BurnLeaf.UniverseKey
}

// UniverseLeafNode returns the leaf node to use when inserting this update
// into a universe MS-SMT tree.
func (n *NewBurnEvent) UniverseLeafNode() (*mssmt.LeafNode, error) {
	return n.BurnLeaf.UniverseLeafNode()
}

// A compile time assertion to ensure that NewBurnEvent implements the
// SupplyUpdateEvent interface.
var _ SupplyUpdateEvent = (*NewBurnEvent)(nil)

// NewMintEvent signals that a caller wishes to update the mint portion of the
// supply tree with a new minted asset.
type NewMintEvent struct {
	// LeafKey is the universe leaf key for the asset issuance or spend.
	LeafKey universe.UniqueLeafKey

	IssuanceProof universe.Leaf
}

// eventSealed is a special method that is used to seal the interface.
func (n *NewMintEvent) eventSealed() {}

// ScriptKey returns the script key that is used to identify the target
// asset.
func (n *NewMintEvent) ScriptKey() asset.SerializedKey {
	leafKey := n.IssuanceProof.Asset.ScriptKey
	return asset.ToSerialized(leafKey.PubKey)
}

// SupplySubTreeType returns the type of sub-tree this update affects.
func (n *NewMintEvent) SupplySubTreeType() SupplySubTree {
	return MintTreeType
}

// UniverseLeafKey returns the specific leaf key to use when inserting this
// update into a universe MS-SMT tree.
func (n *NewMintEvent) UniverseLeafKey() universe.LeafKey {
	return n.LeafKey
}

// UniverseLeafNode returns the leaf node to use when inserting this update
// into a universe MS-SMT tree.
func (n *NewMintEvent) UniverseLeafNode() (*mssmt.LeafNode, error) {
	return n.IssuanceProof.SmtLeafNode(), nil
}

// Encode encodes the mint event into the passed io.Writer.
func (n *NewMintEvent) Encode(w io.Writer) error {
	// TODO(roasbeef): TLV here?
	_, err := w.Write(n.IssuanceProof.RawProof)
	return err
}

// Decode decodes the mint event from the passed io.Reader.
func (n *NewMintEvent) Decode(r io.Reader) error {
	var b bytes.Buffer
	if _, err := io.Copy(&b, r); err != nil {
		return fmt.Errorf("decode mint event: %w", err)
	}

	n.IssuanceProof = universe.Leaf{
		RawProof: b.Bytes(),
	}

	var issuanceProof proof.Proof
	if err := issuanceProof.Decode(&b); err != nil {
		return fmt.Errorf("decode mint event: %w", err)
	}

	n.IssuanceProof.GenesisWithGroup = universe.GenesisWithGroup{
		Genesis:  issuanceProof.Asset.Genesis,
		GroupKey: issuanceProof.Asset.GroupKey,
	}
	n.IssuanceProof.Asset = &issuanceProof.Asset
	n.IssuanceProof.Amt = issuanceProof.Asset.Amount
	n.IssuanceProof.IsBurn = false

	n.LeafKey = universe.AssetLeafKey{
		BaseLeafKey: universe.BaseLeafKey{
			OutPoint:  issuanceProof.OutPoint(),
			ScriptKey: &issuanceProof.Asset.ScriptKey,
		},
		AssetID: issuanceProof.Asset.ID(),
	}

	return nil
}

// A compile time assertion to ensure that NewMintEvent implements the
// SupplyUpdateEvent interface.
var _ SupplyUpdateEvent = (*NewMintEvent)(nil)

// DefaultState is the idle state of the state machine. We start in this state
// when there are no pending changes that need to committed.
//
// Once we receive a new supply commit event, we'll transition to the
// UpdatePendingState.
//
//   - SupplyUpdateEvent -> UpdatePendingState
//
// State transitions:
//
// TODO(roasbeef): transition if have items in log that are pending?
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

// CommitTickEvent is a special event that is used to trigger an update of the
// on-chain commitment.
type CommitTickEvent struct {
}

// eventSealed is a special method that is used to seal the interface.
func (c *CommitTickEvent) eventSealed() {}

// UpdatePendingState is the state of the state machine when we have From this
// state, we can queue/accept new supply commit events. Periodically, we'll rely
// on a new incoming Commit event, that'll be used as a trigger to progress the
// state machine to the next state.
//
// Upon restart, we'll start in this state if we already have pending items in
// the update/staging log.
//
// State transitions:
//   - SupplyUpdateEvent -> UpdatePendingState
//   - CommitTickEvent -> CommmitTreeCreate
type UpdatesPendingState struct {
	pendingUpdates []SupplyUpdateEvent
}

// stateSealed is a special method that is used to seal the interface.
func (u *UpdatesPendingState) stateSealed() {}

// IsTerminal returns true if the target state is a terminal state.
func (u *UpdatesPendingState) IsTerminal() bool {
	return false
}

// String returns the name of the state.
func (u *UpdatesPendingState) String() string {
	return "UpdatesPendingState"
}

// CreateTreeEvent is a special event that is used to trigger the creation of
// the supply tree.
type CreateTreeEvent struct {
	updatesToCommit []SupplyUpdateEvent
}

// eventSealed is a special method that is used to seal the interface.
func (c *CreateTreeEvent) eventSealed() {}

// CommitTreeCreateState is the state of the state machine when we have a series
// of new updates to commit to the tree. In this state, we'll create a new
// version of the supply tree in memory, to stage before going to the next state
// where we'll create the txn that will be used to commit the new tree in the
// chain.
//
// State transitions:
//   - CreateTreeEvent -> CommitTxCreateState
//
// TODO(roasbeef): have all states cache pending updates once started with tick?
type CommitTreeCreateState struct {
}

// stateSealed is a special method that is used to seal the interface.
func (c *CommitTreeCreateState) stateSealed() {}

// IsTerminal returns true if the target state is a terminal state.
func (c *CommitTreeCreateState) IsTerminal() bool {
	return false
}

// String returns the name of the state.
func (c *CommitTreeCreateState) String() string {
	return "CommitTreeCreateState"
}

// CreateTxEvent is a special event that is used to trigger the creation of the
// commitment transaction.
type CreateTxEvent struct {
}

// eventSealed is a special method that is used to seal the interface.
func (c *CreateTxEvent) eventSealed() {}

// CommitTxCreateState is the state of the state machine we'll transition to
// once we've created a new supply tree in memory. In this state, we'll create
// the actual transaction which spends the existing pre-commitment output(s) and
// the current commitment output.
//
// State transitions:
//   - CommitTxCreateState -> CommitTxSignState
type CommitTxCreateState struct {
	// SupplyTransition holds all the information about the current state
	// transition, including old/new trees and commitments.
	SupplyTransition SupplyStateTransition
}

// TODO(roasbeef): attrs of event vs the state itself?

// stateSealed is a special method that is used to seal the interface.
func (c *CommitTxCreateState) stateSealed() {}

// IsTerminal returns true if the target state is a terminal state.
func (c *CommitTxCreateState) IsTerminal() bool {
	return false
}

// String returns the name of the state.
func (c *CommitTxCreateState) String() string {
	return "CommitTxCreateState"
}

// SignTxEvent is a special event that is used to trigger the signing of the
// commitment transaction.
type SignTxEvent struct {
	// CommitPkt is the unsigned transaction that will be used to commit to
	// the new supply tree.
	CommitPkt *tapsend.FundedPsbt

	// NewSupplyCommit is the new supply commitment that that will be
	// created by the above commit pkt.
	NewSupplyCommit RootCommitment
}

// eventSealed is a special method that is used to seal the interface.
func (s *SignTxEvent) eventSealed() {}

// CommitTxSignState is the state of the state machine we'll transition to once
// we've created the tx that commits to the latest supply tree. In this state,
// we'll sign the transaction and all its inputs, then write our state to disk
// so we'll be able to recover it on restart.
//
// State transitions:
//   - SignTxEvent -> CommitBroadcastState
type CommitTxSignState struct {
	// SupplyTransition holds all the information about the current state
	// transition, including old/new trees and commitments.
	SupplyTransition SupplyStateTransition
}

// stateSealed is a special method that is used to seal the interface.
func (s *CommitTxSignState) stateSealed() {}

// IsTerminal returns true if the target state is a terminal state.
func (s *CommitTxSignState) IsTerminal() bool {
	return false
}

// String returns the name of the state.
func (s *CommitTxSignState) String() string {
	return "CommitTxSignState"
}

// BroadcastEvent is a special event that is used to trigger the broadcasting of
// the commitment transaction.
type BroadcastEvent struct {
	// SignedCommitPkt is the signed commitment transaction that will be
	// broadcast to the network.
	SignedCommitPkt *psbt.Packet
}

// eventSealed is a special method that is used to seal the interface.
func (b *BroadcastEvent) eventSealed() {}

// ConfEvent is a special event sent once our latest commitment transaction
// confirms on chain.
type ConfEvent struct {
	// BlockHeight is the height of the block in which the transaction was
	// confirmed within.
	BlockHeight uint32

	// TxIndex is the index within the block of the ultimate confirmed
	// transaction.
	TxIndex uint32

	// Tx is the transaction for which the notification was requested for.
	Tx *wire.MsgTx

	// Block is the block that contains the transaction referenced above.
	Block *wire.MsgBlock
}

// eventSealed is a special method that is used to seal the interface.
func (c *ConfEvent) eventSealed() {}

// CommitBroadcastState is the state of the state machine we'll transitions
// to once we've signed the transaction. In this state, we'll broadcast the
// transaction, then wait for a confirmation event.
//
// State transitions:
//   - BroadcastEvent -> CommitBroadcastState
//   - ConfEvent -> DefaultState
type CommitBroadcastState struct {
	// SupplyTransition holds all the information about the current state
	// transition, including old/new trees and commitments.
	SupplyTransition SupplyStateTransition
}

// stateSealed is a special method that is used to seal the interface.
func (c *CommitBroadcastState) stateSealed() {}

// IsTerminal returns true if the target state is a terminal state.
func (c *CommitBroadcastState) IsTerminal() bool {
	return false
}

// String returns the name of the state.
func (c *CommitBroadcastState) String() string {
	return "CommitBroadcastState"
}

// FinalizeEvent is a special event that is used to trigger the finalization of
// the state update.
type FinalizeEvent struct {
}

// eventSealed is a special method that is used to seal the interface.
func (f *FinalizeEvent) eventSealed() {}

// CommitFinalizeState is the final state of the state machine. In this state
// we'll update the state info on disk, swap in our in-memory tree with the new
// we've had in memory, then transition back to the DefaultState.
//
// State transitions:
//   - ConfEvent -> DefaultState
type CommitFinalizeState struct {
	// SupplyTransition holds all the information about the current state
	// transition, including old/new trees and commitments.
	SupplyTransition SupplyStateTransition
}

// stateSealed is a special method that is used to seal the interface.
func (c *CommitFinalizeState) stateSealed() {}

// IsTerminal returns true if the target state is a terminal state.
func (c *CommitFinalizeState) IsTerminal() bool {
	return true
}

// String returns the name of the state.
func (c *CommitFinalizeState) String() string {
	return "CommitFinalizeState"
}

// SpendEvent....
type SpendEvent struct {
	// Tx is the spending transaction that has been confirmed.
	Tx *wire.MsgTx

	// BlockHeight is the height of the block that confirmed the
	// transaction.
	BlockHeight uint32
}

// eventSealed is a special method that is used to seal the interface.
func (s *SpendEvent) eventSealed() {}

// SpendMapper is a type used to map the generic spend event to one specific to
// this package.
type SpendMapper = protofsm.SpendMapper[Event]

// ConfMapper is a type used to map the generic confirmation event to one
// specific to this package.
type ConfMapper = protofsm.ConfMapper[ConfEvent]

func SpendMapperFunc(spendEvent *chainntnfs.SpendDetail) Event {
	return &SpendEvent{
		Tx:          spendEvent.SpendingTx,
		BlockHeight: uint32(spendEvent.SpendingHeight),
	}
}

// FsmState is a type alias for the state of the supply commit state machine.
type FsmState = protofsm.State[Event, *Environment]

// FsmEvent is a type alias for the event type of the supply commit state
// machine.
type FsmEvent = protofsm.EmittedEvent[Event]

// StateSub is a type alias for the state subscriber of the supply commit state
// machine.
type StateSub = protofsm.StateSubscriber[Event, *Environment]
