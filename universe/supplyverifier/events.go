package supplyverifier

import (
	"time"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/universe/supplycommit"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/protofsm"
)

// Event is a special interface used to create the equivalent of a sum-type, but
// using a "sealed" interface.
type Event interface {
	eventSealed()
}

// FsmEvent is a type alias for the event type of the supply verifier state
// machine.
type FsmEvent = protofsm.EmittedEvent[Event]

// InitEvent is the first event that is sent to the state machine.
type InitEvent struct{}

// eventSealed is a special method that is used to seal the interface.
func (i *InitEvent) eventSealed() {}

// SyncVerifyEvent is sent to SyncVerifyState to prompt it to sync-verify
// starting from the given outpoint, or from scratch if no outpoint is given.
type SyncVerifyEvent struct {
	// SpentCommitOutpoint is an optional outpoint that was spent which
	// triggered the need to start syncing from the beginning. If this is
	// None, then we will sync from the first supply commitment.
	SpentCommitOutpoint fn.Option[wire.OutPoint]
}

// eventSealed is a special method that is used to seal the interface.
func (e *SyncVerifyEvent) eventSealed() {}

// WatchOutputsEvent is an event that carries the set of outputs to watch.
type WatchOutputsEvent struct {
	// PreCommits is the set of all pre-commitments that should be watched
	// for a spend.
	PreCommits supplycommit.PreCommits

	// SupplyCommit is the latest known supply commitment that should be
	// watched for a spend.
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

	// WatchStartTimestamp records when monitoring for this spend began.
	// It is used to calculate the delay before syncing, giving the issuer
	// time to publish the new supply commitment.
	WatchStartTimestamp time.Time
}

// eventSealed is a special method that is used to seal the interface.
func (s *SpendEvent) eventSealed() {}
