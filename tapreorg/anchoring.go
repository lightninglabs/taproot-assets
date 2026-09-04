package tapreorg

import (
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightningnetwork/lnd/chainntnfs"
)

var (
	// ErrEmptyTriggerSet is returned when a trigger set is
	// constructed with no outpoints.
	ErrEmptyTriggerSet = errors.New("trigger set must not be empty")

	// ErrDuplicateTrigger is returned when a trigger set is
	// constructed with a repeated outpoint.
	ErrDuplicateTrigger = errors.New("duplicate trigger outpoint")

	// ErrIncompleteWitness is returned when a witness is
	// constructed from incomplete location data.
	ErrIncompleteWitness = errors.New("witness requires a " +
		"transaction and a complete chain location")
)

// SiteID identifies a subsystem that stakes local state on chain
// outcomes and registers anchorings with the watcher. Site IDs are
// stable strings; they are persisted with each anchoring and used to
// route signals back to the owning site's handlers after a restart.
type SiteID string

// AnchoringID is the registry-assigned identifier of an anchoring. It
// is a distinct type so that it cannot be confused with other integral
// identifiers.
type AnchoringID int64

// Verdict is a site's judgment of a candidate spending transaction:
// either the candidate realizes the site's anchoring (possibly in a
// different form than originally broadcast), or it is a foreign
// transaction that forecloses it.
type Verdict uint8

const (
	// VerdictSatisfies indicates the candidate realizes the
	// anchoring.
	VerdictSatisfies Verdict = 0

	// VerdictForeign indicates the candidate forecloses the
	// anchoring.
	VerdictForeign Verdict = 1
)

// NewVerdict converts a raw integer (e.g. from a database row) into a
// Verdict, rejecting unknown values.
func NewVerdict(v uint8) (Verdict, error) {
	switch Verdict(v) {
	case VerdictSatisfies:
		return VerdictSatisfies, nil

	case VerdictForeign:
		return VerdictForeign, nil

	default:
		return 0, fmt.Errorf("unknown verdict %d", v)
	}
}

// String returns a human-readable verdict.
func (v Verdict) String() string {
	switch v {
	case VerdictSatisfies:
		return "satisfies"

	case VerdictForeign:
		return "foreign"

	default:
		return fmt.Sprintf("unknown<%d>", uint8(v))
	}
}

// TriggerOutPoint is one outpoint of an anchoring's trigger set,
// together with the script and height hint needed to open a spend
// subscription on it.
type TriggerOutPoint struct {
	// OutPoint is the outpoint whose spending constitutes (or
	// forecloses) the anchoring event.
	OutPoint wire.OutPoint

	// PkScript is the output script of the outpoint.
	PkScript []byte

	// HeightHint is the earliest height at which the outpoint
	// could have been spent.
	HeightHint uint32
}

// TriggerSet is the non-empty, duplicate-free set of outpoints whose
// spending the watcher observes for an anchoring. Identity of the
// anchoring lives here: any admissible witness must spend the entire
// set (the whole-set rule), so a satisfying spend and a foreign spend
// can never coexist on a single chain. The watcher enforces the rule
// structurally — a transaction spending only part of the set is
// foreign by construction and never reaches the site's predicate —
// so a set must be consumed atomically or not at all; outpoints that
// can legitimately be realized in separate transactions belong to
// separate anchorings.
//
// Beware batching spenders the site does not control: lnd's sweeper
// may split a batch's inputs across separate transactions, realizing
// outpoints independently even when they were offered together — a
// multi-outpoint anchoring then reads as conflicted and abandoned
// though every outpoint was swept as intended. Sites should default
// to one outpoint per anchoring unless they control the spending
// transaction.
//
// The zero value is invalid; values in circulation originate from
// NewTriggerSet and are therefore well-formed by provenance.
type TriggerSet struct {
	outpoints []TriggerOutPoint
}

// NewTriggerSet builds a trigger set, rejecting empty sets and
// duplicate outpoints.
func NewTriggerSet(points []TriggerOutPoint) (TriggerSet, error) {
	if len(points) == 0 {
		return TriggerSet{}, ErrEmptyTriggerSet
	}

	seen := make(map[wire.OutPoint]struct{}, len(points))
	copied := make([]TriggerOutPoint, len(points))
	for i, p := range points {
		if _, ok := seen[p.OutPoint]; ok {
			return TriggerSet{}, fmt.Errorf("%w: %v",
				ErrDuplicateTrigger, p.OutPoint)
		}
		seen[p.OutPoint] = struct{}{}

		copied[i] = TriggerOutPoint{
			OutPoint:   p.OutPoint,
			PkScript:   append([]byte(nil), p.PkScript...),
			HeightHint: p.HeightHint,
		}
	}

	return TriggerSet{outpoints: copied}, nil
}

// OutPoints returns a copy of the trigger outpoints.
func (t TriggerSet) OutPoints() []TriggerOutPoint {
	out := make([]TriggerOutPoint, len(t.outpoints))
	for i, p := range t.outpoints {
		out[i] = TriggerOutPoint{
			OutPoint:   p.OutPoint,
			PkScript:   append([]byte(nil), p.PkScript...),
			HeightHint: p.HeightHint,
		}
	}

	return out
}

// SpentBy returns the trigger outpoints the given transaction
// spends. The whole-set rule turns on its length: only a transaction
// spending every trigger outpoint can realize the anchoring, while
// one spending any strict subset forecloses it — whatever else the
// transaction spends alongside.
func (t TriggerSet) SpentBy(tx *wire.MsgTx) []wire.OutPoint {
	var spent []wire.OutPoint
	for _, p := range t.outpoints {
		for _, txIn := range tx.TxIn {
			if txIn.PreviousOutPoint == p.OutPoint {
				spent = append(spent, p.OutPoint)
				break
			}
		}
	}

	return spent
}

// Contains reports whether the given outpoint is part of the trigger
// set.
func (t TriggerSet) Contains(op wire.OutPoint) bool {
	for _, p := range t.outpoints {
		if p.OutPoint == op {
			return true
		}
	}

	return false
}

// Len returns the number of trigger outpoints.
func (t TriggerSet) Len() int {
	return len(t.outpoints)
}

// Witness is a transaction located on the chain: the transaction
// itself plus the block hash, height and transaction index of its
// inclusion. A witness for an anchoring is a satisfying spend of its
// trigger set; the same type also locates foreign spends.
//
// The zero value is invalid; values in circulation originate from
// NewWitness (or the phase decoder, which routes through it) and are
// therefore fully located by provenance: a partially-located witness
// is unrepresentable.
type Witness struct {
	txHash    chainhash.Hash
	blockHash chainhash.Hash
	height    uint32
	txIndex   uint32
	tx        *wire.MsgTx
}

// NewWitness builds a witness from a transaction and its complete
// chain location. The transaction is deep-copied.
func NewWitness(tx *wire.MsgTx, blockHash chainhash.Hash, height uint32,
	txIndex uint32) (Witness, error) {

	if tx == nil || height == 0 {
		return Witness{}, ErrIncompleteWitness
	}

	txCopy := tx.Copy()

	return Witness{
		txHash:    txCopy.TxHash(),
		blockHash: blockHash,
		height:    height,
		txIndex:   txIndex,
		tx:        txCopy,
	}, nil
}

// TxHash returns the hash of the located transaction.
func (w Witness) TxHash() chainhash.Hash {
	return w.txHash
}

// BlockHash returns the hash of the block containing the transaction.
func (w Witness) BlockHash() chainhash.Hash {
	return w.blockHash
}

// Height returns the height of the block containing the transaction.
func (w Witness) Height() uint32 {
	return w.height
}

// TxIndex returns the index of the transaction within its block.
func (w Witness) TxIndex() uint32 {
	return w.txIndex
}

// Tx returns a deep copy of the located transaction.
func (w Witness) Tx() *wire.MsgTx {
	return w.tx.Copy()
}

// ForeignSpend is an observed foreign spend of a trigger outpoint: the
// spent outpoint plus the located spending transaction.
type ForeignSpend struct {
	// SpentOutPoint is the trigger outpoint the foreign
	// transaction spends.
	SpentOutPoint wire.OutPoint

	// W locates the foreign spending transaction on chain.
	W Witness
}

// VersionedBlob is the envelope in which all site-owned opaque data
// (match data, site payloads, effect payloads) travels and persists.
// The version tags the site's encoding so that a site can decode
// every version it has ever written.
type VersionedBlob struct {
	// Version is the site-owned encoding version of Data.
	Version uint16

	// Data is the opaque payload. The watcher never interprets it.
	Data []byte
}

// RegistrationSpec is the data a site supplies to register an
// anchoring. It contains only data — the no-closures rule is
// structural.
type RegistrationSpec struct {
	// Site is the registering site.
	Site SiteID

	// Triggers is the trigger set; see TriggerSet for the identity
	// semantics it carries.
	Triggers TriggerSet

	// MatchData is handed back to the site's predicate when a
	// candidate spend appears.
	MatchData VersionedBlob

	// Payload carries whatever the site needs to patch, finalize
	// or reverse its speculation. It must identify everything the
	// site keyed to the anchoring.
	Payload VersionedBlob

	// Threshold is the confirmation depth at which this site
	// considers an outcome final (act-confirmed). It must lie
	// within the chain notifier's supported range, 1 to
	// chainntnfs.MaxNumConfs. Zero defers to the watcher's
	// configured default, which carries the daemon's re-org
	// safety policy (--reorgsafedepth). A threshold of one makes
	// the very first confirmation act-final and absorbing — sound
	// only for sites that genuinely want single-confirmation
	// finality.
	Threshold uint32
}

// Validate checks the spec's value-level invariants.
func (s *RegistrationSpec) Validate() error {
	if s.Site == "" {
		return errors.New("registration requires a site ID")
	}
	if s.Triggers.Len() == 0 {
		return ErrEmptyTriggerSet
	}
	if s.Threshold == 0 {
		return errors.New("registration requires a threshold " +
			"of at least one confirmation")
	}

	// The notifier rejects deeper subscriptions outright; an
	// anchoring past this bound could never certify, so it is
	// refused at the door rather than left to loop in the sweep.
	if s.Threshold > chainntnfs.MaxNumConfs {
		return fmt.Errorf("threshold %d exceeds the chain "+
			"notifier's maximum of %d confirmations",
			s.Threshold, uint32(chainntnfs.MaxNumConfs))
	}

	// The notifier parses every registered script and refuses
	// nonstandard classes. A trigger it cannot watch would pass
	// registration and then fail sensor adoption on every sweep,
	// leaving the anchoring live but blind; refuse it at the call
	// site instead, where the defect is attributable.
	for _, trigger := range s.Triggers.OutPoints() {
		_, err := txscript.ParsePkScript(trigger.PkScript)
		if err != nil {
			return fmt.Errorf("trigger %v: unwatchable "+
				"pkScript %x: %w", trigger.OutPoint,
				trigger.PkScript, err)
		}
	}

	return nil
}

// Anchoring is one act of staking local state on a future chain
// outcome, made first-class and durable. It is the unit of
// registration, sensing and delivery.
type Anchoring struct {
	// ID is the registry-assigned identifier.
	ID AnchoringID

	// Site is the owning site.
	Site SiteID

	// Triggers is the trigger set.
	Triggers TriggerSet

	// MatchData is the site's opaque predicate input.
	MatchData VersionedBlob

	// Payload is the site's opaque repair/finalize data.
	Payload VersionedBlob

	// Threshold is the act-confirmation depth for this anchoring.
	Threshold uint32

	// CreatedHeight is the best height at registration time.
	CreatedHeight uint32

	// Phase is the sensed phase: the registry's derived truth.
	Phase Phase

	// DeliveredPhase is the last phase the owning site has durably
	// acknowledged. The site is converged when it equals Phase.
	DeliveredPhase Phase

	// Stuck indicates delivery has failed repeatedly; retries
	// continue at low frequency, and the condition is surfaced.
	Stuck bool

	// DeliveryAttempts counts failed delivery attempts since the
	// last successful delivery.
	DeliveryAttempts uint32

	// Spends is the chain view: every candidate spend observed for
	// this anchoring, on-chain or not.
	Spends []CandidateSpend
}
