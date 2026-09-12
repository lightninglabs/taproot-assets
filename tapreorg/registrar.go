package tapreorg

import (
	"bytes"
	"context"
	"fmt"
	"sync"

	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/proof"
)

// Registrar is the watcher surface a subsystem uses to stake local
// state on chain outcomes and to observe the phases the watcher has
// delivered: registration, identity lookup across every phase, and
// per-anchoring reads. Implemented by *Watcher; subsystem tests use
// MockRegistrar.
type Registrar interface {
	// Register stakes a new anchoring, running the optional phase-1
	// write in the registration transaction. Registration is
	// idempotent per (site, match key): a registration that finds
	// its identity already registered attaches to the existing
	// anchoring — its ID is returned, the phase-1 write runs only
	// when the spec's Phase1OnAttach marks the stake as this
	// registration's own, trigger outpoints the existing set lacks
	// are unioned in,
	// and the delivered phase is re-delivered to the site in the
	// same transaction, so the caller's freshly materialized state
	// lands on what earlier stakes already reflect.
	Register(ctx context.Context, spec RegistrationSpec,
		phase1 func(context.Context, RegistryTx,
			AnchoringID) error) (AnchoringID, error)

	// AllAnchorings reads one site's anchorings across every phase,
	// settled ones included.
	AllAnchorings(ctx context.Context,
		site SiteID) ([]*Anchoring, error)

	// LookupByMatchKey returns the site's existing anchoring for
	// this identity key, or (nil, nil) if none. Sites use this at
	// registration time to deduplicate by essential identity in
	// O(1), rather than scanning AllAnchorings and decoding each
	// payload.
	LookupByMatchKey(ctx context.Context, site SiteID,
		matchKey []byte) (*Anchoring, error)

	// Anchoring reads a single anchoring by identifier.
	Anchoring(ctx context.Context, id AnchoringID) (*Anchoring, error)

	// KickOutbox wakes the outbox dispatcher ahead of its scan. A
	// subsystem calls it once it has materialized the inputs of an
	// effect whose handler reported ErrEffectNotReady, so the effect
	// dispatches promptly instead of at the next scan. Latency path
	// only: the scan repairs a lost kick.
	KickOutbox()
}

// A compile-time assertion that the watcher provides the registrar
// surface.
var _ Registrar = (*Watcher)(nil)

// MockRegistrar is an in-memory Registrar for subsystem unit tests: it
// records registrations and lets a test flip an anchoring's delivered
// phase — with a properly located, block-enriched witness — the way
// the real watcher would after sensing and delivery. Phase-1 writes
// are not run unless RunPhase1 hands the mock a transaction handle:
// they are transaction-scoped database work that unit tests exercise
// separately, or through a fake handle when the test's phase-1 write
// targets a fake store.
type MockRegistrar struct {
	mu         sync.Mutex
	nextID     AnchoringID
	failNext   error
	anchorings map[AnchoringID]*Anchoring
	phase1Tx   RegistryTx
}

// MockRegistryTx is a RegistryTx for phase-1 writes against fake
// stores: it has no database transaction and records the effects
// enqueued on it.
type MockRegistryTx struct {
	Effects []OutboxEffect
}

// Queries returns nil: a fake store's phase-1 write must not need
// the generated queries.
func (m *MockRegistryTx) Queries() *sqlc.Queries { return nil }

// EnqueueEffect records the effect.
func (m *MockRegistryTx) EnqueueEffect(_ context.Context,
	effect OutboxEffect) error {

	m.Effects = append(m.Effects, effect)

	return nil
}

// A compile-time assertion that the mock handle is a RegistryTx.
var _ RegistryTx = (*MockRegistryTx)(nil)

// NewMockRegistrar returns an empty mock registrar.
func NewMockRegistrar() *MockRegistrar {
	return &MockRegistrar{
		anchorings: make(map[AnchoringID]*Anchoring),
	}
}

// Register records the registration and returns a fresh identifier.
func (m *MockRegistrar) Register(ctx context.Context, spec RegistrationSpec,
	phase1 func(context.Context, RegistryTx,
		AnchoringID) error) (AnchoringID, error) {

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.failNext != nil {
		err := m.failNext
		m.failNext = nil

		return 0, err
	}

	runPhase1 := func(id AnchoringID) error {
		if phase1 == nil || m.phase1Tx == nil {
			return nil
		}

		return phase1(ctx, m.phase1Tx, id)
	}

	// Mirror the production registrar's identity idempotency: a
	// match-key collision returns the existing anchoring rather
	// than registering a second one, running the phase-1 write only
	// when the spec marks the stake as this registration's own.
	if len(spec.MatchKey) > 0 {
		for _, existing := range m.anchorings {
			if existing.Site == spec.Site &&
				bytes.Equal(existing.MatchKey, spec.MatchKey) {

				if spec.Phase1OnAttach {
					err := runPhase1(existing.ID)
					if err != nil {
						return 0, err
					}
				}

				return existing.ID, nil
			}
		}
	}

	m.nextID++
	id := m.nextID
	anchoring := &Anchoring{
		ID:             id,
		Site:           spec.Site,
		Triggers:       spec.Triggers,
		MatchData:      spec.MatchData,
		Payload:        spec.Payload,
		MatchKey:       append([]byte(nil), spec.MatchKey...),
		Threshold:      spec.Threshold,
		Phase:          Unwitnessed{},
		DeliveredPhase: Unwitnessed{},
	}
	if spec.SeedCandidate != nil {
		anchoring.Spends = []CandidateSpend{*spec.SeedCandidate}
		anchoring.Phase = Witnessed{W: spec.SeedCandidate.W}
		anchoring.DeliveredPhase = Witnessed{W: spec.SeedCandidate.W}
	}
	if err := runPhase1(id); err != nil {
		return 0, err
	}
	m.anchorings[id] = anchoring

	return id, nil
}

// RunPhase1 makes the mock run registrations' phase-1 writes against
// the given handle, the way the production registrar runs them on
// its transaction.
func (m *MockRegistrar) RunPhase1(tx RegistryTx) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.phase1Tx = tx
}

// KickOutbox is a no-op: the mock has no outbox.
func (m *MockRegistrar) KickOutbox() {}

// FailNextRegister makes the next Register call fail with the given
// error, the way a registration transaction can fail in production.
func (m *MockRegistrar) FailNextRegister(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.failNext = err
}

// snapshot copies an anchoring deeply enough that a caller holding the
// result is unaffected by later mutation through the registrar.
//
// The production registrar assembles a fresh value out of database rows
// on every read, so its callers own what they receive. The mock keeps
// its anchorings in a map and has to copy them to offer the same
// guarantee: ConfirmSpend rewrites Spends, Phase and DeliveredPhase in
// place, and a subsystem's outcome wait reads an anchoring on its own
// goroutine while the test drives delivery from the test goroutine.
//
// The candidate spends are copied one level. Their block headers and
// merkle proofs are pointers, but ConfirmSpend installs freshly
// allocated ones and replaces the slice wholesale rather than writing
// through the existing pointers, so nothing reachable from a returned
// candidate is ever mutated in place.
func snapshot(a *Anchoring) *Anchoring {
	out := *a
	out.MatchKey = append([]byte(nil), a.MatchKey...)
	out.Spends = append([]CandidateSpend(nil), a.Spends...)

	return &out
}

// AllAnchorings lists the site's recorded anchorings.
func (m *MockRegistrar) AllAnchorings(_ context.Context,
	site SiteID) ([]*Anchoring, error) {

	m.mu.Lock()
	defer m.mu.Unlock()

	out := make([]*Anchoring, 0, len(m.anchorings))
	for _, anchoring := range m.anchorings {
		if anchoring.Site == site {
			out = append(out, snapshot(anchoring))
		}
	}

	return out, nil
}

// LookupByMatchKey scans the recorded anchorings for one whose site
// and match key equal the arguments.
func (m *MockRegistrar) LookupByMatchKey(_ context.Context, site SiteID,
	matchKey []byte) (*Anchoring, error) {

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, anchoring := range m.anchorings {
		if anchoring.Site != site {
			continue
		}
		if bytes.Equal(anchoring.MatchKey, matchKey) {
			return snapshot(anchoring), nil
		}
	}

	return nil, nil
}

// Anchoring reads a recorded anchoring.
func (m *MockRegistrar) Anchoring(_ context.Context,
	id AnchoringID) (*Anchoring, error) {

	m.mu.Lock()
	defer m.mu.Unlock()

	anchoring, ok := m.anchorings[id]
	if !ok {
		return nil, fmt.Errorf("no anchoring with id %d", id)
	}

	return snapshot(anchoring), nil
}

// ConfirmSpend marks every anchoring whose trigger set is spent by the
// given transaction as witnessed-and-delivered at the given location,
// recording a block-enriched candidate the way sensing would. It
// returns the number of anchorings confirmed.
func (m *MockRegistrar) ConfirmSpend(tx *wire.MsgTx,
	blockHash chainhash.Hash, height, txIndex uint32,
	header wire.BlockHeader, merkleProof proof.TxMerkleProof) (int,
	error) {

	witness, err := NewWitness(tx, blockHash, height, txIndex)
	if err != nil {
		return 0, err
	}

	spent := make(map[wire.OutPoint]struct{}, len(tx.TxIn))
	for _, txIn := range tx.TxIn {
		spent[txIn.PreviousOutPoint] = struct{}{}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	confirmed := 0
	for _, anchoring := range m.anchorings {
		hit := false
		for _, trigger := range anchoring.Triggers.OutPoints() {
			if _, ok := spent[trigger.OutPoint]; ok {
				hit = true
				break
			}
		}
		if !hit {
			continue
		}

		headerCopy := header
		merkleCopy := merkleProof
		anchoring.Spends = []CandidateSpend{{
			W:           witness,
			BlockHeader: &headerCopy,
			MerkleProof: &merkleCopy,
		}}
		anchoring.Phase = Witnessed{W: witness}
		anchoring.DeliveredPhase = Witnessed{W: witness}
		confirmed++
	}

	return confirmed, nil
}

// Abandon marks an anchoring as abandoned-and-delivered on the burial
// of a foreign transaction spending one of its trigger outpoints at
// the given location, the way sensing and delivery would.
func (m *MockRegistrar) Abandon(id AnchoringID, foreign *wire.MsgTx,
	blockHash chainhash.Hash, height, txIndex uint32) error {

	witness, err := NewWitness(foreign, blockHash, height, txIndex)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	anchoring, ok := m.anchorings[id]
	if !ok {
		return fmt.Errorf("no anchoring with id %d", id)
	}

	spent := anchoring.Triggers.SpentBy(foreign)
	if len(spent) == 0 {
		return fmt.Errorf("transaction %v spends no trigger of "+
			"anchoring %d", foreign.TxHash(), id)
	}

	phase := Abandoned{Cause: ForeignBurial{Spend: ForeignSpend{
		SpentOutPoint: spent[0],
		W:             witness,
	}}}
	anchoring.Phase = phase
	anchoring.DeliveredPhase = phase

	return nil
}
