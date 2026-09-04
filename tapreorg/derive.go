package tapreorg

import (
	"bytes"
	"sort"

	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
)

// CandidateSpend is one observed spending transaction of an
// anchoring's trigger set: the located transaction, the site's
// verdict on it, which trigger outpoints it spends, and whether it is
// currently part of the dominant chain. Candidates are never deleted
// by sensing — a candidate that reorgs out merely flips off-chain,
// since it may return.
type CandidateSpend struct {
	// Verdict is the site's judgment of the candidate. It is
	// evaluated exactly once per candidate transaction, since the
	// predicate is pure.
	Verdict Verdict

	// W locates the candidate; the location is refreshed when the
	// candidate re-confirms in a different block.
	W Witness

	// OnChain reports whether the candidate is currently part of
	// the dominant chain.
	OnChain bool

	// ActCertified reports that the chain notifier certified the
	// candidate reaching the anchoring's threshold depth: a
	// confirmation subscription registered at that depth fired,
	// which the notifier does only for a transaction that
	// genuinely held the depth on the dominant chain. Act-tier
	// derivation trusts only this certification — never depth
	// arithmetic over a possibly-torn (view, best height) pair —
	// and the flag is sticky: a deeper reorg afterwards is the
	// out-of-scope case, not a retraction.
	ActCertified bool

	// BlockHeader is the header of the including block, captured
	// from the confirmation event at sensing time so that site
	// handlers can rebuild proofs without network access inside
	// their transaction.
	BlockHeader *wire.BlockHeader

	// MerkleProof is the candidate's inclusion proof in its block,
	// captured alongside BlockHeader.
	MerkleProof *proof.TxMerkleProof

	// SpentOutPoints are the trigger outpoints the candidate
	// spends.
	SpentOutPoints []wire.OutPoint
}

// ForeclosureEvent is staged foreclosure evidence on an anchoring: a
// parent anchoring can no longer supply a depended-upon trigger
// outpoint, because the parent was abandoned or because its witness
// changed to a different transaction. The foreclosure becomes final —
// and the anchoring Abandoned — only when the foreclosing transaction
// reaches the anchoring's own threshold.
type ForeclosureEvent struct {
	// Parent is the anchoring whose outcome forecloses this one.
	Parent AnchoringID

	// W locates the foreclosing transaction (the foreign spend
	// that abandoned the parent, or the parent's replacement
	// witness).
	W Witness

	// OnChain reports whether the foreclosing transaction is
	// currently part of the dominant chain; foreclosure staged by
	// a transaction that itself reorgs out carries no force.
	OnChain bool

	// ActCertified reports that the notifier certified the
	// foreclosing transaction reaching the *child's* threshold
	// depth. Only a certified foreclosure abandons the child; see
	// CandidateSpend.ActCertified for the certification
	// discipline.
	ActCertified bool
}

// ChainView is the sensed evidence from which an anchoring's phase is
// derived: every candidate spend observed for it, plus any staged
// foreclosure.
type ChainView struct {
	// Spends are the observed candidate spends.
	Spends []CandidateSpend

	// Foreclosure is staged foreclosure evidence, if any.
	Foreclosure fn.Option[ForeclosureEvent]
}

// DerivePhase computes an anchoring's phase as a pure, total function
// of its chain view. Every possible view maps to a phase, so there is
// no state of the world the registry cannot represent. Withdrawn is
// never derived: it is site-initiated, not chain-derived.
//
// Act-tier phases derive exclusively from notifier certifications
// (the ActCertified flags): the notifier fires a threshold-depth
// confirmation only for a transaction that genuinely held that depth
// on the dominant chain. Depth is never computed here from a view
// plus a best height, because those two inputs arrive on independent
// streams and can tear — deriving act finality from their combination
// can certify a chain state that never existed.
//
// Derivation, in order of evidence strength:
//
//   - A certified satisfying spend yields Buried; a certified foreign
//     spend yields Abandoned; a certified foreclosure yields
//     Abandoned by cascade. Certification is sticky, so these are
//     absorbing.
//   - Otherwise, potency follows the dominant chain: an on-chain
//     satisfying spend yields Witnessed, on-chain foreign spends
//     yield Conflicted, and nothing on-chain yields Unwitnessed.
//
// Under the whole-set rule a satisfying spend and a foreign spend
// cannot coexist on one chain, and certifications cannot coexist
// across verdicts. If a corrupt view presents contradictory evidence,
// the conservative reading wins: Conflicted, which triggers only soft
// site action, never burial or compensation.
func DerivePhase(view ChainView) Phase {
	var (
		witness          *CandidateSpend
		foreign          []CandidateSpend
		certifiedWitness *CandidateSpend
		certifiedForeign *CandidateSpend
	)
	for i := range view.Spends {
		spend := &view.Spends[i]

		if spend.ActCertified {
			switch spend.Verdict {
			case VerdictSatisfies:
				if certifiedWitness == nil || spendPreferred(
					spend, certifiedWitness,
				) {

					certifiedWitness = spend
				}

			case VerdictForeign:
				if certifiedForeign == nil || spendPreferred(
					spend, certifiedForeign,
				) {

					certifiedForeign = spend
				}
			}
		}

		if !spend.OnChain {
			continue
		}

		switch spend.Verdict {
		case VerdictSatisfies:
			// Under the whole-set rule there is at most one
			// on-chain satisfying spend; against a corrupt
			// view we keep the preferred one.
			if witness == nil || spendPreferred(spend, witness) {
				witness = spend
			}

		case VerdictForeign:
			foreign = append(foreign, *spend)
		}
	}

	// Contradictory certifications are a corrupt view: withhold
	// act finality entirely and read the potency evidence
	// conservatively below.
	if certifiedWitness != nil && certifiedForeign != nil {
		certifiedWitness, certifiedForeign = nil, nil
	}

	switch {
	// A certified witness: act-positive, absorbing.
	case certifiedWitness != nil:
		return Buried{W: certifiedWitness.W}

	// A certified foreign spend: act-negative, absorbing.
	case certifiedForeign != nil:
		return Abandoned{Cause: ForeignBurial{
			Spend: foreignSpendOf(*certifiedForeign),
		}}
	}

	// A certified foreclosure resolves an anchoring that has no
	// certified direct evidence of its own: its premises are dead
	// with act-level finality. Potency evidence does not gate it —
	// an on-chain but uncertified witness is outranked, since its
	// on-chain flag is reversible and a terminal phase must never
	// hinge on evidence a one-block reorg can flip.
	fc := view.Foreclosure.UnwrapToPtr()
	if fc != nil && fc.ActCertified {
		return Abandoned{Cause: Foreclosed{
			Parent: fc.Parent,
			W:      fc.W,
		}}
	}

	switch {
	// A live witness, uncontradicted: potency-positive.
	case witness != nil && len(foreign) == 0:
		return Witnessed{W: witness.W}

	// Foreign spends only: potency-negative.
	case witness == nil && len(foreign) > 0:
		return Conflicted{Spends: foreignSpendsOf(foreign)}

	// Whole-set violation: both a satisfying and a foreign spend
	// claim to be on one chain. Impossible for a view built from a
	// single chain; read conservatively as Conflicted, which
	// neither buries nor compensates.
	case witness != nil && len(foreign) > 0:
		return Conflicted{Spends: foreignSpendsOf(foreign)}
	}

	return Unwitnessed{}
}

// spendPreferred is a total, deterministic preference order among
// candidate spends: deeper wins; height ties (two foreign spends of
// different outpoints in the same block are perfectly possible) break
// on transaction hash, then block hash, then transaction index, so
// that derivation never depends on sensing order.
func spendPreferred(a, b *CandidateSpend) bool {
	if a.W.Height() != b.W.Height() {
		return a.W.Height() < b.W.Height()
	}

	hashA, hashB := a.W.TxHash(), b.W.TxHash()
	if cmp := bytes.Compare(hashA[:], hashB[:]); cmp != 0 {
		return cmp < 0
	}

	blockA, blockB := a.W.BlockHash(), b.W.BlockHash()
	if cmp := bytes.Compare(blockA[:], blockB[:]); cmp != 0 {
		return cmp < 0
	}

	return a.W.TxIndex() < b.W.TxIndex()
}

// foreignSpendOf converts an on-chain foreign candidate into the
// ForeignSpend evidence carried by phases. The candidate's first
// spent trigger outpoint identifies what it claimed.
func foreignSpendOf(c CandidateSpend) ForeignSpend {
	var op wire.OutPoint
	if len(c.SpentOutPoints) > 0 {
		op = c.SpentOutPoints[0]
	}

	return ForeignSpend{SpentOutPoint: op, W: c.W}
}

// foreignSpendsOf converts on-chain foreign candidates into phase
// evidence, canonically ordered so that derivation — and therefore
// phase equality — is invariant under the order in which spends were
// sensed.
func foreignSpendsOf(cs []CandidateSpend) []ForeignSpend {
	out := make([]ForeignSpend, len(cs))
	for i, c := range cs {
		out[i] = foreignSpendOf(c)
	}

	sort.Slice(out, func(i, j int) bool {
		hashI, hashJ := out[i].W.TxHash(), out[j].W.TxHash()
		cmp := bytes.Compare(hashI[:], hashJ[:])
		if cmp != 0 {
			return cmp < 0
		}

		opCmp := bytes.Compare(
			out[i].SpentOutPoint.Hash[:],
			out[j].SpentOutPoint.Hash[:],
		)
		if opCmp != 0 {
			return opCmp < 0
		}

		return out[i].SpentOutPoint.Index < out[j].SpentOutPoint.Index
	})

	return out
}
