package tapreorg

import (
	"bytes"
	"sort"

	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/fn"
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
// of its chain view, threshold and the current best height. Every
// possible view maps to a phase, so there is no state of the world
// the registry cannot represent. Withdrawn is never derived: it is
// site-initiated, not chain-derived.
//
// Derivation, in order of evidence strength:
//
//   - A satisfying spend on the dominant chain yields Witnessed, or
//     Buried at threshold depth.
//   - Otherwise, foreign spends on the dominant chain yield
//     Conflicted, or Abandoned once the deepest reaches threshold.
//   - Otherwise, on-chain foreclosure at threshold depth yields
//     Abandoned; shallower (or off-chain) foreclosure carries no
//     force, and the anchoring is simply Unwitnessed — its witness,
//     if any, is off-chain.
//
// Under the whole-set rule a satisfying spend and a foreign spend
// cannot coexist on one chain. If a corrupt view presents both, the
// conservative reading wins: Conflicted, which triggers only soft
// site action, never burial or compensation.
func DerivePhase(view ChainView, threshold uint32,
	bestHeight uint32) Phase {

	var (
		witness    *CandidateSpend
		foreign    []CandidateSpend
		maxForeign *CandidateSpend
	)
	for i := range view.Spends {
		spend := &view.Spends[i]
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
			if maxForeign == nil ||
				spendPreferred(spend, maxForeign) {

				maxForeign = spend
			}
		}
	}

	switch {
	// A live witness, uncontradicted: potency or act depending on
	// depth.
	case witness != nil && len(foreign) == 0:
		if witness.W.Depth(bestHeight) >= threshold {
			return Buried{W: witness.W}
		}

		return Witnessed{W: witness.W}

	// Foreign spends only: the stake cannot currently succeed, and
	// once the deepest foreign spend is buried, the chain has
	// decided against us with the same finality it grants
	// successes.
	case witness == nil && len(foreign) > 0:
		if maxForeign.W.Depth(bestHeight) >= threshold {
			return Abandoned{Cause: ForeignBurial{
				Spend: foreignSpendOf(*maxForeign),
			}}
		}

		return Conflicted{Spends: foreignSpendsOf(foreign)}

	// Whole-set violation: both a satisfying and a foreign spend
	// claim to be on one chain. Impossible for a view built from a
	// single chain under the whole-set rule; read conservatively
	// as Conflicted, which neither buries nor compensates.
	case witness != nil && len(foreign) > 0:
		return Conflicted{Spends: foreignSpendsOf(foreign)}
	}

	// No trigger outpoint is spent on the dominant chain. A staged
	// on-chain foreclosure that has reached threshold depth
	// resolves the anchoring: its premises are dead with act-level
	// finality, and no direct chain evidence about it can ever
	// arrive.
	fc := view.Foreclosure.UnwrapToPtr()
	if fc != nil && fc.OnChain && fc.W.Depth(bestHeight) >= threshold {
		return Abandoned{Cause: Foreclosed{
			Parent: fc.Parent,
			W:      fc.W,
		}}
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
