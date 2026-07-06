package tapreorg

import (
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// genHash draws an arbitrary 32-byte hash.
func genHash(t *rapid.T, label string) chainhash.Hash {
	var h chainhash.Hash
	copy(h[:], rapid.SliceOfN(rapid.Byte(), 32, 32).Draw(t, label))

	return h
}

// genTx draws a small arbitrary transaction.
func genTx(t *rapid.T, label string) *wire.MsgTx {
	tx := wire.NewMsgTx(2)

	numIn := rapid.IntRange(1, 3).Draw(t, label+".numIn")
	for i := 0; i < numIn; i++ {
		op := wire.OutPoint{
			Hash: genHash(t, fmt.Sprintf("%s.in%d", label, i)),
			Index: uint32(rapid.IntRange(0, 10).Draw(
				t, fmt.Sprintf("%s.in%d.idx", label, i),
			)),
		}
		tx.AddTxIn(wire.NewTxIn(&op, nil, nil))
	}

	numOut := rapid.IntRange(1, 2).Draw(t, label+".numOut")
	for i := 0; i < numOut; i++ {
		value := rapid.Int64Range(0, 100_000).Draw(
			t, fmt.Sprintf("%s.out%d.value", label, i),
		)
		script := rapid.SliceOfN(rapid.Byte(), 1, 34).Draw(
			t, fmt.Sprintf("%s.out%d.script", label, i),
		)
		tx.AddTxOut(wire.NewTxOut(value, script))
	}

	return tx
}

// genWitnessAt draws a witness located at the given height.
func genWitnessAt(t *rapid.T, label string, height uint32) Witness {
	w, err := NewWitness(
		genTx(t, label+".tx"), genHash(t, label+".block"), height,
		uint32(rapid.IntRange(0, 1_000).Draw(t, label+".txIndex")),
	)
	require.NoError(t, err)

	return w
}

// genWitness draws a witness at an arbitrary height in [1, maxHeight].
func genWitness(t *rapid.T, label string, maxHeight uint32) Witness {
	height := uint32(rapid.IntRange(1, int(maxHeight)).Draw(
		t, label+".height",
	))

	return genWitnessAt(t, label, height)
}

// genForeignSpend draws an arbitrary foreign spend.
func genForeignSpend(t *rapid.T, label string, maxHeight uint32) ForeignSpend {
	return ForeignSpend{
		SpentOutPoint: wire.OutPoint{
			Hash: genHash(t, label+".op"),
			Index: uint32(rapid.IntRange(0, 10).Draw(
				t, label+".opIdx",
			)),
		},
		W: genWitness(t, label+".w", maxHeight),
	}
}

// genPhase draws an arbitrary phase, evidence included.
func genPhase(t *rapid.T) Phase {
	const maxHeight = 1_000_000

	switch rapid.IntRange(0, 6).Draw(t, "phaseKind") {
	case 0:
		return Unwitnessed{}

	case 1:
		return Witnessed{W: genWitness(t, "witnessed", maxHeight)}

	case 2:
		numSpends := rapid.IntRange(1, 3).Draw(t, "numSpends")
		spends := make([]ForeignSpend, numSpends)
		for i := range spends {
			spends[i] = genForeignSpend(
				t, fmt.Sprintf("conflicted.%d", i), maxHeight,
			)
		}

		return Conflicted{Spends: spends}

	case 3:
		return Buried{W: genWitness(t, "buried", maxHeight)}

	case 4:
		return Abandoned{Cause: ForeignBurial{
			Spend: genForeignSpend(t, "burial", maxHeight),
		}}

	case 5:
		return Abandoned{Cause: Foreclosed{
			Parent: AnchoringID(rapid.Int64Range(1, 1<<40).Draw(
				t, "parent",
			)),
			W: genWitness(t, "foreclosing", maxHeight),
		}}

	default:
		return Withdrawn{}
	}
}

// TestPhaseCodecRoundTrip asserts that every phase survives the
// encode/decode round trip, and that the encoding is canonical: the
// decoded value re-encodes to identical bytes.
func TestPhaseCodecRoundTrip(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(rt *rapid.T) {
		p := genPhase(rt)

		code, evidence, err := EncodePhase(p)
		require.NoError(rt, err)

		decoded, err := DecodePhase(code, evidence)
		require.NoError(rt, err)
		require.True(rt, PhaseEqual(p, decoded))

		code2, evidence2, err := EncodePhase(decoded)
		require.NoError(rt, err)
		require.Equal(rt, code, code2)
		require.Equal(rt, evidence, evidence2)

		// Trailing garbage must be rejected.
		_, err = DecodePhase(code, append(evidence, 0x00))
		require.Error(rt, err)
	})
}

// genHostileView draws a completely unconstrained chain view: any
// combination of verdicts, on-chain flags and locations, including
// combinations the whole-set rule forbids.
func genHostileView(t *rapid.T, maxHeight uint32) ChainView {
	numSpends := rapid.IntRange(0, 4).Draw(t, "numSpends")
	spends := make([]CandidateSpend, numSpends)
	for i := range spends {
		label := fmt.Sprintf("spend%d", i)

		var verdict Verdict
		if rapid.Bool().Draw(t, label+".foreign") {
			verdict = VerdictForeign
		}

		numOps := rapid.IntRange(0, 2).Draw(t, label+".numOps")
		ops := make([]wire.OutPoint, numOps)
		for j := range ops {
			ops[j] = wire.OutPoint{
				Hash: genHash(
					t, fmt.Sprintf("%s.op%d", label, j),
				),
			}
		}

		spends[i] = CandidateSpend{
			Verdict:        verdict,
			W:              genWitness(t, label+".w", maxHeight),
			OnChain:        rapid.Bool().Draw(t, label+".onChain"),
			SpentOutPoints: ops,
		}
	}

	view := ChainView{Spends: spends}
	if rapid.Bool().Draw(t, "haveForeclosure") {
		view.Foreclosure = fn.Some(ForeclosureEvent{
			Parent: AnchoringID(rapid.Int64Range(1, 1<<40).Draw(
				t, "fcParent",
			)),
			W:       genWitness(t, "fc.w", maxHeight),
			OnChain: rapid.Bool().Draw(t, "fc.onChain"),
		})
	}

	return view
}

// TestDerivePhaseTotal asserts totality and the conservative reading
// over hostile views: derivation always yields a well-formed,
// non-Withdrawn phase; it never affirms without on-chain satisfying
// evidence, and never buries while a foreign spend sits on-chain.
func TestDerivePhaseTotal(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(rt *rapid.T) {
		const maxHeight = 2_000
		view := genHostileView(rt, maxHeight)
		threshold := uint32(rapid.IntRange(1, 20).Draw(rt, "threshold"))
		bestHeight := uint32(rapid.IntRange(0, 2*maxHeight).Draw(
			rt, "bestHeight",
		))

		p := DerivePhase(view, threshold, bestHeight)
		require.NotNil(rt, p)

		// Withdrawn is never derived.
		_, isWithdrawn := p.(Withdrawn)
		require.False(rt, isWithdrawn)

		// The derived phase is well-formed: it encodes.
		_, _, err := EncodePhase(p)
		require.NoError(rt, err)

		var (
			haveSatisfying bool
			haveForeign    bool
		)
		for _, s := range view.Spends {
			if !s.OnChain {
				continue
			}
			switch s.Verdict {
			case VerdictSatisfies:
				haveSatisfying = true
			case VerdictForeign:
				haveForeign = true
			}
		}

		switch p.(type) {
		case Witnessed:
			require.True(rt, haveSatisfying)
		case Buried:
			require.True(rt, haveSatisfying)
			require.False(rt, haveForeign)
		}
	})
}

// wholeSetView is a chain view drawn under the whole-set rule,
// together with the facts the adequacy assertions need.
type wholeSetView struct {
	view ChainView

	// mode is 0 (nothing on-chain), 1 (satisfying on-chain) or 2
	// (foreign on-chain).
	mode int

	// witness is the on-chain satisfying spend in mode 1.
	witness Witness

	// minForeignHeight is the deepest on-chain foreign height in
	// mode 2.
	minForeignHeight uint32

	// numForeign is the number of on-chain foreign spends in mode
	// 2.
	numForeign int
}

// genWholeSetView draws a chain view obeying the whole-set rule: at
// most one on-chain satisfying spend, never coexisting with on-chain
// foreign spends; off-chain candidates unconstrained.
func genWholeSetView(t *rapid.T, maxHeight uint32) wholeSetView {
	out := wholeSetView{mode: rapid.IntRange(0, 2).Draw(t, "mode")}

	// Off-chain candidates are harmless in every mode.
	numOff := rapid.IntRange(0, 2).Draw(t, "numOffChain")
	for i := 0; i < numOff; i++ {
		label := fmt.Sprintf("off%d", i)
		var verdict Verdict
		if rapid.Bool().Draw(t, label+".foreign") {
			verdict = VerdictForeign
		}
		out.view.Spends = append(out.view.Spends, CandidateSpend{
			Verdict: verdict,
			W:       genWitness(t, label+".w", maxHeight),
			OnChain: false,
		})
	}

	switch out.mode {
	case 1:
		out.witness = genWitness(t, "sat.w", maxHeight)
		out.view.Spends = append(out.view.Spends, CandidateSpend{
			Verdict: VerdictSatisfies,
			W:       out.witness,
			OnChain: true,
		})

	case 2:
		numForeign := rapid.IntRange(1, 3).Draw(t, "numForeign")
		out.numForeign = numForeign
		for i := 0; i < numForeign; i++ {
			label := fmt.Sprintf("foreign%d", i)
			w := genWitness(t, label+".w", maxHeight)
			if i == 0 || w.Height() < out.minForeignHeight {
				out.minForeignHeight = w.Height()
			}
			out.view.Spends = append(
				out.view.Spends, CandidateSpend{
					Verdict: VerdictForeign,
					W:       w,
					OnChain: true,
					SpentOutPoints: []wire.OutPoint{{
						Hash: genHash(
							t, label+".op",
						),
					}},
				},
			)
		}
	}

	// Foreclosure can only be staged when the child is not itself
	// witnessed: a foreclosed premise and an on-chain witness
	// cannot coexist.
	if out.mode == 0 && rapid.Bool().Draw(t, "haveForeclosure") {
		out.view.Foreclosure = fn.Some(ForeclosureEvent{
			Parent: 1,
			W:      genWitness(t, "fc.w", maxHeight),
			OnChain: rapid.Bool().Draw(
				t, "fc.onChain",
			),
		})
	}

	return out
}

// TestDeriveEvidenceAdequacy asserts, over whole-set views, that the
// derived phase is exactly what the evidence justifies at each depth
// tier.
func TestDeriveEvidenceAdequacy(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(rt *rapid.T) {
		const maxHeight = 2_000
		ws := genWholeSetView(rt, maxHeight)
		threshold := uint32(rapid.IntRange(1, 20).Draw(rt, "threshold"))
		bestHeight := uint32(rapid.IntRange(0, 2*maxHeight).Draw(
			rt, "bestHeight",
		))

		p := DerivePhase(ws.view, threshold, bestHeight)

		switch ws.mode {
		// Nothing on-chain: Unwitnessed, unless an on-chain
		// foreclosure has reached threshold depth.
		case 0:
			fc := ws.view.Foreclosure.UnwrapToPtr()
			foreclosed := fc != nil && fc.OnChain &&
				fc.W.Depth(bestHeight) >= threshold

			if foreclosed {
				abandoned, ok := p.(Abandoned)
				require.True(rt, ok)
				cause, ok := abandoned.Cause.(Foreclosed)
				require.True(rt, ok)
				require.Equal(
					rt, fc.W.TxHash(), cause.W.TxHash(),
				)
			} else {
				require.Equal(rt, Unwitnessed{}, p)
			}

		// A satisfying spend on-chain: Witnessed below threshold,
		// Buried at it, with the same witness either way.
		case 1:
			if ws.witness.Depth(bestHeight) >= threshold {
				buried, ok := p.(Buried)
				require.True(rt, ok)
				require.Equal(
					rt, ws.witness.TxHash(),
					buried.W.TxHash(),
				)
			} else {
				witnessed, ok := p.(Witnessed)
				require.True(rt, ok)
				require.Equal(
					rt, ws.witness.TxHash(),
					witnessed.W.TxHash(),
				)
			}

		// Foreign spends on-chain: Conflicted below threshold,
		// Abandoned once the deepest reaches it.
		case 2:
			deepestDepth := bestHeight - ws.minForeignHeight + 1
			if bestHeight < ws.minForeignHeight {
				deepestDepth = 0
			}

			if deepestDepth >= threshold {
				abandoned, ok := p.(Abandoned)
				require.True(rt, ok)
				cause, ok := abandoned.Cause.(ForeignBurial)
				require.True(rt, ok)
				require.Equal(
					rt, ws.minForeignHeight,
					cause.Spend.W.Height(),
				)
			} else {
				conflicted, ok := p.(Conflicted)
				require.True(rt, ok)
				require.Len(
					rt, conflicted.Spends, ws.numForeign,
				)
			}
		}
	})
}

// TestDeriveActMonotone asserts that, with the view fixed, growing
// best height can only move a phase from potency to act — never the
// reverse, and never across the verdict's sign.
func TestDeriveActMonotone(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(rt *rapid.T) {
		const maxHeight = 2_000
		ws := genWholeSetView(rt, maxHeight)
		threshold := uint32(rapid.IntRange(1, 20).Draw(rt, "threshold"))
		h1 := uint32(rapid.IntRange(0, 2*maxHeight).Draw(rt, "h1"))
		h2 := h1 + uint32(rapid.IntRange(0, 100).Draw(rt, "delta"))

		p1 := DerivePhase(ws.view, threshold, h1)
		p2 := DerivePhase(ws.view, threshold, h2)

		switch phase1 := p1.(type) {
		case Buried:
			buried2, ok := p2.(Buried)
			require.True(rt, ok)
			require.Equal(
				rt, phase1.W.TxHash(), buried2.W.TxHash(),
			)

		case Abandoned:
			_, ok := p2.(Abandoned)
			require.True(rt, ok)

		case Witnessed:
			switch phase2 := p2.(type) {
			case Witnessed:
				require.Equal(
					rt, phase1.W.TxHash(),
					phase2.W.TxHash(),
				)
			case Buried:
				require.Equal(
					rt, phase1.W.TxHash(),
					phase2.W.TxHash(),
				)
			default:
				rt.Fatalf("witnessed regressed to %v", p2)
			}

		case Conflicted:
			switch p2.(type) {
			case Conflicted, Abandoned:
			default:
				rt.Fatalf("conflicted regressed to %v", p2)
			}

		case Unwitnessed:
			switch p2.(type) {
			case Unwitnessed:
			case Abandoned:
				// Only an on-chain foreclosure can resolve
				// an unwitnessed anchoring.
				fc := ws.view.Foreclosure.UnwrapToPtr()
				require.NotNil(rt, fc)
				require.True(rt, fc.OnChain)
			default:
				rt.Fatalf("unwitnessed regressed to %v", p2)
			}
		}
	})
}

// TestDerivePermutationInvariant asserts that derivation does not
// depend on the order in which candidate spends were sensed.
func TestDerivePermutationInvariant(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(rt *rapid.T) {
		const maxHeight = 2_000
		view := genHostileView(rt, maxHeight)
		threshold := uint32(rapid.IntRange(1, 20).Draw(rt, "threshold"))
		bestHeight := uint32(rapid.IntRange(0, 2*maxHeight).Draw(
			rt, "bestHeight",
		))

		p1 := DerivePhase(view, threshold, bestHeight)

		// Fisher-Yates over the spends, with rapid-drawn swaps.
		shuffled := ChainView{
			Spends:      append([]CandidateSpend{}, view.Spends...),
			Foreclosure: view.Foreclosure,
		}
		for i := len(shuffled.Spends) - 1; i > 0; i-- {
			j := rapid.IntRange(0, i).Draw(
				rt, fmt.Sprintf("swap%d", i),
			)
			shuffled.Spends[i], shuffled.Spends[j] =
				shuffled.Spends[j], shuffled.Spends[i]
		}

		p2 := DerivePhase(shuffled, threshold, bestHeight)
		require.True(rt, PhaseEqual(p1, p2), "p1=%v p2=%v", p1, p2)
	})
}

// TestConstructorInvariants pins the parse-don't-validate boundary:
// invalid trigger sets, witnesses and verdicts are unconstructible.
func TestConstructorInvariants(t *testing.T) {
	t.Parallel()

	// Empty trigger sets are rejected.
	_, err := NewTriggerSet(nil)
	require.ErrorIs(t, err, ErrEmptyTriggerSet)

	// Duplicate outpoints are rejected.
	op := TriggerOutPoint{OutPoint: wire.OutPoint{Index: 1}}
	_, err = NewTriggerSet([]TriggerOutPoint{op, op})
	require.ErrorIs(t, err, ErrDuplicateTrigger)

	// A witness requires a transaction and a nonzero height.
	_, err = NewWitness(nil, chainhash.Hash{}, 1, 0)
	require.ErrorIs(t, err, ErrIncompleteWitness)
	_, err = NewWitness(wire.NewMsgTx(2), chainhash.Hash{}, 0, 0)
	require.ErrorIs(t, err, ErrIncompleteWitness)

	// Unknown verdicts are rejected.
	_, err = NewVerdict(2)
	require.Error(t, err)

	// Registration specs validate their value-level invariants.
	// The trigger script is a standard (P2WSH-shaped) one: the
	// notifier refuses to watch anything else, so Validate does
	// too.
	op.PkScript = append(
		[]byte{txscript.OP_0, txscript.OP_DATA_32},
		make([]byte, 32)...,
	)
	triggers, err := NewTriggerSet([]TriggerOutPoint{op})
	require.NoError(t, err)

	spec := RegistrationSpec{Triggers: triggers, Threshold: 6}
	require.Error(t, spec.Validate()) // no site

	spec.Site = "test"
	spec.Threshold = 0
	require.Error(t, spec.Validate()) // no threshold

	spec.Threshold = 6
	require.NoError(t, spec.Validate())

	require.Error(t, (&RegistrationSpec{
		Site: "test", Threshold: 6,
	}).Validate()) // no triggers

	// Unwatchable trigger scripts — empty, or parseable but
	// nonstandard — are rejected.
	for _, script := range [][]byte{
		nil,
		{txscript.OP_RETURN},
		{txscript.OP_TRUE},
	} {
		bad := op
		bad.PkScript = script
		badTriggers, err := NewTriggerSet([]TriggerOutPoint{bad})
		require.NoError(t, err)

		badSpec := spec
		badSpec.Triggers = badTriggers
		require.ErrorContains(
			t, badSpec.Validate(), "unwatchable pkScript",
		)
	}
}
