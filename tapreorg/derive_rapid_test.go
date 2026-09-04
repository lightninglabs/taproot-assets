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

// TestPhaseNameRoundTrip asserts that every phase code's stable name
// resolves back to the code: a phase name read off one operator
// surface (a listing, a metric label) filters on another verbatim.
func TestPhaseNameRoundTrip(t *testing.T) {
	t.Parallel()

	codes := []PhaseCode{
		PhaseCodeUnwitnessed, PhaseCodeWitnessed,
		PhaseCodeConflicted, PhaseCodeBuried, PhaseCodeAbandoned,
		PhaseCodeWithdrawn,
	}
	for _, code := range codes {
		back, err := PhaseCodeFromName(code.String())
		require.NoError(t, err)
		require.Equal(t, code, back)
	}

	_, err := PhaseCodeFromName(PhaseCode(17).String())
	require.Error(t, err)
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
			Verdict: verdict,
			W:       genWitness(t, label+".w", maxHeight),
			OnChain: rapid.Bool().Draw(t, label+".onChain"),
			ActCertified: rapid.Bool().Draw(
				t, label+".certified",
			),
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
			ActCertified: rapid.Bool().Draw(
				t, "fc.certified",
			),
		})
	}

	return view
}

// TestDerivePhaseTotal asserts totality and the conservative reading
// over hostile views: derivation always yields a well-formed,
// non-Withdrawn phase, act phases derive only from certifications,
// and contradictory evidence never buries or compensates.
func TestDerivePhaseTotal(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(rt *rapid.T) {
		const maxHeight = 2_000
		view := genHostileView(rt, maxHeight)

		p := DerivePhase(view)
		require.NotNil(rt, p)

		// Withdrawn is never derived.
		_, isWithdrawn := p.(Withdrawn)
		require.False(rt, isWithdrawn)

		// The derived phase is well-formed: it encodes.
		_, _, err := EncodePhase(p)
		require.NoError(rt, err)

		var (
			haveSatisfying     bool
			haveCertSatisfying bool
			haveCertForeign    bool
		)
		for _, s := range view.Spends {
			satisfying := s.Verdict == VerdictSatisfies
			if s.OnChain && satisfying {
				haveSatisfying = true
			}
			if s.ActCertified && satisfying {
				haveCertSatisfying = true
			}
			if s.ActCertified && !satisfying {
				haveCertForeign = true
			}
		}
		fc := view.Foreclosure.UnwrapToPtr()
		haveCertForeclosure := fc != nil && fc.ActCertified

		switch phase := p.(type) {
		// Affirmatives require the corresponding evidence, and
		// act affirmatives require an uncontradicted
		// certification.
		case Witnessed:
			require.True(rt, haveSatisfying)

		case Buried:
			require.True(rt, haveCertSatisfying)
			require.False(rt, haveCertForeign)

		case Abandoned:
			switch phase.Cause.(type) {
			case ForeignBurial:
				require.True(rt, haveCertForeign)
				require.False(rt, haveCertSatisfying)

			case Foreclosed:
				require.True(rt, haveCertForeclosure)
			}
		}
	})
}

// wholeSetView is a chain view drawn under the whole-set rule,
// together with the facts the adequacy assertions need.
type wholeSetView struct {
	view ChainView

	// mode is 0 (nothing spent), 1 (satisfying spend) or 2
	// (foreign spends).
	mode int

	// certified reports whether the mode's evidence carries an act
	// certification.
	certified bool

	// witness is the satisfying spend in mode 1.
	witness Witness

	// certForeignTxHash is the certified foreign spend in mode 2,
	// when certified.
	certForeignTxHash chainhash.Hash

	// numOnChainForeign is the number of on-chain foreign spends
	// in mode 2.
	numOnChainForeign int
}

// genWholeSetView draws a chain view obeying the whole-set rule: at
// most one satisfying spend, never coexisting with foreign spends;
// certifications consistent with a single chain history.
func genWholeSetView(t *rapid.T, maxHeight uint32) wholeSetView {
	out := wholeSetView{mode: rapid.IntRange(0, 2).Draw(t, "mode")}

	// Off-chain, uncertified candidates are harmless in every
	// mode.
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
	// A satisfying spend: on-chain, certified, or both (a
	// certified spend that later fell off-chain is the
	// deeper-than-threshold reorg, and certification is sticky).
	case 1:
		out.certified = rapid.Bool().Draw(t, "sat.certified")
		onChain := true
		if out.certified {
			onChain = rapid.Bool().Draw(t, "sat.onChain")
		}

		out.witness = genWitness(t, "sat.w", maxHeight)
		out.view.Spends = append(out.view.Spends, CandidateSpend{
			Verdict:      VerdictSatisfies,
			W:            out.witness,
			OnChain:      onChain,
			ActCertified: out.certified,
		})

	// Foreign spends of distinct outpoints; at most one certified.
	case 2:
		out.certified = rapid.Bool().Draw(t, "foreign.certified")
		numForeign := rapid.IntRange(1, 3).Draw(t, "numForeign")
		for i := 0; i < numForeign; i++ {
			label := fmt.Sprintf("foreign%d", i)
			w := genWitness(t, label+".w", maxHeight)

			certified := out.certified && i == 0
			onChain := true
			if certified {
				onChain = rapid.Bool().Draw(
					t, label+".onChain",
				)
			}
			if certified {
				out.certForeignTxHash = w.TxHash()
			}
			if onChain {
				out.numOnChainForeign++
			}

			out.view.Spends = append(
				out.view.Spends, CandidateSpend{
					Verdict:      VerdictForeign,
					W:            w,
					OnChain:      onChain,
					ActCertified: certified,
					SpentOutPoints: []wire.OutPoint{{
						Hash: genHash(
							t, label+".op",
						),
					}},
				},
			)
		}
	}

	// Foreclosure can only be staged when the anchoring is not
	// itself witnessed: a foreclosed premise and a live witness
	// cannot coexist.
	if out.mode == 0 && rapid.Bool().Draw(t, "haveForeclosure") {
		out.view.Foreclosure = fn.Some(ForeclosureEvent{
			Parent: 1,
			W:      genWitness(t, "fc.w", maxHeight),
			OnChain: rapid.Bool().Draw(
				t, "fc.onChain",
			),
			ActCertified: rapid.Bool().Draw(
				t, "fc.certified",
			),
		})
	}

	return out
}

// TestDeriveEvidenceAdequacy asserts, over whole-set views, that the
// derived phase is exactly what the evidence justifies at each tier:
// certifications decide act, the dominant chain decides potency.
func TestDeriveEvidenceAdequacy(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(rt *rapid.T) {
		const maxHeight = 2_000
		ws := genWholeSetView(rt, maxHeight)

		p := DerivePhase(ws.view)

		switch ws.mode {
		// Nothing spent: Unwitnessed, unless a certified
		// foreclosure resolves the anchoring.
		case 0:
			fc := ws.view.Foreclosure.UnwrapToPtr()
			if fc != nil && fc.ActCertified {
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

		// A satisfying spend: Buried when certified (on-chain or
		// not — certification is sticky), Witnessed while merely
		// on-chain, with the same witness either way.
		case 1:
			onChain := ws.view.Spends[len(ws.view.Spends)-1].
				OnChain

			switch {
			case ws.certified:
				buried, ok := p.(Buried)
				require.True(rt, ok)
				require.Equal(
					rt, ws.witness.TxHash(),
					buried.W.TxHash(),
				)

			case onChain:
				witnessed, ok := p.(Witnessed)
				require.True(rt, ok)
				require.Equal(
					rt, ws.witness.TxHash(),
					witnessed.W.TxHash(),
				)

			default:
				require.Equal(rt, Unwitnessed{}, p)
			}

		// Foreign spends: Abandoned when one is certified,
		// Conflicted while any is merely on-chain.
		case 2:
			switch {
			case ws.certified:
				abandoned, ok := p.(Abandoned)
				require.True(rt, ok)
				cause, ok := abandoned.Cause.(ForeignBurial)
				require.True(rt, ok)
				require.Equal(
					rt, ws.certForeignTxHash,
					cause.Spend.W.TxHash(),
				)

			case ws.numOnChainForeign > 0:
				conflicted, ok := p.(Conflicted)
				require.True(rt, ok)
				require.Len(
					rt, conflicted.Spends,
					ws.numOnChainForeign,
				)

			default:
				require.Equal(rt, Unwitnessed{}, p)
			}
		}
	})
}

// TestDeriveCertificationMonotone asserts that certifying the
// evidence a potency phase rests on moves it to the act tier of the
// same sign, with the same deciding transaction — and never flips the
// sign.
func TestDeriveCertificationMonotone(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(rt *rapid.T) {
		const maxHeight = 2_000
		ws := genWholeSetView(rt, maxHeight)

		p1 := DerivePhase(ws.view)

		// Certify every on-chain candidate.
		certified := ChainView{
			Spends: append(
				[]CandidateSpend{}, ws.view.Spends...,
			),
			Foreclosure: ws.view.Foreclosure,
		}
		for i := range certified.Spends {
			if certified.Spends[i].OnChain {
				certified.Spends[i].ActCertified = true
			}
		}

		p2 := DerivePhase(certified)

		switch phase1 := p1.(type) {
		case Witnessed:
			buried, ok := p2.(Buried)
			require.True(rt, ok)
			require.Equal(
				rt, phase1.W.TxHash(), buried.W.TxHash(),
			)

		case Conflicted:
			abandoned, ok := p2.(Abandoned)
			require.True(rt, ok)
			_, ok = abandoned.Cause.(ForeignBurial)
			require.True(rt, ok)

		case Buried:
			require.True(rt, PhaseEqual(p1, p2))

		case Abandoned:
			// Additional certifications can change which
			// foreign spend is preferred as the cause;
			// derivation is pure, and absorption of the
			// first-sensed terminal is the service's job.
			// The sign, however, never flips.
			_, ok := p2.(Abandoned)
			require.True(rt, ok)

		case Unwitnessed:
			// Nothing on-chain to certify: unchanged.
			require.True(rt, PhaseEqual(p1, p2))
		}
	})
}

// TestDeriveCertifiedForeclosureAbsorbing pins the act-tier ranking
// around a certified foreclosure: it abandons the anchoring even
// while an uncertified satisfying spend sits on the dominant chain —
// terminal abandonment must never hinge on the reversible on-chain
// flag — while the anchoring's own certified witness outranks it.
func TestDeriveCertifiedForeclosureAbsorbing(t *testing.T) {
	t.Parallel()

	mkWitness := func(lock, height uint32) Witness {
		tx := wire.NewMsgTx(2)
		tx.LockTime = lock
		w, err := NewWitness(tx, chainhash.Hash{1}, height, 0)
		require.NoError(t, err)

		return w
	}

	own := mkWitness(1, 100)
	foreclosing := mkWitness(2, 101)

	view := ChainView{
		Spends: []CandidateSpend{{
			Verdict: VerdictSatisfies,
			W:       own,
			OnChain: true,
		}},
		Foreclosure: fn.Some(ForeclosureEvent{
			Parent:       1,
			W:            foreclosing,
			OnChain:      true,
			ActCertified: true,
		}),
	}

	p := DerivePhase(view)
	abandoned, ok := p.(Abandoned)
	require.True(t, ok, "got %v", p)
	cause, ok := abandoned.Cause.(Foreclosed)
	require.True(t, ok)
	require.Equal(t, foreclosing.TxHash(), cause.W.TxHash())

	// Flipping the witness's on-chain flag must not change the
	// outcome: the deciding evidence is act-tier, not potency.
	view.Spends[0].OnChain = false
	require.True(t, PhaseEqual(p, DerivePhase(view)))

	// The anchoring's own certified witness outranks the certified
	// foreclosure: direct act evidence wins over cascaded.
	view.Spends[0].OnChain = true
	view.Spends[0].ActCertified = true
	buried, ok := DerivePhase(view).(Buried)
	require.True(t, ok)
	require.Equal(t, own.TxHash(), buried.W.TxHash())
}

// TestDerivePermutationInvariant asserts that derivation does not
// depend on the order in which candidate spends were sensed.
func TestDerivePermutationInvariant(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(rt *rapid.T) {
		const maxHeight = 2_000
		view := genHostileView(rt, maxHeight)

		p1 := DerivePhase(view)

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

		p2 := DerivePhase(shuffled)
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
