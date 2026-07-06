package tapreorg

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
)

// Phase is the chain's current answer to an anchoring, as a sealed
// sum: exactly the types in this file implement it. Each variant
// carries the evidence that justifies it, so an evidence-free
// affirmative (a Witnessed without a witness, a Buried without burial
// evidence) is unrepresentable.
//
// The live phases are Unwitnessed, Witnessed and Conflicted; the
// terminal phases are Buried, Abandoned and Withdrawn. Unwitnessed is
// re-enterable: a witness reorged out with no successor returns the
// anchoring to Unwitnessed rather than leaving a stale affirmative
// standing.
type Phase interface {
	fmt.Stringer

	// sealedPhase restricts implementations to this package.
	sealedPhase()
}

// Unwitnessed is the phase in which no trigger outpoint is spent on
// the dominant chain: the initial phase, and the phase re-entered
// when a witness is lost with no successor.
type Unwitnessed struct{}

// Witnessed is the phase in which a satisfying spend of the trigger
// set sits on the dominant chain, within the anchoring's threshold.
type Witnessed struct {
	// W is the current witness.
	W Witness
}

// Conflicted is the phase in which some trigger outpoint is spent on
// the dominant chain by a transaction the site's predicate rejected,
// within the anchoring's threshold.
type Conflicted struct {
	// Spends are the on-chain foreign spends.
	Spends []ForeignSpend
}

// Buried is the terminal phase in which the current witness has
// reached the anchoring's threshold: the speculation is
// act-confirmed.
type Buried struct {
	// W is the buried witness.
	W Witness
}

// Abandoned is the terminal phase in which the chain has decided
// against the anchoring with act-level finality.
type Abandoned struct {
	// Cause records what decided against the anchoring.
	Cause AbandonCause
}

// Withdrawn is the terminal phase entered when the owning site revokes
// its own stake. It is never derived from chain evidence.
type Withdrawn struct{}

func (Unwitnessed) sealedPhase() {}
func (Witnessed) sealedPhase()   {}
func (Conflicted) sealedPhase()  {}
func (Buried) sealedPhase()      {}
func (Abandoned) sealedPhase()   {}
func (Withdrawn) sealedPhase()   {}

// String returns the phase name.
func (Unwitnessed) String() string {
	return "unwitnessed"
}

// String returns the phase name and the witness location.
func (p Witnessed) String() string {
	return fmt.Sprintf("witnessed(%v@%d)", p.W.TxHash(), p.W.Height())
}

// String returns the phase name and the number of foreign spends.
func (p Conflicted) String() string {
	return fmt.Sprintf("conflicted(%d foreign)", len(p.Spends))
}

// String returns the phase name and the witness location.
func (p Buried) String() string {
	return fmt.Sprintf("buried(%v@%d)", p.W.TxHash(), p.W.Height())
}

// String returns the phase name and its cause.
func (p Abandoned) String() string {
	return fmt.Sprintf("abandoned(%v)", p.Cause)
}

// String returns the phase name.
func (Withdrawn) String() string {
	return "withdrawn"
}

// AbandonCause records what decided against an anchoring, as a sealed
// sum: a foreign spend reaching burial depth, or the foreclosure of a
// premise the anchoring depended on.
type AbandonCause interface {
	fmt.Stringer

	// Witness locates the transaction whose burial decided
	// against the anchoring on chain.
	Witness() Witness

	// sealedAbandonCause restricts implementations to this
	// package.
	sealedAbandonCause()
}

// ForeignBurial is the abandon cause in which a foreign spend of a
// trigger outpoint reached the anchoring's threshold.
type ForeignBurial struct {
	// Spend is the buried foreign spend.
	Spend ForeignSpend
}

// Foreclosed is the abandon cause in which a parent anchoring can no
// longer supply a depended-upon trigger outpoint, with act-level
// finality: the chain voted on the anchoring's premises rather than
// on the anchoring itself.
type Foreclosed struct {
	// Parent is the anchoring whose outcome foreclosed this one.
	Parent AnchoringID

	// W locates the transaction whose burial made the foreclosure
	// final (the foreign spend that abandoned the parent, or the
	// parent's replacement witness). Carrying the full witness
	// keeps the cause self-contained, so foreclosure can cascade
	// onward to this anchoring's own dependents.
	W Witness
}

func (ForeignBurial) sealedAbandonCause() {}
func (Foreclosed) sealedAbandonCause()    {}

// Witness locates the buried foreign spend.
func (c ForeignBurial) Witness() Witness {
	return c.Spend.W
}

// Witness locates the transaction whose burial made the foreclosure
// final.
func (c Foreclosed) Witness() Witness {
	return c.W
}

// String returns the cause description.
func (c ForeignBurial) String() string {
	return fmt.Sprintf("foreign burial by %v", c.Spend.W.TxHash())
}

// String returns the cause description.
func (c Foreclosed) String() string {
	return fmt.Sprintf("foreclosed by parent anchoring %d via %v",
		c.Parent, c.W.TxHash())
}

// IsTerminal reports whether the phase is terminal. Terminal
// anchorings are no longer sensed and never leave their phase.
func IsTerminal(p Phase) bool {
	switch p.(type) {
	case Buried, Abandoned, Withdrawn:
		return true

	case Unwitnessed, Witnessed, Conflicted:
		return false

	default:
		// Unreachable: the sum is sealed.
		panic(fmt.Sprintf("unknown phase type %T", p))
	}
}

// PhaseCode is the compact database representation of a phase's
// variant. Evidence travels separately, in the encoded evidence blob.
type PhaseCode uint8

const (
	// PhaseCodeUnwitnessed tags Unwitnessed.
	PhaseCodeUnwitnessed PhaseCode = 0

	// PhaseCodeWitnessed tags Witnessed.
	PhaseCodeWitnessed PhaseCode = 1

	// PhaseCodeConflicted tags Conflicted.
	PhaseCodeConflicted PhaseCode = 2

	// PhaseCodeBuried tags Buried.
	PhaseCodeBuried PhaseCode = 3

	// PhaseCodeAbandoned tags Abandoned.
	PhaseCodeAbandoned PhaseCode = 4

	// PhaseCodeWithdrawn tags Withdrawn.
	PhaseCodeWithdrawn PhaseCode = 5
)

// phaseEvidenceVersion versions the evidence encoding below, so that
// a future format change can coexist with rows written by this one.
const phaseEvidenceVersion byte = 0

// abandon cause tags within the Abandoned evidence encoding.
const (
	causeTagForeignBurial byte = 0
	causeTagForeclosed    byte = 1
)

// CodeOf returns the compact code of the phase's variant.
func CodeOf(p Phase) PhaseCode {
	switch p.(type) {
	case Unwitnessed:
		return PhaseCodeUnwitnessed

	case Witnessed:
		return PhaseCodeWitnessed

	case Conflicted:
		return PhaseCodeConflicted

	case Buried:
		return PhaseCodeBuried

	case Abandoned:
		return PhaseCodeAbandoned

	case Withdrawn:
		return PhaseCodeWithdrawn

	default:
		// Unreachable: the sum is sealed.
		panic(fmt.Sprintf("unknown phase type %T", p))
	}
}

// String renders the code's stable lowercase name, as used on
// operator surfaces such as RPC filters and metric labels. It is the
// inverse of PhaseCodeFromName, so a phase name read off one surface
// filters on another verbatim.
func (c PhaseCode) String() string {
	switch c {
	case PhaseCodeUnwitnessed:
		return "unwitnessed"

	case PhaseCodeWitnessed:
		return "witnessed"

	case PhaseCodeConflicted:
		return "conflicted"

	case PhaseCodeBuried:
		return "buried"

	case PhaseCodeAbandoned:
		return "abandoned"

	case PhaseCodeWithdrawn:
		return "withdrawn"

	default:
		return fmt.Sprintf("unknown<%d>", uint8(c))
	}
}

// PhaseCodeFromName resolves a phase's stable lowercase name — as
// used on operator surfaces such as RPC filters and metric labels —
// to its code. It is the inverse of PhaseCode.String.
func PhaseCodeFromName(name string) (PhaseCode, error) {
	switch name {
	case "unwitnessed":
		return PhaseCodeUnwitnessed, nil

	case "witnessed":
		return PhaseCodeWitnessed, nil

	case "conflicted":
		return PhaseCodeConflicted, nil

	case "buried":
		return PhaseCodeBuried, nil

	case "abandoned":
		return PhaseCodeAbandoned, nil

	case "withdrawn":
		return PhaseCodeWithdrawn, nil

	default:
		return 0, fmt.Errorf("unknown phase name %q", name)
	}
}

// EncodePhase encodes a phase into its compact code and evidence
// blob. The encoding is deterministic, which makes encoded equality a
// sound phase equality (see PhaseEqual).
func EncodePhase(p Phase) (PhaseCode, []byte, error) {
	var buf bytes.Buffer

	switch phase := p.(type) {
	case Unwitnessed:
		return PhaseCodeUnwitnessed, nil, nil

	case Witnessed:
		buf.WriteByte(phaseEvidenceVersion)
		if err := encodeWitness(&buf, phase.W); err != nil {
			return 0, nil, err
		}

		return PhaseCodeWitnessed, buf.Bytes(), nil

	case Conflicted:
		if len(phase.Spends) == 0 {
			return 0, nil, fmt.Errorf("conflicted phase " +
				"requires at least one foreign spend")
		}
		if len(phase.Spends) > math.MaxUint16 {
			return 0, nil, fmt.Errorf("too many foreign spends")
		}

		buf.WriteByte(phaseEvidenceVersion)
		writeU16(&buf, uint16(len(phase.Spends)))
		for _, s := range phase.Spends {
			if err := encodeForeignSpend(&buf, s); err != nil {
				return 0, nil, err
			}
		}

		return PhaseCodeConflicted, buf.Bytes(), nil

	case Buried:
		buf.WriteByte(phaseEvidenceVersion)
		if err := encodeWitness(&buf, phase.W); err != nil {
			return 0, nil, err
		}

		return PhaseCodeBuried, buf.Bytes(), nil

	case Abandoned:
		buf.WriteByte(phaseEvidenceVersion)
		switch cause := phase.Cause.(type) {
		case ForeignBurial:
			buf.WriteByte(causeTagForeignBurial)
			err := encodeForeignSpend(&buf, cause.Spend)
			if err != nil {
				return 0, nil, err
			}

		case Foreclosed:
			buf.WriteByte(causeTagForeclosed)
			writeU64(&buf, uint64(cause.Parent))
			err := encodeWitness(&buf, cause.W)
			if err != nil {
				return 0, nil, err
			}

		default:
			return 0, nil, fmt.Errorf("unknown abandon cause "+
				"type %T", phase.Cause)
		}

		return PhaseCodeAbandoned, buf.Bytes(), nil

	case Withdrawn:
		return PhaseCodeWithdrawn, nil, nil

	default:
		return 0, nil, fmt.Errorf("unknown phase type %T", p)
	}
}

// DecodePhase decodes a phase from its compact code and evidence
// blob, validating the evidence completely; trailing bytes are an
// error.
func DecodePhase(code PhaseCode, evidence []byte) (Phase, error) {
	// The evidence-free phases must come with no evidence.
	switch code {
	case PhaseCodeUnwitnessed:
		if len(evidence) != 0 {
			return nil, fmt.Errorf("unexpected evidence for " +
				"unwitnessed phase")
		}

		return Unwitnessed{}, nil

	case PhaseCodeWithdrawn:
		if len(evidence) != 0 {
			return nil, fmt.Errorf("unexpected evidence for " +
				"withdrawn phase")
		}

		return Withdrawn{}, nil

	// Every other code carries evidence, decoded below.
	default:
	}

	r := bytes.NewReader(evidence)
	version, err := r.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("missing evidence version: %w", err)
	}
	if version != phaseEvidenceVersion {
		return nil, fmt.Errorf("unknown evidence version %d", version)
	}

	var decoded Phase
	switch code {
	case PhaseCodeWitnessed:
		w, err := decodeWitness(r)
		if err != nil {
			return nil, err
		}
		decoded = Witnessed{W: w}

	case PhaseCodeConflicted:
		count, err := readU16(r)
		if err != nil {
			return nil, err
		}
		if count == 0 {
			return nil, fmt.Errorf("conflicted phase requires " +
				"at least one foreign spend")
		}

		spends := make([]ForeignSpend, count)
		for i := range spends {
			spends[i], err = decodeForeignSpend(r)
			if err != nil {
				return nil, err
			}
		}
		decoded = Conflicted{Spends: spends}

	case PhaseCodeBuried:
		w, err := decodeWitness(r)
		if err != nil {
			return nil, err
		}
		decoded = Buried{W: w}

	case PhaseCodeAbandoned:
		tag, err := r.ReadByte()
		if err != nil {
			return nil, fmt.Errorf("missing abandon cause "+
				"tag: %w", err)
		}

		switch tag {
		case causeTagForeignBurial:
			spend, err := decodeForeignSpend(r)
			if err != nil {
				return nil, err
			}
			decoded = Abandoned{Cause: ForeignBurial{
				Spend: spend,
			}}

		case causeTagForeclosed:
			parent, err := readU64(r)
			if err != nil {
				return nil, err
			}
			w, err := decodeWitness(r)
			if err != nil {
				return nil, err
			}
			decoded = Abandoned{Cause: Foreclosed{
				Parent: AnchoringID(parent),
				W:      w,
			}}

		default:
			return nil, fmt.Errorf("unknown abandon cause "+
				"tag %d", tag)
		}

	default:
		return nil, fmt.Errorf("unknown phase code %d", code)
	}

	if r.Len() != 0 {
		return nil, fmt.Errorf("%d trailing evidence bytes", r.Len())
	}

	return decoded, nil
}

// PhaseEqual reports whether two phases are equal, including their
// evidence. Equality is defined as equality of the deterministic
// encoding; a rewitness (same variant, new witness) therefore
// compares unequal, which is exactly what redelivery decisions need.
func PhaseEqual(a, b Phase) bool {
	codeA, evA, errA := EncodePhase(a)
	codeB, evB, errB := EncodePhase(b)
	if errA != nil || errB != nil {
		return false
	}

	return codeA == codeB && bytes.Equal(evA, evB)
}

// encodeWitness writes a witness as blockHash || height || txIndex ||
// txLen || tx.
func encodeWitness(buf *bytes.Buffer, w Witness) error {
	if w.tx == nil {
		return ErrIncompleteWitness
	}

	blockHash := w.BlockHash()
	buf.Write(blockHash[:])
	writeU32(buf, w.Height())
	writeU32(buf, w.TxIndex())

	var txBuf bytes.Buffer
	if err := w.tx.Serialize(&txBuf); err != nil {
		return fmt.Errorf("unable to serialize witness tx: %w", err)
	}
	if uint64(txBuf.Len()) > math.MaxUint32 {
		return fmt.Errorf("witness tx too large")
	}
	writeU32(buf, uint32(txBuf.Len()))
	buf.Write(txBuf.Bytes())

	return nil
}

// decodeWitness reads a witness in the encodeWitness format, routing
// through NewWitness so that decoded values obey the same invariants
// as constructed ones.
func decodeWitness(r *bytes.Reader) (Witness, error) {
	var blockHash chainhash.Hash
	if _, err := io.ReadFull(r, blockHash[:]); err != nil {
		return Witness{}, fmt.Errorf("short block hash: %w", err)
	}

	height, err := readU32(r)
	if err != nil {
		return Witness{}, err
	}
	txIndex, err := readU32(r)
	if err != nil {
		return Witness{}, err
	}

	txLen, err := readU32(r)
	if err != nil {
		return Witness{}, err
	}
	if uint64(txLen) > uint64(r.Len()) {
		return Witness{}, fmt.Errorf("witness tx length %d exceeds "+
			"remaining evidence %d", txLen, r.Len())
	}

	txBytes := make([]byte, txLen)
	if _, err := io.ReadFull(r, txBytes); err != nil {
		return Witness{}, fmt.Errorf("short witness tx: %w", err)
	}

	var tx wire.MsgTx
	if err := tx.Deserialize(bytes.NewReader(txBytes)); err != nil {
		return Witness{}, fmt.Errorf("unable to deserialize "+
			"witness tx: %w", err)
	}

	return NewWitness(&tx, blockHash, height, txIndex)
}

// encodeForeignSpend writes a foreign spend as outpoint || witness.
func encodeForeignSpend(buf *bytes.Buffer, s ForeignSpend) error {
	buf.Write(s.SpentOutPoint.Hash[:])
	writeU32(buf, s.SpentOutPoint.Index)

	return encodeWitness(buf, s.W)
}

// decodeForeignSpend reads a foreign spend in the encodeForeignSpend
// format.
func decodeForeignSpend(r *bytes.Reader) (ForeignSpend, error) {
	var op wire.OutPoint
	if _, err := io.ReadFull(r, op.Hash[:]); err != nil {
		return ForeignSpend{}, fmt.Errorf("short outpoint hash: "+
			"%w", err)
	}

	index, err := readU32(r)
	if err != nil {
		return ForeignSpend{}, err
	}
	op.Index = index

	w, err := decodeWitness(r)
	if err != nil {
		return ForeignSpend{}, err
	}

	return ForeignSpend{SpentOutPoint: op, W: w}, nil
}

func writeU16(buf *bytes.Buffer, v uint16) {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	buf.Write(b[:])
}

func writeU32(buf *bytes.Buffer, v uint32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	buf.Write(b[:])
}

func writeU64(buf *bytes.Buffer, v uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	buf.Write(b[:])
}

func readU16(r *bytes.Reader) (uint16, error) {
	var b [2]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, fmt.Errorf("short uint16: %w", err)
	}

	return binary.BigEndian.Uint16(b[:]), nil
}

func readU32(r *bytes.Reader) (uint32, error) {
	var b [4]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, fmt.Errorf("short uint32: %w", err)
	}

	return binary.BigEndian.Uint32(b[:]), nil
}

func readU64(r *bytes.Reader) (uint64, error) {
	var b [8]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, fmt.Errorf("short uint64: %w", err)
	}

	return binary.BigEndian.Uint64(b[:]), nil
}
