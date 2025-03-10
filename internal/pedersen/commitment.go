package pedersen

import (
	"crypto/sha256"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/input"
)

var (
	// DefaultNUMS is the default NUMS key used for Pedersen commitments.
	DefaultNUMS = input.TaprootNUMSKey

	// one is the value 1 as a scalar value.
	one = new(btcec.ModNScalar).SetInt(1)
)

// Opening is the opening to a Pedersen commitment. It contains a message, and
// an optional mask. If the mask is left off, then the commitment will lose its
// hiding property (two identical messages will map to the same point), but the
// binding property is kept.
type Opening struct {
	// Msg is the message that was committed to.
	Msg [sha256.Size]byte

	// Mask is the mask used to blind the message. This is typically
	// referred to as `r` in the Pedersen commitment literature.
	//
	// We make this optional, as without it we'll default to no value, which
	// means that the commitment loses the hiding attribute, but still
	// remains computationally binding.
	Mask fn.Option[[sha256.Size]byte]

	// NUMS is an optional value that should be used to verify the
	// commitment if a custom NUMS point was used.
	NUMS fn.Option[btcec.PublicKey]
}

// Commitment is a Pedersen commitment of the form: m*G + r*H, where:
//   - m is the message being committed together
//   - G is the generator point of the curve
//   - r is the mask used to blind the messages
//   - H is the auxiliary generator point
//
// The commitment is a point on the curve. Given the opening a 3rd party can
// verify the message that was committed to.
type Commitment struct {
	// point is the committed point.
	point btcec.PublicKey
}

// commitOpts is a struct that holds the options for creating a commitment.
type commitOpts struct {
	// numsPoint is the NUMS point used for the commitment. If this is not
	// set, then the default NUMS point will be used.
	numsPoint fn.Option[btcec.PublicKey]
}

// defaultCommitOpts returns the default options for creating a commitment.
func defaultCommitOpts() *commitOpts {
	return &commitOpts{}
}

// commitOpt is a functional option that can be used to modify the default set
// of options.
type commitOpt func(*commitOpts)

// WithCustomNUMS is a functional option that can be used to set a custom NUMS
// point.
func WithCustomNUMS(h btcec.PublicKey) commitOpt {
	return func(o *commitOpts) {
		o.numsPoint = fn.Some(h)
	}
}

// commit is a helper function that creates a Pedersen commitment given a
// message, mask, and NUMS point.
func commit(msg [sha256.Size]byte, mask fn.Option[[sha256.Size]byte],
	nums btcec.PublicKey) btcec.PublicKey {

	var (
		numsJ          btcec.JacobianPoint
		blindingPointJ btcec.JacobianPoint

		msgPointJ btcec.JacobianPoint

		commitJ btcec.JacobianPoint
	)

	nums.AsJacobian(&numsJ)

	// First, we'll create the message point, m*G. This maps the message to
	// a new EC point.
	msgPoint, _ := btcec.PrivKeyFromBytes(msg[:])
	msgPoint.PubKey().AsJacobian(&msgPointJ)

	// With the message point created, we'll now create the blinding point
	// using the aux generator H. This will optionally utilize the masking
	// value r. From this we derive the blinding point: r*H.
	blindingVal := fn.MapOption(
		func(r [sha256.Size]byte) *btcec.ModNScalar {
			rVal := new(btcec.ModNScalar)
			rVal.SetByteSlice(r[:])

			return rVal
		},
	)(mask).UnwrapOr(one)
	btcec.ScalarMultNonConst(blindingVal, &numsJ, &blindingPointJ)

	// With the message and blinding point constructed, we'll now add them
	// together to obtain our final commitment.
	btcec.AddNonConst(&msgPointJ, &blindingPointJ, &commitJ)

	commitJ.ToAffine()

	return *btcec.NewPublicKey(&commitJ.X, &commitJ.Y)
}

// NewCommitment creates a new Pedersen commitment given an opening.
func NewCommitment(op Opening, opts ...commitOpt) Commitment {
	opt := defaultCommitOpts()
	for _, o := range opts {
		o(opt)
	}

	numsPoint := opt.numsPoint.UnwrapOr(DefaultNUMS)

	commitPoint := commit(op.Msg, op.Mask, numsPoint)

	return Commitment{
		point: commitPoint,
	}
}

// Verify verifies that the commitment is valid given the opening. False is
// returned if the commitment doesn't match up.
func (c Commitment) Verify(op Opening) bool {
	commitPoint := commit(op.Msg, op.Mask, op.NUMS.UnwrapOr(DefaultNUMS))

	return c.point.IsEqual(&commitPoint)
}

// Point returns the underlying point of the commitment.
func (c Commitment) Point() btcec.PublicKey {
	return c.point
}
