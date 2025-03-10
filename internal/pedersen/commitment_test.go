package pedersen

import (
	"crypto/sha256"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightningnetwork/lnd/fn/v2"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// generateRandomBytes generates a random 256-byte array.
func generateRandomBytes(t *rapid.T) [sha256.Size]byte {
	bytes := rapid.SliceOfN(
		rapid.Byte(), sha256.Size, sha256.Size,
	).Draw(t, "bytes")

	var result [sha256.Size]byte
	copy(result[:], bytes)

	return result
}

// TestPedersenCommitmentProperties tests various properties of Pedersen
// commitments using property-based testing.
func TestPedersenCommitmentProperties(t *testing.T) {
	t.Parallel()

	// Property 1: A commitment should verify with its own opening.
	t.Run("correctness", rapid.MakeCheck(func(t *rapid.T) {
		msg := generateRandomBytes(t)
		mask := generateRandomBytes(t)

		opening := Opening{
			Msg:  msg,
			Mask: fn.Some(mask),
		}

		commitment := NewCommitment(opening)
		require.True(
			t, commitment.Verify(opening),
			"commitment failed to verify with its own opening",
		)
	}))

	// Property 2: Different messages should (with very high probability)
	// produce different commitments.
	t.Run("uniqueness", rapid.MakeCheck(func(t *rapid.T) {
		msg1 := generateRandomBytes(t)
		msg2 := generateRandomBytes(t)
		mask := generateRandomBytes(t)

		// Skip if messages happen to be the same.
		if msg1 == msg2 {
			return
		}

		opening1 := Opening{
			Msg:  msg1,
			Mask: fn.Some(mask),
		}
		opening2 := Opening{
			Msg:  msg2,
			Mask: fn.Some(mask),
		}

		commitment1 := NewCommitment(opening1)
		commitment2 := NewCommitment(opening2)

		// Different messages should produce different commitments.
		require.NotEqual(
			t, commitment1, commitment2,
			"different messages produced identical commitments",
		)
	}))

	// Property 3: Commitments should be binding (cannot find different
	// openings that verify for the same commitment).
	t.Run("binding", rapid.MakeCheck(func(t *rapid.T) {
		msg1 := generateRandomBytes(t)
		msg2 := generateRandomBytes(t)
		mask1 := generateRandomBytes(t)
		mask2 := generateRandomBytes(t)

		// Skip if messages or masks happen to be the same
		if msg1 == msg2 || mask1 == mask2 {
			return
		}

		opening1 := Opening{
			Msg:  msg1,
			Mask: fn.Some(mask1),
		}
		opening2 := Opening{
			Msg:  msg2,
			Mask: fn.Some(mask2),
		}

		commitment := NewCommitment(opening1)

		// The commitment should not verify with a different opening
		require.False(
			t, commitment.Verify(opening2),
			"commitment verified with incorrect opening",
		)
	}))

	// Property 4: Commitments should work with optional masks (non-hiding
	// but still binding).
	t.Run("no_mask_none_hiding", rapid.MakeCheck(func(t *rapid.T) {
		msg := generateRandomBytes(t)

		opening := Opening{
			Msg:  msg,
			Mask: fn.None[[sha256.Size]byte](),
		}

		commitment := NewCommitment(opening)
		require.True(
			t, commitment.Verify(opening),
			"commitment without mask failed to verify",
		)

		// If we make another opening with the same message, then we
		// should get the same commitment, as no mask was used.
		opening2 := Opening{
			Msg:  msg,
			Mask: fn.None[[sha256.Size]byte](),
		}

		commitment2 := NewCommitment(opening2)

		require.Equal(t, commitment, commitment2)
	}))

	// Property 5: Test with custom NUMS point
	t.Run("custom_nums", rapid.MakeCheck(func(t *rapid.T) {
		msg := generateRandomBytes(t)
		mask := generateRandomBytes(t)

		// Generate a random point for testing
		privKey, _ := btcec.NewPrivateKey()
		customNUMs := privKey.PubKey()

		opening := Opening{
			Msg:  msg,
			Mask: fn.Some(mask),
			NUMS: fn.Some(*customNUMs),
		}

		commitment := NewCommitment(
			opening, WithCustomNUMS(*customNUMs),
		)

		require.True(
			t, commitment.Verify(opening),
			"commitment with custom NUMS failed to verify",
		)
	}))

	// Property 6: Same message and mask should always produce the same
	// commitment.
	t.Run("determinism", rapid.MakeCheck(func(t *rapid.T) {
		msg := generateRandomBytes(t)
		mask := generateRandomBytes(t)

		opening := Opening{
			Msg:  msg,
			Mask: fn.Some(mask),
		}

		commitment1 := NewCommitment(opening)
		commitment2 := NewCommitment(opening)

		require.Equal(
			t, commitment1, commitment2,
			"same opening produced different commitments",
		)
	}))
}
