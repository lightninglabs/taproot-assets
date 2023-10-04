package tapdb

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExecutorOptionRetryDelay(t *testing.T) {
	t.Parallel()

	opts := defaultTxExecutorOptions()

	halfDelay := opts.initialRetryDelay / 2

	// Expect a random delay between -0.5 and +0.5 of the initial delay.
	require.InDelta(
		t, opts.initialRetryDelay, opts.randRetryDelay(0),
		float64(halfDelay),
	)

	// Expect the second attempt to be double the initial delay.
	require.InDelta(
		t, opts.initialRetryDelay*2, opts.randRetryDelay(1),
		float64(halfDelay*2),
	)

	// Expect the value to be capped at the maximum delay.
	require.Equal(t, opts.maxRetryDelay, opts.randRetryDelay(100))
}

// TestInt64PrimaryKey makes sure that we can actually store proper int64
// numbers as the primary key in our database.
func TestInt64PrimaryKey(t *testing.T) {
	t.Parallel()

	db := NewTestDB(t)
	t.Cleanup(func() {
		require.NoError(t, db.Close())
	})

	testHash, err := hex.DecodeString(
		"d6c3887fbb041e5ce486e12f7bd8cf2131b3f0705d116bf2c893ee946158" +
			"fe80",
	)
	require.NoError(t, err)
	testID := int64(9223372036854775807)

	// Insert a row with a large int64 primary key.
	_, err = db.Exec(`
		INSERT INTO assets_meta (meta_id, meta_data_hash)
		VALUES ($1, $2);
	`, testID, testHash)
	require.NoError(t, err)

	// Query the row and make sure we get the correct value back.
	var (
		storedID   int64
		storedHash []byte
	)
	err = db.QueryRow(`
		SELECT meta_id, meta_data_hash
		FROM assets_meta
		WHERE meta_id = $1;
	`, testID).Scan(&storedID, &storedHash)
	require.NoError(t, err)

	require.Equal(t, testID, storedID)
	require.Equal(t, testHash, storedHash)
}
