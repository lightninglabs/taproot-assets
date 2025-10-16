package lndservices

import (
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// makeHeader creates a test block header with a unique hash based on the
// provided nonce.
func makeHeader(nonce uint32, timestamp time.Time) wire.BlockHeader {
	return wire.BlockHeader{
		Version:   1,
		PrevBlock: chainhash.Hash{},
		MerkleRoot: chainhash.Hash{
			byte(nonce), byte(nonce >> 8), byte(nonce >> 16),
			byte(nonce >> 24),
		},
		Timestamp: timestamp,
		Bits:      0x1d00ffff,
		Nonce:     nonce,
	}
}

// makeConsecutiveHeaders creates a set of consecutive block headers where each
// header's PrevBlock points to the previous header's hash.
func makeConsecutiveHeaders(startHeight uint32, count int,
	baseTime time.Time) []wire.BlockHeader {

	headers := make([]wire.BlockHeader, count)
	var prevHash chainhash.Hash

	for i := 0; i < count; i++ {
		timestamp := baseTime.Add(time.Duration(i) * 10 * time.Minute)
		header := wire.BlockHeader{
			Version:    1,
			PrevBlock:  prevHash,
			MerkleRoot: chainhash.Hash{byte(i)},
			Timestamp:  timestamp,
			Bits:       0x1d00ffff,
			Nonce:      startHeight + uint32(i),
		}
		headers[i] = header
		prevHash = header.BlockHash()
	}

	return headers
}

// TestBlockHeaderCacheBasicPutGet tests basic put and get operations by
// height and hash.
func TestBlockHeaderCacheBasicPutGet(t *testing.T) {
	t.Parallel()

	cfg := BlockHeaderCacheConfig{
		MaxSize:              100,
		PurgePercentage:      10,
		MinSettledBlockDepth: 6,
	}
	cache, err := NewBlockHeaderCache(cfg)
	require.NoError(t, err)

	now := time.Now().UTC()
	header1 := makeHeader(1, now)
	header2 := makeHeader(2, now.Add(10*time.Minute))

	// Put headers at height 100 and 106 (so 100 becomes settled).
	err = cache.Put(100, header1)
	require.NoError(t, err)

	err = cache.Put(106, header2)
	require.NoError(t, err)

	// Height 100 should now be settled (106 - 100 >= 6).
	retrieved, ok := cache.GetByHeight(100)
	require.True(t, ok)
	require.Equal(t, header1.BlockHash(), retrieved.BlockHash())

	// Get by hash should also work.
	hash1 := header1.BlockHash()
	retrievedByHash, ok := cache.GetByHash(hash1)
	require.True(t, ok)
	require.Equal(t, header1.BlockHash(), retrievedByHash.BlockHash())

	// Height 106 should not be settled yet (no blocks after it).
	retrieved, ok = cache.GetByHeight(106)
	require.False(t, ok, "unsettled block should return false")

	// Now add a block at height 112 to settle height 106.
	header3 := makeHeader(3, now.Add(20*time.Minute))
	err = cache.Put(112, header3)
	require.NoError(t, err)

	// Now height 106 should be settled.
	retrieved, ok = cache.GetByHeight(106)
	require.True(t, ok)
	require.Equal(t, header2.BlockHash(), retrieved.BlockHash())
}

// TestBlockHeaderCacheCapacity tests that the cache purges entries when it
// reaches capacity.
func TestBlockHeaderCacheCapacity(t *testing.T) {
	t.Parallel()

	cfg := BlockHeaderCacheConfig{
		MaxSize:              10,
		PurgePercentage:      30,
		MinSettledBlockDepth: 1,
	}
	cache, err := NewBlockHeaderCache(cfg)
	require.NoError(t, err)

	now := time.Now().UTC()

	// Fill the cache to capacity.
	for i := uint32(0); i < 10; i++ {
		header := makeHeader(i, now.Add(time.Duration(i)*time.Minute))
		err := cache.Put(i, header)
		require.NoError(t, err)
	}

	require.Equal(t, 10, cache.Size())

	// Add one more entry, which should trigger a purge.
	header := makeHeader(100, now.Add(100*time.Minute))
	err = cache.Put(100, header)
	require.NoError(t, err)

	// Cache should have purged ~3 entries (30% of 10), then added 1.
	// So we should have around 8 entries.
	size := cache.Size()
	require.LessOrEqual(t, size, 10, "cache should not exceed max size")
	require.GreaterOrEqual(t, size, 7, "cache should have purged entries")
}

// TestBlockHeaderCacheUnsettledVsSettled tests the unsettled vs settled
// semantics with confirmation depth.
func TestBlockHeaderCacheUnsettledVsSettled(t *testing.T) {
	t.Parallel()

	cfg := BlockHeaderCacheConfig{
		MaxSize:              100,
		PurgePercentage:      10,
		MinSettledBlockDepth: 6,
	}
	cache, err := NewBlockHeaderCache(cfg)
	require.NoError(t, err)

	now := time.Now().UTC()
	headers := makeConsecutiveHeaders(100, 20, now)

	// Add headers 100-119.
	for i, header := range headers {
		err := cache.Put(uint32(100+i), header)
		require.NoError(t, err)
	}

	// Headers 100-113 should be settled (119 - 6 = 113).
	for i := uint32(100); i <= 113; i++ {
		_, ok := cache.GetByHeight(i)
		require.True(t, ok, "height %d should be settled", i)
	}

	// Headers 114-119 should be unsettled.
	for i := uint32(114); i <= 119; i++ {
		_, ok := cache.GetByHeight(i)
		require.False(t, ok, "height %d should be unsettled", i)
	}

	// Check stats.
	stats := cache.Stats()
	require.Equal(t, 20, stats.TotalEntries)
	require.Equal(t, 14, stats.SettledEntries) // 100-113
	require.Equal(t, uint32(119), stats.MaxHeight)
}

// TestBlockHeaderCacheReorg tests reorg detection and orphaned branch
// invalidation.
func TestBlockHeaderCacheReorg(t *testing.T) {
	t.Parallel()

	cfg := BlockHeaderCacheConfig{
		MaxSize:              100,
		PurgePercentage:      10,
		MinSettledBlockDepth: 6,
	}
	cache, err := NewBlockHeaderCache(cfg)
	require.NoError(t, err)

	now := time.Now().UTC()

	// Create initial chain: headers at heights 100-110.
	originalChain := makeConsecutiveHeaders(100, 11, now)
	for i, header := range originalChain {
		err := cache.Put(uint32(100+i), header)
		require.NoError(t, err)
	}

	// Verify heights 100-104 are settled (110 - 6 = 104).
	for i := uint32(100); i <= 104; i++ {
		_, ok := cache.GetByHeight(i)
		require.True(t, ok, "height %d should be settled", i)
	}

	// Verify we have 11 entries.
	require.Equal(t, 11, cache.Size())

	// Simulate a reorg at height 105 by inserting a different header.
	reorgHeader := makeHeader(9999, now.Add(50*time.Minute))
	err = cache.Put(105, reorgHeader)
	require.NoError(t, err)

	// Heights 105-110 should have been invalidated.
	// Only heights 100-104 should remain (5 entries) plus the new 105.
	require.Equal(t, 6, cache.Size())

	// Heights 100-104 should be unsettled as the new highest block height
	// is 105 (which is not enough to settle them).
	for i := uint32(100); i <= 104; i++ {
		_, ok := cache.GetByHeight(i)
		require.False(t, ok, "height %d should not be settled", i)
	}

	// The new header at 105 should be unsettled (no blocks after it).
	_, ok := cache.GetByHeight(105)
	require.False(t, ok, "new height 105 should be unsettled")

	// Old headers at 106-110 should be gone.
	for i := uint32(106); i <= 110; i++ {
		_, ok := cache.GetByHeight(i)
		require.False(t, ok, "height %d should be invalidated", i)
	}

	// Verify the hash at 105 is the new one.
	cache.mu.RLock()
	entry := cache.byHeight[105]
	cache.mu.RUnlock()
	require.NotNil(t, entry)
	require.Equal(t, reorgHeader.BlockHash(), entry.header.BlockHash())
}

// TestBlockHeaderCacheDuplicateInsert tests that inserting the same header
// twice doesn't cause issues.
func TestBlockHeaderCacheDuplicateInsert(t *testing.T) {
	t.Parallel()

	cfg := DefaultBlockHeaderCacheConfig()
	cache, err := NewBlockHeaderCache(cfg)
	require.NoError(t, err)

	now := time.Now().UTC()
	header := makeHeader(42, now)

	err = cache.Put(100, header)
	require.NoError(t, err)

	// Insert again at same height with same header.
	err = cache.Put(100, header)
	require.NoError(t, err)

	// Should still have just 1 entry.
	require.Equal(t, 1, cache.Size())
}

// TestBlockHeaderCacheClear tests the Clear method.
func TestBlockHeaderCacheClear(t *testing.T) {
	t.Parallel()

	cfg := DefaultBlockHeaderCacheConfig()
	cache, err := NewBlockHeaderCache(cfg)
	require.NoError(t, err)

	now := time.Now().UTC()

	// Add some entries.
	for i := uint32(0); i < 10; i++ {
		header := makeHeader(i, now.Add(time.Duration(i)*time.Minute))
		err := cache.Put(i*10, header)
		require.NoError(t, err)
	}

	require.Equal(t, 10, cache.Size())

	// Clear the cache.
	cache.Clear()

	require.Equal(t, 0, cache.Size())

	stats := cache.Stats()
	require.Equal(t, 0, stats.TotalEntries)
	require.Equal(t, 0, stats.SettledEntries)
	require.Equal(t, uint32(0), stats.MaxHeight)
}

// TestBlockHeaderCacheStats tests the Stats method.
func TestBlockHeaderCacheStats(t *testing.T) {
	t.Parallel()

	cfg := BlockHeaderCacheConfig{
		MaxSize:              100,
		PurgePercentage:      10,
		MinSettledBlockDepth: 5,
	}
	cache, err := NewBlockHeaderCache(cfg)
	require.NoError(t, err)

	now := time.Now().UTC()

	// Add 15 headers starting at height 100.
	for i := uint32(0); i < 15; i++ {
		header := makeHeader(i, now.Add(time.Duration(i)*time.Minute))
		err := cache.Put(100+i, header)
		require.NoError(t, err)
	}

	stats := cache.Stats()

	// Should have 15 total entries.
	require.Equal(t, 15, stats.TotalEntries)

	// Heights 100-109 should be settled (114 - 5 = 109), that's 10 entries.
	require.Equal(t, 10, stats.SettledEntries)

	// Highest settled should be 114.
	require.Equal(t, uint32(114), stats.MaxHeight)

	// Test String method.
	statsStr := stats.String()
	require.Contains(t, statsStr, "total=15")
	require.Contains(t, statsStr, "settled=10")
	require.Contains(t, statsStr, "max_height=114")
}

// TestBlockHeaderCacheEdgeCases tests various edge cases.
func TestBlockHeaderCacheEdgeCases(t *testing.T) {
	t.Parallel()

	cfg := BlockHeaderCacheConfig{
		MaxSize:              10,
		PurgePercentage:      10,
		MinSettledBlockDepth: 6,
	}
	cache, err := NewBlockHeaderCache(cfg)
	require.NoError(t, err)

	// Get from empty cache.
	_, ok := cache.GetByHeight(100)
	require.False(t, ok)

	hash := chainhash.Hash{}
	_, ok = cache.GetByHash(hash)
	require.False(t, ok)

	// Add a single header.
	now := time.Now().UTC()
	header := makeHeader(1, now)
	err = cache.Put(100, header)
	require.NoError(t, err)

	// Should be unsettled (no confirmations).
	_, ok = cache.GetByHeight(100)
	require.False(t, ok)

	// Add header far enough ahead to settle the first one.
	header2 := makeHeader(2, now.Add(10*time.Minute))
	err = cache.Put(107, header2)
	require.NoError(t, err)

	// Now first header should be settled.
	retrieved, ok := cache.GetByHeight(100)
	require.True(t, ok)
	require.Equal(t, header.BlockHash(), retrieved.BlockHash())
}

// TestBlockHeaderCacheHeaderEntryHashField verifies that the headerEntry.hash
// field is set and used correctly, especially during invalidation and purge.
func TestBlockHeaderCacheHeaderEntryHashField(t *testing.T) {
	t.Parallel()

	cfg := BlockHeaderCacheConfig{
		MaxSize:              10,
		PurgePercentage:      50,
		MinSettledBlockDepth: 1,
	}
	cache, err := NewBlockHeaderCache(cfg)
	require.NoError(t, err)

	now := time.Now().UTC()
	header := makeHeader(123, now)
	height := uint32(5)

	// Insert header and check hash field.
	err = cache.Put(height, header)
	require.NoError(t, err)

	cache.mu.RLock()
	entry, exists := cache.byHeight[height]
	cache.mu.RUnlock()
	require.True(t, exists, "entry should exist")
	require.Equal(
		t, header.BlockHash(), entry.hash,
		"headerEntry.hash should match header.BlockHash()",
	)

	// Insert a different header at the same height to trigger
	// reorg/invalidation.
	altHeader := makeHeader(999, now.Add(1*time.Minute))
	err = cache.Put(height, altHeader)
	require.NoError(t, err)

	cache.mu.RLock()
	entry, exists = cache.byHeight[height]
	cache.mu.RUnlock()
	require.True(t, exists, "entry should exist after reorg")
	require.Equal(
		t, altHeader.BlockHash(), entry.hash,
		"headerEntry.hash should update after reorg",
	)
}

// TestBlockHeaderCacheInvalidConfig tests that invalid configurations return
// errors.
func TestBlockHeaderCacheInvalidConfig(t *testing.T) {
	t.Parallel()

	// Test PurgePercentage = 0.
	cfg := BlockHeaderCacheConfig{
		MaxSize:              100,
		PurgePercentage:      0,
		MinSettledBlockDepth: 6,
	}
	cache, err := NewBlockHeaderCache(cfg)
	require.Error(t, err)
	require.Nil(t, cache)
	require.Contains(t, err.Error(), "invalid PurgePercentage")

	// Test PurgePercentage > 100.
	cfg.PurgePercentage = 101
	cache, err = NewBlockHeaderCache(cfg)
	require.Error(t, err)
	require.Nil(t, cache)
	require.Contains(t, err.Error(), "invalid PurgePercentage")

	// Test valid edge cases.
	cfg.PurgePercentage = 1
	cache, err = NewBlockHeaderCache(cfg)
	require.NoError(t, err)
	require.NotNil(t, cache)

	cfg.PurgePercentage = 100
	cache, err = NewBlockHeaderCache(cfg)
	require.NoError(t, err)
	require.NotNil(t, cache)
}
