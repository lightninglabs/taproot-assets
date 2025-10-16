package lndservices

import (
	"fmt"
	"sync"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

const (
	// DefaultHeaderCacheSize is the default maximum number of block
	// headers to cache.
	DefaultHeaderCacheSize = 100_000

	// DefaultPurgePercentage is the default percentage of entries to purge
	// when the cache reaches capacity (from 1 to 100).
	DefaultPurgePercentage = 10

	// DefaultMinSettledBlockDepth is the default minimum block depth
	// required before a block header is considered settled.
	DefaultMinSettledBlockDepth = 6
)

// BlockHeaderCacheConfig holds configuration parameters for the block header
// cache.
type BlockHeaderCacheConfig struct {
	// MaxSize is the maximum number of block headers to cache.
	MaxSize uint32

	// PurgePercentage is the percentage of entries to purge when the cache
	// reaches capacity (from 1 to 100, inclusive).
	PurgePercentage uint32

	// MinSettledBlockDepth is the minimum block depth required before a
	// block header is considered settled.
	MinSettledBlockDepth uint32
}

// DefaultBlockHeaderCacheConfig returns a BlockHeaderCacheConfig with default
// values.
func DefaultBlockHeaderCacheConfig() BlockHeaderCacheConfig {
	return BlockHeaderCacheConfig{
		MaxSize:              DefaultHeaderCacheSize,
		PurgePercentage:      DefaultPurgePercentage,
		MinSettledBlockDepth: DefaultMinSettledBlockDepth,
	}
}

// Validate checks that the configuration parameters are valid.
func (c *BlockHeaderCacheConfig) Validate() error {
	if c.PurgePercentage == 0 || c.PurgePercentage > 100 {
		return fmt.Errorf("invalid PurgePercentage: %d, must "+
			"be > 0 and <= 100", c.PurgePercentage)
	}

	return nil
}

// headerEntry represents a cached block header with metadata.
type headerEntry struct {
	// header is the cached block header.
	header wire.BlockHeader

	// hash is the cached block hash.
	hash chainhash.Hash

	// height is the block height of this header.
	height uint32
}

// BlockHeaderCache is a reorg-aware cache of block headers.
//
// TODO(ffranr): Once this component is stable, consider moving btcd repo.
type BlockHeaderCache struct {
	// cfg is the cache configuration.
	cfg BlockHeaderCacheConfig

	// mu protects concurrent access to the cache.
	mu sync.RWMutex

	// byHeight maps block height to header entry.
	byHeight map[uint32]*headerEntry

	// byHash maps block hash to header entry.
	byHash map[chainhash.Hash]*headerEntry

	// maxHeight tracks the highest block height we've seen.
	maxHeight uint32
}

// NewBlockHeaderCache creates a new block header cache with the given
// configuration.
func NewBlockHeaderCache(cfg BlockHeaderCacheConfig) (*BlockHeaderCache,
	error) {

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &BlockHeaderCache{
		cfg:      cfg,
		byHeight: make(map[uint32]*headerEntry),
		byHash:   make(map[chainhash.Hash]*headerEntry),
	}, nil
}

// isSettled returns whether an entry is considered settled based on
// block depth.
func (c *BlockHeaderCache) isSettled(height uint32) bool {
	settledHeight := height + c.cfg.MinSettledBlockDepth

	// If the maximum height among all seen block headers meets or exceeds
	// the settled height, this entry is considered settled.
	return settledHeight <= c.maxHeight
}

// Put adds a block header to the cache at the given height.
//
// If the insertion exceeded capacity, entries are purged first. If a
// conflicting header exists at this height, a reorg is detected and all headers
// at or above this height are invalidated.
func (c *BlockHeaderCache) Put(height uint32, header wire.BlockHeader) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	hash := header.BlockHash()

	// Check if there's already an entry at this height.
	if existing, exists := c.byHeight[height]; exists {
		existingHash := existing.hash

		// If the hashes match, this is a duplicate insertion.
		if existingHash == hash {
			return nil
		}

		// The hashes do not match, indicating a reorg. Invalidate
		// all known headers at or above this height.
		c.invalidateFromHeight(height)
	}

	// Check capacity and purge if needed.
	if uint32(len(c.byHeight)) >= c.cfg.MaxSize {
		c.purge()
	}

	// Create the new entry and store in the cache.
	entry := &headerEntry{
		header: header,
		hash:   hash,
		height: height,
	}

	c.byHeight[height] = entry
	c.byHash[hash] = entry

	// Update max height seen.
	if height > c.maxHeight {
		c.maxHeight = height
	}

	return nil
}

// GetByHeight retrieves a block header by height. Returns ok=false if not found
// or if the entry is unsettled (to force external lookup).
func (c *BlockHeaderCache) GetByHeight(height uint32) (wire.BlockHeader, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var zero wire.BlockHeader

	entry, exists := c.byHeight[height]
	if !exists || !c.isSettled(height) {
		return zero, false
	}

	return entry.header, true
}

// GetByHash retrieves a block header by hash. Returns ok=false if not found or
// if the entry is unsettled (to force external lookup).
func (c *BlockHeaderCache) GetByHash(hash chainhash.Hash) (wire.BlockHeader,
	bool) {

	c.mu.RLock()
	defer c.mu.RUnlock()

	var zero wire.BlockHeader

	entry, exists := c.byHash[hash]
	if !exists || !c.isSettled(entry.height) {
		return zero, false
	}

	return entry.header, true
}

// invalidateFromHeight removes all entries at or above the given height,
// effectively invalidating the orphaned chain.
func (c *BlockHeaderCache) invalidateFromHeight(heightLowerBound uint32) {
	// Track new max height after entries are removed.
	var newMaxHeight uint32

	// Iterate over all entries and remove those at or above the lower
	// bound.
	for height, entry := range c.byHeight {
		// Skip entries below the lower bound.
		if height < heightLowerBound {
			// Update new max height if needed.
			if height > newMaxHeight {
				newMaxHeight = height
			}

			continue
		}

		// Remove the entry which is at or above the lower bound.
		hash := entry.hash
		delete(c.byHeight, height)
		delete(c.byHash, hash)
	}

	c.maxHeight = newMaxHeight
}

// purge removes a random set of entries from the cache at the configured
// purge percentage.
func (c *BlockHeaderCache) purge() {
	numToPurge := len(c.byHeight) * int(c.cfg.PurgePercentage) / 100
	if numToPurge == 0 {
		numToPurge = 1
	}

	// Remove entries directly from the map iteration (already random
	// order).
	maxHeightDeleted := false
	count := 0
	for height, entry := range c.byHeight {
		if count >= numToPurge {
			break
		}

		if height == c.maxHeight {
			maxHeightDeleted = true
		}

		hash := entry.hash
		delete(c.byHeight, height)
		delete(c.byHash, hash)
		count++
	}

	if !maxHeightDeleted {
		return
	}

	// Recalculate max height only if it was deleted.
	c.maxHeight = 0
	for height := range c.byHeight {
		if height > c.maxHeight {
			c.maxHeight = height
		}
	}
}

// Size returns the current number of entries in the cache.
func (c *BlockHeaderCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.byHeight)
}

// Clear removes all entries from the cache.
func (c *BlockHeaderCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.byHeight = make(map[uint32]*headerEntry)
	c.byHash = make(map[chainhash.Hash]*headerEntry)
	c.maxHeight = 0
}

// Stats returns statistics about the cache.
func (c *BlockHeaderCache) Stats() CacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	settled := 0
	for height := range c.byHeight {
		if c.isSettled(height) {
			settled++
		}
	}

	return CacheStats{
		TotalEntries:   len(c.byHeight),
		SettledEntries: settled,
		MaxHeight:      c.maxHeight,
	}
}

// CacheStats holds statistics about the block header cache.
type CacheStats struct {
	// TotalEntries is the total number of entries in the cache.
	TotalEntries int

	// SettledEntries is the number of settled entries in the cache.
	SettledEntries int

	// MaxHeight is the highest block height seen.
	MaxHeight uint32
}

// String returns a string representation of the cache stats.
func (s CacheStats) String() string {
	return fmt.Sprintf("BlockHeaderCacheStats(total=%d, settled=%d, "+
		"max_height=%d)", s.TotalEntries, s.SettledEntries,
		s.MaxHeight)
}
