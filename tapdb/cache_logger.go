package tapdb

import "sync/atomic"

// cacheLogger is used to log the hit/miss ratio of a given universe cache.
// Callers can mark a cache hit, or cache miss via exposed methods. Every 100th
// call to either method will trigger a log message to logs the hit/miss ratio
// along with the name of the cache.
type cacheLogger struct {
	name string

	hit  atomic.Int64
	miss atomic.Int64
}

// newCacheLogger returns a new cacheLogger with the given name.
func newCacheLogger(name string) *cacheLogger {
	return &cacheLogger{
		name: name,
	}
}

// Hit increments the hit counter for the cacheLogger. Every 100th call to this
// method will trigger a log message.
func (c *cacheLogger) Hit() {
	c.hit.Add(1)
	c.log()
}

// Miss increments the miss counter for the cacheLogger. Every 100th call to
// this method will trigger a log message.
func (c *cacheLogger) Miss() {
	c.miss.Add(1)
	c.log()
}

// log logs the hit/miss ratio of the cacheLogger. It is called every 100th
// time a hit or miss is recorded.
func (c *cacheLogger) log() {
	if (c.hit.Load()+c.miss.Load())%100 != 0 {
		return
	}

	hit := c.hit.Load()
	miss := c.miss.Load()
	total := hit + miss
	ratio := float64(hit) / float64(total) * 100

	log.Infof("db cache %s: %d hits, %d misses, %.2f%% hit ratio",
		c.name, hit, miss, ratio)
}
