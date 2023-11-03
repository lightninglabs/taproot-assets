//go:build itest

package tapdb

// StatsCacheDuration is the duration for which the stats cache is valid. For
// itests, we reduce this to pretty much nothing.
const StatsCacheDuration = 0
