//go:build !itest

package tapdb

import "time"

// StatsCacheDuration is the duration for which the stats cache is valid.
const StatsCacheDuration = time.Minute * 30
