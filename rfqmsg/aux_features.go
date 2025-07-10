//go:build !dev

package rfqmsg

var (
	// UseNoOpHTLCs is set to false, as we don't want to enable it for
	// production builds.
	UseNoOpHTLCs = false
)
