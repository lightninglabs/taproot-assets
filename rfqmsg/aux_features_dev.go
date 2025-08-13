//go:build dev

package rfqmsg

var (
	// UseNoOpHTLCs is set to true, as we want to enable it for dev builds.
	UseNoOpHTLCs = true
)
