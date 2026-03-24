package tapsend

import "fmt"

const (
	// AnchorTxVersionV2 is the default anchor transaction version. We keep
	// v2 as the default to maximize propagation compatibility.
	AnchorTxVersionV2 int32 = 2

	// AnchorTxVersionV3 is the TRUC transaction version.
	AnchorTxVersionV3 int32 = 3

	// DefaultAnchorTxVersion is the transaction version used when callers
	// do not explicitly opt into a newer version.
	DefaultAnchorTxVersion = AnchorTxVersionV2
)

// AnchorTxConfig holds the configurable fields for newly constructed anchor
// transaction templates.
type AnchorTxConfig struct {
	TxVersion int32
}

// AnchorTxOption configures a newly constructed anchor transaction template.
type AnchorTxOption func(*AnchorTxConfig)

func defaultAnchorTxConfig() AnchorTxConfig {
	return AnchorTxConfig{
		TxVersion: DefaultAnchorTxVersion,
	}
}

// WithAnchorTxVersion configures the version of a newly constructed anchor
// transaction template.
func WithAnchorTxVersion(version int32) AnchorTxOption {
	return func(cfg *AnchorTxConfig) {
		cfg.TxVersion = version
	}
}

// ResolveAnchorTxVersion validates an anchor transaction version and applies
// the default if none was specified.
func ResolveAnchorTxVersion(version int32) (int32, error) {
	switch version {
	case 0, DefaultAnchorTxVersion:
		return DefaultAnchorTxVersion, nil

	case AnchorTxVersionV3:
		return AnchorTxVersionV3, nil

	default:
		return 0, fmt.Errorf("unknown anchor tx version: %d", version)
	}
}
