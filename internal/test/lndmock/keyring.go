package lndmock

import (
	"testing"

	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightningnetwork/lnd/lnwallet"
)

// RandCommitmentKeyRing returns a commitment key ring with random keys and
// tweaks.
func RandCommitmentKeyRing(t *testing.T) lnwallet.CommitmentKeyRing {
	return lnwallet.CommitmentKeyRing{
		CommitPoint:         test.RandPubKey(t),
		LocalCommitKeyTweak: test.RandBytes(32),
		LocalHtlcKeyTweak:   test.RandBytes(32),
		LocalHtlcKey:        test.RandPubKey(t),
		RemoteHtlcKey:       test.RandPubKey(t),
		ToLocalKey:          test.RandPubKey(t),
		ToRemoteKey:         test.RandPubKey(t),
		RevocationKey:       test.RandPubKey(t),
	}
}
