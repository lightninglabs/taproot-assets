package tapchannel

import (
	"sync"

	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/proof"
)

// spenderLeafWarnings records the channels warned about by
// warnMissingSpenderLeaves, so each is warned about only once.
var spenderLeafWarnings sync.Map

// warnMissingSpenderLeaves warns, once per channel, that a commitment of an
// asset channel carries no spender leaves while a proof activation height is
// set. Transition proofs anchored from that height on must carry spender
// proofs, which a transaction spending such a commitment can't provide. It
// returns true if it warned.
func warnMissingSpenderLeaves(chanPoint wire.OutPoint,
	features STXOFeatures) bool {

	if features.Spender {
		return false
	}

	activation := proof.DefaultActivationHeight()
	if activation.IsNone() {
		return false
	}
	height := activation.UnwrapOr(0)

	_, warned := spenderLeafWarnings.LoadOrStore(chanPoint, struct{}{})
	if warned {
		return false
	}

	log.Warnf("Asset channel %v: its commitment carries no spender "+
		"leaves. Transition proofs anchored from block %d on must "+
		"carry spender proofs, so the asset outputs of a transaction "+
		"spending this commitment can't be proven from then on. "+
		"Update the channel with a peer that supports the "+
		"stxo-spender feature, or close it, before block %d.",
		chanPoint, height, height)

	return true
}
