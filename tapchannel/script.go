package tapchannel

import (
	"github.com/btcsuite/btcd/txscript"
	"github.com/lightningnetwork/lnd/input"
)

// anyoneCanSpendScript is a simple script that allows anyone to spend the
// output.
func anyoneCanSpendScript() []byte {
	return []byte{txscript.OP_TRUE}
}

// FundingScriptTree is a struct that contains the funding script tree for a
// custom channel.
type FundingScriptTree struct {
	input.ScriptTree
}

// NewFundingScriptTree creates a new funding script tree for a custom channel
// asset-level script key. The script tree is constructed with a simple OP_TRUE
// script that allows anyone to spend the output. This simplifies the funding
// process as no signatures for the asset-level witnesses need to be exchanged.
// This is still safe because the BTC level multi-sig output is still protected
// by a 2-of-2 MuSig2 output.
func NewFundingScriptTree() *FundingScriptTree {
	// First, we'll generate our OP_TRUE script.
	fundingScript := anyoneCanSpendScript()
	fundingTapLeaf := txscript.NewBaseTapLeaf(fundingScript)

	// With the funding script derived, we'll now create the tapscript tree
	// from it.
	tapscriptTree := txscript.AssembleTaprootScriptTree(fundingTapLeaf)
	tapScriptRoot := tapscriptTree.RootNode.TapHash()

	// Finally, we'll make the funding output script which actually uses a
	// NUMs key to force a script path only.
	fundingOutputKey := txscript.ComputeTaprootOutputKey(
		&input.TaprootNUMSKey, tapScriptRoot[:],
	)

	return &FundingScriptTree{
		ScriptTree: input.ScriptTree{
			InternalKey:   &input.TaprootNUMSKey,
			TaprootKey:    fundingOutputKey,
			TapscriptTree: tapscriptTree,
			TapscriptRoot: tapScriptRoot[:],
		},
	}
}
