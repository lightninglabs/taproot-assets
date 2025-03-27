package tapscript

import (
	"fmt"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightningnetwork/lnd/input"
)

// AnyoneCanSpendScript is a simple script that allows anyone to spend the
// output.
func AnyoneCanSpendScript() []byte {
	return []byte{txscript.OP_TRUE}
}

// FundingScriptTree is a struct that contains the funding script tree for a
// custom channel.
type FundingScriptTree struct {
	input.ScriptTree
}

// NewChannelFundingScriptTree creates a new funding script tree for a custom
// channel asset-level script key. The script tree is constructed with a simple
// OP_TRUE script that allows anyone to spend the output. This simplifies the
// funding process as no signatures for the asset-level witnesses need to be
// exchanged. This is still safe because the BTC level multi-sig output is still
// protected by a 2-of-2 MuSig2 output.
func NewChannelFundingScriptTree() *FundingScriptTree {
	// First, we'll generate our OP_TRUE script.
	fundingScript := AnyoneCanSpendScript()
	fundingTapLeaf := txscript.NewBaseTapLeaf(fundingScript)

	// With the funding script derived, we'll now create the tapscript tree
	// from it.
	tapscriptTree := txscript.AssembleTaprootScriptTree(fundingTapLeaf)
	tapScriptRoot := tapscriptTree.RootNode.TapHash()

	// Finally, we'll make the funding output script which actually uses a
	// NUMS key to force a script path only.
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

// NewChannelFundingScriptTreeUniqueID creates a new funding script tree for a
// custom channel asset-level script key. The script tree is constructed with a
// simple OP_TRUE script that allows anyone to spend the output and another
// OP_RETURN script that makes the resulting script key unique. This simplifies
// the funding process as no signatures for the asset-level witnesses need to be
// exchanged. This is still safe because the BTC level multi-sig output is still
// protected by a 2-of-2 MuSig2 output.
func NewChannelFundingScriptTreeUniqueID(id asset.ID) (*FundingScriptTree,
	error) {

	// First, we'll generate our OP_TRUE script.
	fundingScript := AnyoneCanSpendScript()
	fundingTapLeaf := txscript.NewBaseTapLeaf(fundingScript)

	// Then we'll create the OP_RETURN leaf with the asset ID to make the
	// resulting script key unique.
	opReturnLeaf, err := asset.NewNonSpendableScriptLeaf(
		asset.OpReturnVersion, id[:],
	)
	if err != nil {
		return nil, fmt.Errorf("error deriving op return leaf: %w", err)
	}

	// With the both scripts derived, we'll now create the tapscript tree
	// from them.
	tapscriptTree := txscript.AssembleTaprootScriptTree(
		fundingTapLeaf, opReturnLeaf,
	)
	tapScriptRoot := tapscriptTree.RootNode.TapHash()

	// Finally, we'll make the funding output script which actually uses a
	// NUMS key to force a script path only.
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
	}, nil
}

// ChannelFundingSpendWitness creates a complete witness to spend the OP_TRUE
// funding script of an asset funding output.
func ChannelFundingSpendWitness(uniqueScriptKeys bool,
	assetID asset.ID) (wire.TxWitness, error) {

	fundingScriptTree := NewChannelFundingScriptTree()

	// If we're using unique script keys for multiple virtual packets with
	// different asset IDs, we need to derive a specific script tree that
	// includes the asset ID. Everything else should still work the same
	// way (the OP_TRUE leaf we spend is still at index zero).
	if uniqueScriptKeys {
		var err error
		fundingScriptTree, err = NewChannelFundingScriptTreeUniqueID(
			assetID,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to create unique "+
				"script key: %w", err)
		}
	}

	const opTrueIndex = 0
	tapscriptTree := fundingScriptTree.TapscriptTree
	ctrlBlock := tapscriptTree.LeafMerkleProofs[opTrueIndex].ToControlBlock(
		&input.TaprootNUMSKey,
	)
	ctrlBlockBytes, err := ctrlBlock.ToBytes()
	if err != nil {
		return nil, fmt.Errorf("unable to serialize control "+
			"block: %w", err)
	}

	return wire.TxWitness{
		AnyoneCanSpendScript(), ctrlBlockBytes,
	}, nil
}
