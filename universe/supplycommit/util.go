package supplycommit

import (
	"context"
	"fmt"

	"github.com/lightningnetwork/lnd/fn/v2"
)

// CalcTotalOutstandingSupply calculates the total outstanding supply from the
// given supply subtrees.
func CalcTotalOutstandingSupply(ctx context.Context,
	supplySubtrees SupplyTrees) fn.Result[uint64] {

	var total uint64

	// Add the total minted amount if we have a mint tree.
	if mintTree, ok := supplySubtrees[MintTreeType]; ok {
		root, err := mintTree.Root(ctx)
		if err != nil {
			return fn.Err[uint64](fmt.Errorf("unable to "+
				"extract mint tree root: %w", err))
		}

		total = root.NodeSum()
	}

	// Return early if there's no minted supply, ignore the other subtrees.
	if total == 0 {
		return fn.Ok[uint64](0)
	}

	// Subtract the total burned amount if we have a burn tree.
	if burnTree, ok := supplySubtrees[BurnTreeType]; ok {
		root, err := burnTree.Root(ctx)
		if err != nil {
			return fn.Err[uint64](fmt.Errorf("unable to "+
				"extract burn tree root: %w", err))
		}

		burned := root.NodeSum()
		if burned > total {
			return fn.Err[uint64](fmt.Errorf("total burned %d "+
				"exceeds total outstanding %d", burned, total))
		}

		total -= burned
	}

	// Subtract the total ignored amount if we have an ignore tree.
	if ignoreTree, ok := supplySubtrees[IgnoreTreeType]; ok {
		root, err := ignoreTree.Root(ctx)
		if err != nil {
			return fn.Err[uint64](fmt.Errorf("unable to "+
				"extract ignore tree root: %w", err))
		}

		ignored := root.NodeSum()
		if ignored > total {
			return fn.Err[uint64](fmt.Errorf("total ignored %d "+
				"exceeds total outstanding %d", ignored, total))
		}

		total -= ignored
	}

	return fn.Ok[uint64](total)
}
