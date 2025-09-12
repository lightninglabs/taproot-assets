package supplycommit

import (
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/universe"
)

// SubtreeRootProof represents the root of a supply commit subtree with its main
// supply tree inclusion proof.
type SubtreeRootProof struct {
	// Type indicates the type of the supply commit subtree.
	Type SupplySubTree

	// RootNode is the root node of the supply commit subtree.
	RootNode mssmt.BranchNode

	// SupplyTreeLeafKey locates the subtree leaf node in the supply commit
	// tree.
	SupplyTreeLeafKey universe.UniverseKey

	// SupplyTreeInclusionProof proves inclusion of the subtree root in the
	// supply tree.
	SupplyTreeInclusionProof mssmt.Proof
}

// FetchSupplyCommitResult represents the complete data returned from a
// FetchSupplyCommit RPC call, containing all fields from the RPC response.
type FetchSupplyCommitResult struct {
	// RootCommitment contains the commitment transaction and output data.
	RootCommitment RootCommitment

	// SupplyLeaves contains the issuance, burn, and ignore leaves.
	SupplyLeaves SupplyLeaves

	// ChainProof contains the block header and merkle proof.
	ChainProof ChainProof

	// TxChainFeesSats is the total number of satoshis in on-chain fees
	// paid by the supply commitment transaction.
	TxChainFeesSats int64

	// IssuanceSubtreeRoot is the root of the issuance tree for the asset.
	IssuanceSubtreeRoot SubtreeRootProof

	// BurnSubtreeRoot is the root of the burn tree for the asset.
	BurnSubtreeRoot SubtreeRootProof

	// IgnoreSubtreeRoot is the root of the ignore tree for the asset.
	IgnoreSubtreeRoot SubtreeRootProof

	// SpentCommitmentOutpoint is the outpoint of the previous commitment
	// that this new commitment is spending. This is None for the very
	// first supply commitment of a grouped asset.
	SpentCommitmentOutpoint fn.Option[wire.OutPoint]
}
