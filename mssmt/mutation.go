package mssmt

import "fmt"

// mutKind identifies which storage write a queued mutation represents.
type mutKind uint8

const (
	insertBranchOp mutKind = iota
	deleteBranchOp
	insertLeafOp
	deleteLeafOp
	insertCompactedLeafOp
	deleteCompactedLeafOp
)

// mutation is a deferred storage write. Insert/InsertMany on both
// FullTree and CompactedTree separate their read-only descent (which
// fetches children and builds a new tree in memory, accumulating
// existingSum for overflow accounting) from the impure write-out, so
// the overflow check can run between them and reject the batch
// atomically — nothing has touched storage yet.
//
// Each mutation carries the minimum data the corresponding TreeStore
// write needs. Only one of the typed payload fields is populated per
// mutation; the kind selects which.
type mutation struct {
	kind mutKind

	// hash is the storage key for delete* operations.
	hash NodeHash

	// branch / leaf / compLeaf are the typed payloads for insert*
	// operations.
	branch   *BranchNode
	leaf     *LeafNode
	compLeaf *CompactedLeafNode
}

// apply dispatches the mutation to the underlying transaction.
func (m mutation) apply(tx TreeStoreUpdateTx) error {
	switch m.kind {
	case insertBranchOp:
		return tx.InsertBranch(m.branch)
	case deleteBranchOp:
		return tx.DeleteBranch(m.hash)
	case insertLeafOp:
		return tx.InsertLeaf(m.leaf)
	case deleteLeafOp:
		return tx.DeleteLeaf(m.hash)
	case insertCompactedLeafOp:
		return tx.InsertCompactedLeaf(m.compLeaf)
	case deleteCompactedLeafOp:
		return tx.DeleteCompactedLeaf(m.hash)
	default:
		return fmt.Errorf("mssmt: unknown mutation kind %d", m.kind)
	}
}

// applyAll flushes a queue of mutations to the underlying transaction
// in order. Any error short-circuits the flush; callers should expect
// to have done partial work in that case, the same as if multiple
// direct tx writes had been issued.
func applyAll(tx TreeStoreUpdateTx, muts []mutation) error {
	for i := range muts {
		if err := muts[i].apply(tx); err != nil {
			return err
		}
	}
	return nil
}

// insertBranch enqueues an InsertBranch.
func insertBranch(muts *[]mutation, b *BranchNode) {
	*muts = append(*muts, mutation{kind: insertBranchOp, branch: b})
}

// deleteBranch enqueues a DeleteBranch.
func deleteBranch(muts *[]mutation, h NodeHash) {
	*muts = append(*muts, mutation{kind: deleteBranchOp, hash: h})
}

// insertLeaf enqueues an InsertLeaf.
func insertLeaf(muts *[]mutation, l *LeafNode) {
	*muts = append(*muts, mutation{kind: insertLeafOp, leaf: l})
}

// deleteLeaf enqueues a DeleteLeaf. The argument is the leaf's
// storage key (which for leaves is the insertion key itself).
func deleteLeaf(muts *[]mutation, k NodeHash) {
	*muts = append(*muts, mutation{kind: deleteLeafOp, hash: k})
}

// insertCompactedLeaf enqueues an InsertCompactedLeaf.
func insertCompactedLeaf(muts *[]mutation, cl *CompactedLeafNode) {
	*muts = append(*muts, mutation{
		kind: insertCompactedLeafOp, compLeaf: cl,
	})
}

// deleteCompactedLeaf enqueues a DeleteCompactedLeaf.
func deleteCompactedLeaf(muts *[]mutation, h NodeHash) {
	*muts = append(*muts, mutation{kind: deleteCompactedLeafOp, hash: h})
}
