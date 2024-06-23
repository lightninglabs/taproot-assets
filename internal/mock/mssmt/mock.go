package mssmt

import (
	"bytes"
	"context"
	"encoding/hex"
	"math"
	"testing"

	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/json"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/stretchr/testify/require"
)

// RandLeafAmount generates a random leaf node sum amount.
func RandLeafAmount() uint64 {
	minSum := uint64(1)
	maxSum := uint64(math.MaxUint32)
	return (test.RandInt[uint64]() % maxSum) + minSum
}

// RandProof returns a random proof for testing.
func RandProof(t testing.TB) *mssmt.Proof {
	var (
		store            = mssmt.NewDefaultStore()
		tree  mssmt.Tree = mssmt.NewFullTree(store)
		key1             = test.RandHash()
		key2             = test.RandHash()
		err   error
	)
	tree, err = tree.Insert(
		context.Background(), key1, mssmt.NewLeafNode([]byte("foo"), 10),
	)
	require.NoError(t, err)
	tree, err = tree.Insert(
		context.Background(), key2, mssmt.NewLeafNode([]byte("bar"), 20),
	)
	require.NoError(t, err)

	proof, err := tree.MerkleProof(context.Background(), key2)
	require.NoError(t, err)
	return proof
}

type ValidTestCase struct {
	RootHash        string           `json:"root_hash"`
	RootSum         string           `json:"root_sum"`
	InsertedLeaves  []string         `json:"inserted_leaves"`
	DeletedLeaves   []string         `json:"deleted_leaves"`
	ReplacedLeaves  []*json.Leaf     `json:"replaced_leaves"`
	InclusionProofs []*TestProofCase `json:"inclusion_proofs"`
	ExclusionProofs []*TestProofCase `json:"exclusion_proofs"`
	Comment         string           `json:"comment"`
}

func (tc *ValidTestCase) ShouldInsert(key string) bool {
	return fn.Any(tc.InsertedLeaves, func(k string) bool {
		return k == key
	})
}

func (tc *ValidTestCase) ShouldDelete(key string) bool {
	return fn.Any(tc.DeletedLeaves, func(k string) bool {
		return k == key
	})
}

type ErrorTestCase struct {
	InsertedLeaves []string `json:"inserted_leaves"`
	Error          string   `json:"error"`
	Comment        string   `json:"comment"`
}

func (ec *ErrorTestCase) ShouldInsert(key string) bool {
	return fn.Any(ec.InsertedLeaves, func(k string) bool {
		return k == key
	})
}

type TestVectors struct {
	AllTreeLeaves  []*json.Leaf     `json:"all_tree_leaves"`
	ValidTestCases []*ValidTestCase `json:"valid_test_cases"`
	ErrorTestCases []*ErrorTestCase `json:"error_test_cases"`
}

func (tv *TestVectors) FindLeaf(key string) *json.Leaf {
	for idx := range tv.AllTreeLeaves {
		leaf := tv.AllTreeLeaves[idx]
		if leaf.Key == key {
			return leaf
		}
	}
	return nil
}

type TestProofCase struct {
	ProofKey        string `json:"proof_key"`
	CompressedProof string `json:"compressed_proof"`
}

func (tpc *TestProofCase) ToProof(t testing.TB) *mssmt.Proof {
	t.Helper()

	proofBytes, err := hex.DecodeString(tpc.CompressedProof)
	require.NoError(t, err)

	var compressedProof mssmt.CompressedProof
	err = compressedProof.Decode(bytes.NewReader(proofBytes))
	require.NoError(t, err)

	proof, err := compressedProof.Decompress()
	require.NoError(t, err)

	return proof
}
