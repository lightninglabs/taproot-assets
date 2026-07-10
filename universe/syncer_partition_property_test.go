package universe

import (
	"testing"

	"pgregory.net/rapid"
)

// proofTypeGen generates any ProofType, including Unspecified — the
// partition must handle that class too (by dropping it, matching
// pre-partition uniIdSyncFilter behaviour).
var proofTypeGen = rapid.SampledFrom([]ProofType{
	ProofTypeUnspecified,
	ProofTypeIssuance,
	ProofTypeTransfer,
})

// rootGen produces a Root with a random proof type. The other fields
// stay zero because partitionByProofType only inspects ID.ProofType.
var rootGen = rapid.Custom(func(t *rapid.T) Root {
	return Root{
		ID: Identifier{
			ProofType: proofTypeGen.Draw(t, "proof_type"),
		},
	}
})

var rootSliceGen = rapid.SliceOfN(rootGen, 0, 32)

// TestPartitionByProofType_Soundness pins that every root in a
// bucket carries the matching proof type.
func TestPartitionByProofType_Soundness(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		roots := rootSliceGen.Draw(t, "roots")
		sorted := partitionByProofType(roots)

		for _, r := range sorted.Issuance {
			if r.ID.ProofType != ProofTypeIssuance {
				t.Fatalf("issuance bucket contains %v",
					r.ID.ProofType)
			}
		}
		for _, r := range sorted.Transfer {
			if r.ID.ProofType != ProofTypeTransfer {
				t.Fatalf("transfer bucket contains %v",
					r.ID.ProofType)
			}
		}
		for _, r := range sorted.Other {
			switch r.ID.ProofType {
			case ProofTypeIssuance, ProofTypeTransfer:
				t.Fatalf("other bucket contains %v",
					r.ID.ProofType)
			case ProofTypeUnspecified, ProofTypeIgnore,
				ProofTypeBurn, ProofTypeMintSupply:
				// Expected in Other.
			}
		}
	})
}

// TestPartitionByProofType_Totality pins that every input root ends
// up in exactly one bucket. Non-issuance/non-transfer types land in
// Other rather than being silently dropped, so an explicit-lookup
// caller driving an unusual proof type still gets processed.
func TestPartitionByProofType_Totality(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		roots := rootSliceGen.Draw(t, "roots")
		sorted := partitionByProofType(roots)

		var wantIssuance, wantTransfer, wantOther int
		for _, r := range roots {
			switch r.ID.ProofType {
			case ProofTypeIssuance:
				wantIssuance++
			case ProofTypeTransfer:
				wantTransfer++
			case ProofTypeUnspecified, ProofTypeIgnore,
				ProofTypeBurn, ProofTypeMintSupply:
				wantOther++
			}
		}

		if len(sorted.Issuance) != wantIssuance {
			t.Fatalf("issuance count: got=%d want=%d",
				len(sorted.Issuance), wantIssuance)
		}
		if len(sorted.Transfer) != wantTransfer {
			t.Fatalf("transfer count: got=%d want=%d",
				len(sorted.Transfer), wantTransfer)
		}
		if len(sorted.Other) != wantOther {
			t.Fatalf("other count: got=%d want=%d",
				len(sorted.Other), wantOther)
		}
	})
}

// TestPartitionByProofType_OrderPreserving pins that within a bucket
// the relative order of the input is preserved. This matters if a
// caller depends on stable iteration (e.g. deterministic bench
// results or replay-of-logs debugging).
func TestPartitionByProofType_OrderPreserving(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		roots := rootSliceGen.Draw(t, "roots")

		// Tag each root with its input index via AssetID's first
		// byte, so we can check the survivors keep monotonic order
		// within each bucket.
		for i := range roots {
			roots[i].ID.AssetID[0] = byte(i)
		}

		sorted := partitionByProofType(roots)

		checkMonotonic := func(bucket []Root, name string) {
			for i := 1; i < len(bucket); i++ {
				if bucket[i-1].ID.AssetID[0] >=
					bucket[i].ID.AssetID[0] {

					t.Fatalf("%s bucket lost order at %d",
						name, i)
				}
			}
		}
		checkMonotonic(sorted.Issuance, "issuance")
		checkMonotonic(sorted.Transfer, "transfer")
		checkMonotonic(sorted.Other, "other")
	})
}
