package universe

import (
	"testing"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"pgregory.net/rapid"
)

// baseLeafKeyGen returns a rapid generator that produces a random
// BaseLeafKey. Each draw allocates a fresh *asset.ScriptKey — the same
// shape that surfaces the pointer-identity SetDiff bug in practice.
var baseLeafKeyGen = rapid.Custom(func(t *rapid.T) BaseLeafKey {
	return BaseLeafKey{
		OutPoint: asset.OutPointGen.Draw(t, "outpoint"),
		ScriptKey: fn.Ptr(asset.NewScriptKey(
			asset.PubKeyGen.Draw(t, "script_key"),
		)),
	}
})

// leafKeySliceGen returns a random slice of LeafKey with up to 16
// entries. The size cap keeps rapid's shrinker responsive without
// meaningfully weakening the properties — the invariants are
// structural, not size-dependent.
var leafKeySliceGen = rapid.Custom(func(t *rapid.T) []LeafKey {
	keys := rapid.SliceOfN(baseLeafKeyGen, 0, 16).Draw(t, "keys")
	out := make([]LeafKey, len(keys))
	for i, k := range keys {
		out[i] = k
	}
	return out
})

// clone rebuilds a leaf-key slice with freshly-allocated ScriptKey
// pointers but identical content. Used to construct the exact shape
// that would trigger the fn.SetDiff pointer-identity bug.
func clone(keys []LeafKey) []LeafKey {
	out := make([]LeafKey, len(keys))
	for i, k := range keys {
		bk := k.(BaseLeafKey)
		out[i] = BaseLeafKey{
			OutPoint: bk.OutPoint,
			ScriptKey: fn.Ptr(asset.NewScriptKey(
				bk.ScriptKey.PubKey,
			)),
		}
	}
	return out
}

// keyByContent is the reference impl: compares BaseLeafKeys by
// content (outpoint + script pubkey serialization) without going
// through UniverseKey. Used as the trusted oracle in the extensional
// property.
func keyByContent(k LeafKey) [32 + 33]byte {
	bk := k.(BaseLeafKey)
	var out [32 + 33]byte
	copy(out[:32], bk.OutPoint.Hash[:])
	// The outpoint index folds into the script pubkey slot because
	// this key is only used for equivalence checks in tests, not for
	// on-disk lookup — collisions between different (outpoint index,
	// script key) pairs are astronomically unlikely for random inputs.
	copy(out[32:65], bk.ScriptKey.PubKey.SerializeCompressed())
	out[32] ^= byte(bk.OutPoint.Index)
	return out
}

// TestDiffLeafKeys_Subset asserts that every survivor of the diff
// appears somewhere in remote, matched by content.
func TestDiffLeafKeys_Subset(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		remote := leafKeySliceGen.Draw(t, "remote")
		local := leafKeySliceGen.Draw(t, "local")

		remoteContent := make(map[[65]byte]struct{}, len(remote))
		for _, k := range remote {
			remoteContent[keyByContent(k)] = struct{}{}
		}

		for _, k := range diffLeafKeys(remote, local) {
			if _, ok := remoteContent[keyByContent(k)]; !ok {
				t.Fatalf("diff contains key not in remote: %v",
					k)
			}
		}
	})
}

// TestDiffLeafKeys_Subsequence asserts that survivors keep their
// relative order from remote. The syncer's error attribution loop
// depends on this at syncer.go:436.
func TestDiffLeafKeys_Subsequence(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		remote := leafKeySliceGen.Draw(t, "remote")
		local := leafKeySliceGen.Draw(t, "local")

		diff := diffLeafKeys(remote, local)
		j := 0
		for _, k := range remote {
			if j < len(diff) &&
				keyByContent(diff[j]) == keyByContent(k) {

				j++
			}
		}

		if j != len(diff) {
			t.Fatalf("diff is not a subsequence of remote "+
				"(matched %d of %d)", j, len(diff))
		}
	})
}

// TestDiffLeafKeys_ExtensionalReference asserts that the content
// diff agrees with a naive reference impl comparing by (outpoint,
// pubkey) directly. Extensional: same input → same output as a
// slower, structurally simpler routine.
func TestDiffLeafKeys_ExtensionalReference(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		remote := leafKeySliceGen.Draw(t, "remote")
		local := leafKeySliceGen.Draw(t, "local")

		localContent := make(map[[65]byte]struct{}, len(local))
		for _, k := range local {
			localContent[keyByContent(k)] = struct{}{}
		}

		var expected []LeafKey
		for _, k := range remote {
			if _, ok := localContent[keyByContent(k)]; !ok {
				expected = append(expected, k)
			}
		}

		got := diffLeafKeys(remote, local)
		if len(got) != len(expected) {
			t.Fatalf("length mismatch: got=%d want=%d",
				len(got), len(expected))
		}
		for i := range got {
			if keyByContent(got[i]) != keyByContent(expected[i]) {
				t.Fatalf("mismatch at %d: got=%v want=%v",
					i, got[i], expected[i])
			}
		}
	})
}

// TestDiffLeafKeys_PointerInvariant asserts the exact invariant that
// motivates this PR: for any local slice, if remote is a
// content-identical clone with fresh pointer addresses, the diff is
// empty. Regression against issue #2026.
func TestDiffLeafKeys_PointerInvariant(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		local := leafKeySliceGen.Draw(t, "local")
		remote := clone(local)

		got := diffLeafKeys(remote, local)
		if len(got) != 0 {
			t.Fatalf("expected empty diff for pointer-reallocated "+
				"clone, got %d entries", len(got))
		}
	})
}
