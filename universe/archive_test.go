package universe

import (
	"context"
	"math/rand"
	"testing"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/stretchr/testify/require"
)

// mockMultiverse implements MultiverseArchive, returning
// ErrNoUniverseRoot for any unknown universe.
type mockMultiverse struct {
	knownRoots map[IdentifierKey]Root
}

func (m *mockMultiverse) UniverseRootNode(_ context.Context,
	id Identifier) (Root, error) {

	root, ok := m.knownRoots[id.Key()]
	if !ok {
		return Root{}, ErrNoUniverseRoot
	}

	return root, nil
}

func (m *mockMultiverse) RootNodes(context.Context,
	RootNodesQuery) ([]Root, error) {

	return nil, nil
}

func (m *mockMultiverse) UpsertProofLeaf(context.Context,
	Identifier, LeafKey, *Leaf,
	*proof.MetaReveal) (*Proof, error) {

	return nil, nil
}

func (m *mockMultiverse) UpsertProofLeafBatch(context.Context,
	[]*Item) error {

	return nil
}

func (m *mockMultiverse) FetchProofLeaf(context.Context,
	Identifier, LeafKey) ([]*Proof, error) {

	return nil, nil
}

func (m *mockMultiverse) DeleteUniverse(context.Context,
	Identifier) (string, error) {

	return "", nil
}

func (m *mockMultiverse) DeleteProofLeaf(context.Context,
	Identifier, LeafKey) (string, error) {

	return "", nil
}

func (m *mockMultiverse) UniverseLeafKeys(context.Context,
	UniverseLeafKeysQuery) ([]LeafKey, error) {

	return nil, nil
}

func (m *mockMultiverse) FetchLeaves(context.Context,
	[]MultiverseLeafDesc, ProofType) ([]MultiverseLeaf, error) {

	return nil, nil
}

func (m *mockMultiverse) MultiverseRootNode(context.Context,
	ProofType) (fn.Option[MultiverseRoot], error) {

	return fn.None[MultiverseRoot](), nil
}

// mockStorageBackend implements StorageBackend as a no-op.
type mockStorageBackend struct{}

func (m *mockStorageBackend) RootNode(
	context.Context) (mssmt.Node, string, error) {

	return nil, "", nil
}

func (m *mockStorageBackend) UpsertProofLeaf(context.Context,
	LeafKey, *Leaf, *proof.MetaReveal) (*Proof, error) {

	return nil, nil
}

func (m *mockStorageBackend) FetchProof(context.Context,
	LeafKey) ([]*Proof, error) {

	return nil, nil
}

func (m *mockStorageBackend) FetchKeys(context.Context,
	UniverseLeafKeysQuery) ([]LeafKey, error) {

	return nil, nil
}

func (m *mockStorageBackend) FetchLeaves(
	context.Context) ([]Leaf, error) {

	return nil, nil
}

func (m *mockStorageBackend) DeleteUniverse(
	context.Context) (string, error) {

	return "", nil
}

func (m *mockStorageBackend) DeleteProofLeaf(context.Context,
	LeafKey) (string, error) {

	return "", nil
}

// newTestArchive creates an Archive with a mock multiverse and a
// NewBaseTree that tracks how many times it's been called.
func newTestArchive(
	mv *mockMultiverse) (*Archive, *int) {

	var newTreeCalls int
	a := NewArchive(ArchiveConfig{
		NewBaseTree: func(id Identifier) StorageBackend {
			newTreeCalls++
			return &mockStorageBackend{}
		},
		Multiverse: mv,
	})

	return a, &newTreeCalls
}

func randIdentifier() Identifier {
	var id asset.ID
	//nolint:gosec
	_, _ = rand.Read(id[:])
	return Identifier{
		AssetID:   id,
		ProofType: ProofTypeIssuance,
	}
}

// TestFetchLeavesNonExistentUniverse verifies that FetchLeaves for
// a nonexistent universe returns empty results and does not allocate
// a cached backend.
func TestFetchLeavesNonExistentUniverse(t *testing.T) {
	t.Parallel()

	mv := &mockMultiverse{
		knownRoots: make(map[IdentifierKey]Root),
	}
	archive, newTreeCalls := newTestArchive(mv)

	ctx := context.Background()

	// Request leaves for many random (nonexistent) universes.
	for i := 0; i < 100; i++ {
		leaves, err := archive.FetchLeaves(ctx, randIdentifier())
		require.NoError(t, err)
		require.Nil(t, leaves)
	}

	// NewBaseTree should never have been called.
	require.Equal(t, 0, *newTreeCalls)
}

// TestFetchLeavesExistingUniverse verifies that FetchLeaves for a
// known universe does allocate a cached backend.
func TestFetchLeavesExistingUniverse(t *testing.T) {
	t.Parallel()

	id := randIdentifier()
	mv := &mockMultiverse{
		knownRoots: map[IdentifierKey]Root{
			id.Key(): {ID: id},
		},
	}
	archive, newTreeCalls := newTestArchive(mv)

	ctx := context.Background()

	leaves, err := archive.FetchLeaves(ctx, id)
	require.NoError(t, err)
	require.Nil(t, leaves) // mock returns nil

	require.Equal(t, 1, *newTreeCalls)

	// Second call should hit the cache, not allocate again.
	_, err = archive.FetchLeaves(ctx, id)
	require.NoError(t, err)
	require.Equal(t, 1, *newTreeCalls)
}
