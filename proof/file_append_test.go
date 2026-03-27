package proof

import (
	"bytes"
	"crypto/sha256"
	"strconv"
	"testing"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/stretchr/testify/require"
)

// buildProofChain creates a proof file with n genesis proofs appended
// sequentially. Each proof is independently generated to simulate a realistic
// chain of distinct proofs.
func buildProofChain(t testing.TB, n int) (*File, []Proof) {
	t.Helper()

	proofs := make([]Proof, n)
	for i := range proofs {
		amt := uint64(i + 1)
		proofs[i], _ = genRandomGenesisWithProof(
			t, asset.Normal, &amt, nil, true, nil, nil, nil, nil,
			asset.V0,
		)
	}

	f := NewEmptyFile(V0)
	for i := range proofs {
		require.NoError(t, f.AppendProof(proofs[i]))
	}

	return f, proofs
}

// encodeFile encodes the file to a byte slice.
func encodeFile(t testing.TB, f *File) []byte {
	t.Helper()

	var buf bytes.Buffer
	require.NoError(t, f.Encode(&buf))

	return buf.Bytes()
}

// TestFileAppendProofChainIntegrity verifies that after appending proofs one
// by one the chained hashes remain consistent with a file built all at once.
func TestFileAppendProofChainIntegrity(t *testing.T) {
	t.Parallel()

	const numProofs = 10

	proofs := make([]Proof, numProofs)
	for i := range proofs {
		amt := uint64(i + 1)
		proofs[i], _ = genRandomGenesisWithProof(
			t, asset.Normal, &amt, nil, true, nil, nil, nil, nil,
			asset.V0,
		)
	}

	// Build the reference file from all proofs at once.
	reference, err := NewFile(V0, proofs...)
	require.NoError(t, err)

	// Build the same file by appending one proof at a time.
	incremental := NewEmptyFile(V0)
	for i := range proofs {
		require.NoError(t, incremental.AppendProof(proofs[i]))
	}

	require.Equal(t, reference.NumProofs(), incremental.NumProofs())

	// Every stored hash must match between the two files.
	for i := range reference.proofs {
		require.Equal(
			t, reference.proofs[i].hash, incremental.proofs[i].hash,
			"hash mismatch at index %d", i,
		)
		require.Equal(
			t, reference.proofs[i].proofBytes,
			incremental.proofs[i].proofBytes,
			"proof bytes mismatch at index %d", i,
		)
	}
}

// TestFileAppendRawProofChainIntegrity verifies that AppendProofRaw produces
// the same chained hashes as AppendProof for the same proof bytes.
func TestFileAppendRawProofChainIntegrity(t *testing.T) {
	t.Parallel()

	const numProofs = 5

	proofs := make([]Proof, numProofs)
	for i := range proofs {
		amt := uint64(i + 1)
		proofs[i], _ = genRandomGenesisWithProof(
			t, asset.Normal, &amt, nil, true, nil, nil, nil, nil,
			asset.V0,
		)
	}

	typed := NewEmptyFile(V0)
	raw := NewEmptyFile(V0)

	for i := range proofs {
		require.NoError(t, typed.AppendProof(proofs[i]))

		proofBytes, err := proofs[i].Bytes()
		require.NoError(t, err)
		require.NoError(t, raw.AppendProofRaw(proofBytes))
	}

	require.Equal(t, typed.NumProofs(), raw.NumProofs())
	for i := range typed.proofs {
		require.Equal(
			t, typed.proofs[i].hash, raw.proofs[i].hash,
			"hash mismatch at index %d", i,
		)
	}
}

// TestFileAppendHashChain verifies the chained hash invariant explicitly:
// each proof's hash must equal SHA256(prev_hash || proof_bytes).
func TestFileAppendHashChain(t *testing.T) {
	t.Parallel()

	f, _ := buildProofChain(t, 8)

	var prevHash [sha256.Size]byte
	for i, hp := range f.proofs {
		expected := hashProof(hp.proofBytes, prevHash)
		require.Equal(
			t, expected, hp.hash,
			"chained hash invariant broken at index %d", i,
		)
		prevHash = hp.hash
	}
}

// TestFileAppendEncodeDecode verifies that a file built by sequential appends
// survives a full encode/decode round-trip with all hashes intact.
func TestFileAppendEncodeDecode(t *testing.T) {
	t.Parallel()

	const numProofs = 15

	f, _ := buildProofChain(t, numProofs)

	blob := encodeFile(t, f)

	decoded := NewEmptyFile(V0)
	require.NoError(t, decoded.Decode(bytes.NewReader(blob)))

	require.Equal(t, numProofs, decoded.NumProofs())
	for i := range f.proofs {
		require.Equal(
			t, f.proofs[i].hash, decoded.proofs[i].hash,
			"hash mismatch at index %d after round-trip", i,
		)
		require.Equal(
			t, f.proofs[i].proofBytes, decoded.proofs[i].proofBytes,
			"proof bytes mismatch at index %d after round-trip", i,
		)
	}
}

// TestFileAppendToExistingBlob verifies that appending a proof to an already
// encoded blob (the pattern used by AppendTransition) yields the same result
// as building the file from scratch.
func TestFileAppendToExistingBlob(t *testing.T) {
	t.Parallel()

	const numExisting = 5

	// Build a file with numExisting proofs and encode it.
	existing, proofs := buildProofChain(t, numExisting)
	blob := encodeFile(t, existing)

	// Generate the new proof to append.
	amt := uint64(numExisting + 1)
	newProof, _ := genRandomGenesisWithProof(
		t, asset.Normal, &amt, nil, true, nil, nil, nil, nil, asset.V0,
	)

	// Append via decode → AppendProof → encode (current approach).
	f := NewEmptyFile(V0)
	require.NoError(t, f.Decode(bytes.NewReader(blob)))
	require.NoError(t, f.AppendProof(newProof))

	got := encodeFile(t, f)

	// Build the reference by constructing the full file from scratch.
	allProofs := append(proofs, newProof) //nolint:gocritic
	reference, err := NewFile(V0, allProofs...)
	require.NoError(t, err)

	want := encodeFile(t, reference)

	require.Equal(t, want, got)
}

// TestFileAppendUnknownVersionRejected ensures AppendProof and AppendProofRaw
// both reject files with an unrecognised version.
func TestFileAppendUnknownVersionRejected(t *testing.T) {
	t.Parallel()

	amt := uint64(1)
	p, _ := genRandomGenesisWithProof(
		t, asset.Normal, &amt, nil, true, nil, nil, nil, nil, asset.V0,
	)
	pBytes, err := p.Bytes()
	require.NoError(t, err)

	f := NewEmptyFile(Version(255))

	require.ErrorIs(t, f.AppendProof(p), ErrUnknownVersion)
	require.ErrorIs(t, f.AppendProofRaw(pBytes), ErrUnknownVersion)
}

// TestFileAppendFirstProofUsesZeroPrevHash verifies that the first proof in a
// file is hashed against the all-zero previous hash.
func TestFileAppendFirstProofUsesZeroPrevHash(t *testing.T) {
	t.Parallel()

	amt := uint64(42)
	p, _ := genRandomGenesisWithProof(
		t, asset.Normal, &amt, nil, true, nil, nil, nil, nil, asset.V0,
	)

	f := NewEmptyFile(V0)
	require.NoError(t, f.AppendProof(p))

	pBytes, err := p.Bytes()
	require.NoError(t, err)

	var zeroPrevHash [sha256.Size]byte
	expected := hashProof(pBytes, zeroPrevHash)

	require.Equal(t, expected, f.proofs[0].hash)
}

// BenchmarkFileAppendProof measures the time and allocations for appending a
// single proof to files of increasing size. This establishes the baseline for
// the current O(1)-in-memory append but O(n) encode/decode round-trip that
// AppendTransition performs.
func BenchmarkFileAppendProof(b *testing.B) {
	sizes := []int{10, 100, 1_000, 10_000}

	for _, n := range sizes {
		n := n
		b.Run(
			// nolint:forbidigo
			func() string {
				if n < 1000 {
					return "proofs=" + strconv.Itoa(n)
				}
				return "proofs=" + strconv.Itoa(n/1000) + "k"
			}(),
			func(b *testing.B) {
				f, _ := buildProofChain(b, n)

				amt := uint64(n + 1)
				newProof, _ := genRandomGenesisWithProof(
					b, asset.Normal, &amt, nil, true, nil,
					nil, nil, nil, asset.V0,
				)

				b.ResetTimer()
				b.ReportAllocs()

				for i := 0; i < b.N; i++ {
					// Clone the file so each iteration
					// starts from the same state.
					clone := &File{
						Version: f.Version,
						proofs: make(
							[]*hashedProof,
							len(f.proofs),
						),
					}
					copy(clone.proofs, f.proofs)

					if err := clone.AppendProof(
						newProof,
					); err != nil {
						b.Fatal(err)
					}
				}
			},
		)
	}
}

// BenchmarkAppendTransitionFullRoundTrip measures the full cost of the current
// AppendTransition pattern: decode entire blob → append → encode entire blob.
// This is the hot path that needs to be optimised.
func BenchmarkAppendTransitionFullRoundTrip(b *testing.B) {
	sizes := []int{10, 100, 1_000, 5_000}

	for _, n := range sizes {
		n := n
		b.Run(
			func() string {
				if n < 1000 {
					return "proofs=" + strconv.Itoa(n)
				}
				return "proofs=" + strconv.Itoa(n/1000) + "k"
			}(),
			func(b *testing.B) {
				f, _ := buildProofChain(b, n)
				blob := encodeFile(b, f)

				amt := uint64(n + 1)
				newProof, _ := genRandomGenesisWithProof(
					b, asset.Normal, &amt, nil, true, nil,
					nil, nil, nil, asset.V0,
				)
				newProofBytes, err := newProof.Bytes()
				if err != nil {
					b.Fatal(err)
				}

				b.ResetTimer()
				b.ReportAllocs()

				for i := 0; i < b.N; i++ {
					// Simulate the current approach used
					// by AppendTransition.
					decoded := NewEmptyFile(V0)
					if err := decoded.Decode(
						bytes.NewReader(blob),
					); err != nil {
						b.Fatal(err)
					}

					if err := decoded.AppendProofRaw(
						newProofBytes,
					); err != nil {
						b.Fatal(err)
					}

					var out bytes.Buffer
					if err := decoded.Encode(&out); err != nil {
						b.Fatal(err)
					}
				}
			},
		)
	}
}

// BenchmarkFileEncodeDecode measures encode/decode throughput for files of
// increasing size, providing context for how much of the round-trip cost comes
// from serialisation alone.
func BenchmarkFileEncodeDecode(b *testing.B) {
	sizes := []int{10, 100, 1_000, 10_000}

	for _, n := range sizes {
		n := n
		b.Run(
			func() string {
				if n < 1000 {
					return "proofs=" + strconv.Itoa(n)
				}
				return "proofs=" + strconv.Itoa(n/1000) + "k"
			}(),
			func(b *testing.B) {
				f, _ := buildProofChain(b, n)
				blob := encodeFile(b, f)

				b.ResetTimer()
				b.ReportAllocs()

				for i := 0; i < b.N; i++ {
					decoded := NewEmptyFile(V0)
					if err := decoded.Decode(
						bytes.NewReader(blob),
					); err != nil {
						b.Fatal(err)
					}

					var out bytes.Buffer
					if err := decoded.Encode(&out); err != nil {
						b.Fatal(err)
					}
				}
			},
		)
	}
}
