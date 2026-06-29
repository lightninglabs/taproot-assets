package asset

import (
	"bytes"
	"testing"
)

// BenchmarkAssetCopy measures the cost of Asset.Copy for the two common
// shapes: a freshly-minted Normal asset (no PrevWitnesses) and a Collectible
// transferred once (one PrevWitness with a key-spend signature).
func BenchmarkAssetCopy(b *testing.B) {
	for _, tc := range []struct {
		name string
		a    *Asset
	}{
		{"normal-fresh", RandAsset(b, Normal)},
		{"collectible-fresh", RandAsset(b, Collectible)},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = tc.a.Copy()
			}
		})
	}
}

// BenchmarkAssetEncode measures TLV-encoding throughput. Encoding runs on
// every wire send and every proof append.
func BenchmarkAssetEncode(b *testing.B) {
	for _, tc := range []struct {
		name string
		a    *Asset
	}{
		{"normal", RandAsset(b, Normal)},
		{"collectible", RandAsset(b, Collectible)},
	} {
		b.Run(tc.name, func(b *testing.B) {
			var buf bytes.Buffer
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				buf.Reset()
				if err := tc.a.Encode(&buf); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkAssetDecode measures the inverse of BenchmarkAssetEncode.
func BenchmarkAssetDecode(b *testing.B) {
	for _, tc := range []struct {
		name string
		a    *Asset
	}{
		{"normal", RandAsset(b, Normal)},
		{"collectible", RandAsset(b, Collectible)},
	} {
		b.Run(tc.name, func(b *testing.B) {
			var buf bytes.Buffer
			if err := tc.a.Encode(&buf); err != nil {
				b.Fatal(err)
			}
			raw := buf.Bytes()

			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				var decoded Asset
				err := decoded.Decode(bytes.NewReader(raw))
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkWitnessEncode measures TLV-encoding for a single Witness — hit
// on every PrevWitness round-trip during proof and asset wire transfer.
func BenchmarkWitnessEncode(b *testing.B) {
	a := RandAsset(b, Normal)
	if len(a.PrevWitnesses) == 0 {
		b.Fatal("expected at least one prev witness")
	}
	w := a.PrevWitnesses[0]

	var buf bytes.Buffer
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		if err := w.Encode(&buf); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkWitnessDecode is the inverse of BenchmarkWitnessEncode.
func BenchmarkWitnessDecode(b *testing.B) {
	a := RandAsset(b, Normal)
	if len(a.PrevWitnesses) == 0 {
		b.Fatal("expected at least one prev witness")
	}
	w := a.PrevWitnesses[0]

	var buf bytes.Buffer
	if err := w.Encode(&buf); err != nil {
		b.Fatal(err)
	}
	raw := buf.Bytes()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var decoded Witness
		if err := decoded.Decode(bytes.NewReader(raw)); err != nil {
			b.Fatal(err)
		}
	}
}
