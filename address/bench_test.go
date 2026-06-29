package address

import (
	"bytes"
	"testing"
)

// BenchmarkTapEncode measures Tap.Encode throughput. Encoding runs every
// time we serialize an address (RPC, db, wire).
func BenchmarkTapEncode(b *testing.B) {
	// Pin the version so the courier scheme matches; RandAddr picks a
	// random version and would mismatch the V0/V1 courier.
	addr, _, _ := RandAddrWithVersion(
		b, &RegressionNetTap, RandProofCourierAddr(b), V1,
	)

	var buf bytes.Buffer
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		if err := addr.Tap.Encode(&buf); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkTapDecode measures Tap.Decode throughput.
func BenchmarkTapDecode(b *testing.B) {
	// Pin the version so the courier scheme matches; RandAddr picks a
	// random version and would mismatch the V0/V1 courier.
	addr, _, _ := RandAddrWithVersion(
		b, &RegressionNetTap, RandProofCourierAddr(b), V1,
	)

	var buf bytes.Buffer
	if err := addr.Tap.Encode(&buf); err != nil {
		b.Fatal(err)
	}
	raw := buf.Bytes()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var decoded Tap
		if err := decoded.Decode(bytes.NewReader(raw)); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkEncodeAddress measures the cost of bech32m-encoding an address —
// the form returned to clients.
func BenchmarkEncodeAddress(b *testing.B) {
	// Pin the version so the courier scheme matches; RandAddr picks a
	// random version and would mismatch the V0/V1 courier.
	addr, _, _ := RandAddrWithVersion(
		b, &RegressionNetTap, RandProofCourierAddr(b), V1,
	)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := addr.Tap.EncodeAddress()
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkDecodeAddress measures the cost of parsing a bech32m address
// string back to a Tap address — the inverse of EncodeAddress, hit on every
// inbound send / receive.
func BenchmarkDecodeAddress(b *testing.B) {
	// Pin the version so the courier scheme matches; RandAddr picks a
	// random version and would mismatch the V0/V1 courier.
	addr, _, _ := RandAddrWithVersion(
		b, &RegressionNetTap, RandProofCourierAddr(b), V1,
	)

	encoded, err := addr.Tap.EncodeAddress()
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := DecodeAddress(encoded, &RegressionNetTap)
		if err != nil {
			b.Fatal(err)
		}
	}
}
