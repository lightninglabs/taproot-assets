package tapchannel

import (
	"bytes"
	"testing"

	cmsg "github.com/lightninglabs/taproot-assets/tapchannelmsg"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lnwallet"
)

// BenchmarkCommitmentBlob measures encoding a commitment blob that carries
// asset proofs for a balance output and several HTLC outputs, which is done
// on every commitment update.
func BenchmarkCommitmentBlob(b *testing.B) {
	const numHtlcs = 10

	p := randProof(b)
	newOutput := func() *cmsg.AssetOutput {
		return cmsg.NewAssetOutput(p.Asset.ID(), p.Asset.Amount, p)
	}

	outgoing := make(map[input.HtlcIndex][]*cmsg.AssetOutput, numHtlcs)
	for i := range numHtlcs {
		outgoing[input.HtlcIndex(i)] = []*cmsg.AssetOutput{newOutput()}
	}
	com := cmsg.NewCommitment(
		[]*cmsg.AssetOutput{newOutput()}, nil, outgoing, nil,
		lnwallet.CommitAuxLeaves{}, false,
	)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		if err := com.Encode(&buf); err != nil {
			b.Fatal(err)
		}
	}
}
