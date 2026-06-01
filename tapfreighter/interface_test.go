package tapfreighter

import (
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/stretchr/testify/require"
)

// TestShouldDeliverProof exercises TransferOutput.ShouldDeliverProof,
// in particular the V2 self-send case from issue #2148, where the
// local-script-key shortcut was incorrectly skipping the auth-mailbox
// SendFragment upload — the only path that creates an AddrEvent for
// V2 reusable addresses.
func TestShouldDeliverProof(t *testing.T) {
	t.Parallel()

	priv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	pubKey := priv.PubKey()

	// A local-script-key output mimicking the result of
	// asset.DeriveUniqueScriptKey for a V2 send: TweakedScriptKey is
	// populated, PubKey is set.
	tweakedLocalKey := asset.ScriptKey{
		PubKey: pubKey,
		TweakedScriptKey: &asset.TweakedScriptKey{
			Type: asset.ScriptKeyUniquePedersen,
		},
	}

	// An un-spendable NUMS script key.
	unspendableKey := asset.ScriptKey{
		PubKey: asset.NUMSPubKey,
	}

	// A burn script key + witness pair, so asset.IsBurnKey returns
	// true.
	prevID := asset.PrevID{}
	burnPubKey := asset.DeriveBurnKey(prevID)
	burnKey := asset.ScriptKey{
		PubKey: burnPubKey,
		TweakedScriptKey: &asset.TweakedScriptKey{
			Type: asset.ScriptKeyBurn,
		},
	}
	burnWitness := asset.Witness{
		PrevID: &prevID,
	}

	authmailbox := []byte(
		proof.AuthMailboxUniRpcCourierType + "://example.org:1234",
	)
	universerpc := []byte(
		proof.UniverseRpcCourierType + "://example.org:1234",
	)

	cases := []struct {
		name string
		out  TransferOutput
		want bool
	}{
		// The regression from issue #2148: V2 self-send (authmailbox
		// courier + local script key) must still deliver, since the
		// SendFragment upload is the only way a receiver-side
		// AddrEvent gets created for V2.
		{
			name: "v2 self-send delivers",
			out: TransferOutput{
				ScriptKey:        tweakedLocalKey,
				ScriptKeyLocal:   true,
				ProofCourierAddr: authmailbox,
			},
			want: true,
		},
		{
			name: "v2 remote send delivers",
			out: TransferOutput{
				ScriptKey:        tweakedLocalKey,
				ScriptKeyLocal:   false,
				ProofCourierAddr: authmailbox,
			},
			want: true,
		},
		// V0/V1 self-send must keep its existing shortcut: the
		// wallet-tx watcher creates the event locally, so we don't
		// need to push a proof.
		{
			name: "v0/v1 self-send skips delivery",
			out: TransferOutput{
				ScriptKey:        tweakedLocalKey,
				ScriptKeyLocal:   true,
				ProofCourierAddr: universerpc,
			},
			want: false,
		},
		{
			name: "v0/v1 remote send delivers",
			out: TransferOutput{
				ScriptKey:        tweakedLocalKey,
				ScriptKeyLocal:   false,
				ProofCourierAddr: universerpc,
			},
			want: true,
		},
		{
			name: "unspendable script key skips delivery",
			out: TransferOutput{
				ScriptKey:        unspendableKey,
				ProofCourierAddr: authmailbox,
			},
			want: false,
		},
		{
			name: "burn output skips delivery",
			out: TransferOutput{
				ScriptKey:        burnKey,
				ProofCourierAddr: authmailbox,
				WitnessData:      []asset.Witness{burnWitness},
			},
			want: false,
		},
		{
			name: "empty courier addr skips delivery",
			out: TransferOutput{
				ScriptKey:      tweakedLocalKey,
				ScriptKeyLocal: false,
			},
			want: false,
		},
		{
			name: "completed delivery skips re-delivery",
			out: TransferOutput{
				ScriptKey:             tweakedLocalKey,
				ScriptKeyLocal:        false,
				ProofCourierAddr:      authmailbox,
				ProofDeliveryComplete: fn.Some(true),
			},
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := tc.out.ShouldDeliverProof()
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}
