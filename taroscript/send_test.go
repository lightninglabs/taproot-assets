package taroscript_test

import (
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/taro/address"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/commitment"
	"github.com/lightninglabs/taro/taropsbt"
	"github.com/lightninglabs/taro/taroscript"
	"github.com/stretchr/testify/require"
)

var (
	receiverExternalIdx uint32 = 2
)

type testCase struct {
	name string
	f    func(t *testing.T) error
	err  error
}

func createPacket(addr address.Taro, prevInput asset.PrevID,
	scriptKey btcec.PublicKey, inputSet commitment.InputSet,
	fullValueInteractive bool) *taropsbt.VPacket {

	inputAsset := inputSet[prevInput]
	inputs := []*taropsbt.VInput{{
		PrevID: prevInput,
	}}
	outputs := []*taropsbt.VOutput{{
		Amount:            inputAsset.Amount - addr.Amount,
		ScriptKey:         asset.NewScriptKey(&scriptKey),
		AnchorOutputIndex: 0,
		IsSplitRoot:       true,
	}, {
		Amount:            addr.Amount,
		ScriptKey:         asset.NewScriptKey(&addr.ScriptKey),
		AnchorOutputIndex: receiverExternalIdx,
	}}

	if fullValueInteractive {
		outputs = []*taropsbt.VOutput{{
			Interactive:       true,
			Amount:            addr.Amount,
			ScriptKey:         asset.NewScriptKey(&scriptKey),
			AnchorOutputIndex: receiverExternalIdx,
		}}
	}

	vPacket := &taropsbt.VPacket{
		Inputs:      inputs,
		Outputs:     outputs,
		ChainParams: addr.ChainParams,
	}
	vPacket.SetInputAsset(0, inputAsset, nil)

	return vPacket
}

func checkPreparedOutputsNonInteractive(t *testing.T, packet *taropsbt.VPacket,
	addr address.Taro, scriptKey btcec.PublicKey) {

	t.Helper()

	input := packet.Inputs[0]
	change := packet.Outputs[0]
	receiver := packet.Outputs[1]

	hasSplitCommitment, err := packet.HasSplitCommitment()
	require.NoError(t, err)
	require.True(t, hasSplitCommitment)
	require.Equal(t, *change.Asset.ScriptKey.PubKey, scriptKey)
	require.Equal(t, change.Asset.Amount, input.Asset().Amount-addr.Amount)
	if input.Asset().Amount == addr.Amount {
		require.True(t, change.Asset.IsUnspendable())
	}

	require.Equal(t, receiver.Asset.Amount, addr.Amount)
	require.Equal(t, *receiver.Asset.ScriptKey.PubKey, addr.ScriptKey)
}

func checkPreparedOutputsInteractive(t *testing.T, packet *taropsbt.VPacket,
	addr address.Taro, prevInput asset.PrevID) {

	t.Helper()

	// If we only have one output, it must be a full value interactive send.
	receiver := packet.Outputs[0]
	if len(packet.Outputs) > 1 {
		receiver = packet.Outputs[1]
	}

	receiverAsset := receiver.Asset

	require.Equal(t,
		*receiver.ScriptKey.PubKey, addr.ScriptKey,
	)
	require.Equal(t, receiverAsset.Amount, addr.Amount)
	require.Equal(t,
		*receiverAsset.ScriptKey.PubKey, addr.ScriptKey,
	)
	require.Equal(t, *receiverAsset.PrevWitnesses[0].PrevID, prevInput)
	require.Nil(t, receiverAsset.PrevWitnesses[0].TxWitness)
	require.Nil(t, receiverAsset.PrevWitnesses[0].SplitCommitment)
}

// TestPrepareOutputAssets tests the creating of split commitment data with
// different sets of split locators. The validity of locators is assumed to be
// checked earlier via areValidIndexes().
func TestPrepareOutputAssets(t *testing.T) {
	t.Parallel()

	for _, testCase := range prepareOutputAssetsTestCases {
		success := t.Run(testCase.name, func(t *testing.T) {
			err := testCase.f(t)
			require.ErrorIs(t, err, testCase.err)
		})
		if !success {
			return
		}
	}
}

var prepareOutputAssetsTestCases = []testCase{{
	name: "asset split with custom locators",
	f: func(t *testing.T) error {
		state := initSpendScenario(t)

		pkt := createPacket(
			state.address1, state.asset2PrevID,
			state.spenderScriptKey, state.asset2InputAssets, false,
		)
		err := taroscript.PrepareOutputAssets(pkt)
		require.NoError(t, err)

		checkPreparedOutputsNonInteractive(
			t, pkt, state.address1, state.spenderScriptKey,
		)
		return nil
	},
	err: nil,
}, {
	name: "full value non-interactive send with un-spendable change",
	f: func(t *testing.T) error {
		state := initSpendScenario(t)
		state.spenderScriptKey = *asset.NUMSPubKey

		pkt := createPacket(
			state.address2, state.asset2PrevID,
			state.spenderScriptKey, state.asset2InputAssets, false,
		)
		err := taroscript.PrepareOutputAssets(pkt)
		require.NoError(t, err)

		checkPreparedOutputsNonInteractive(
			t, pkt, state.address2, state.spenderScriptKey,
		)
		return nil
	},
	err: nil,
}, {
	name: "full value interactive send with un-spendable change",
	f: func(t *testing.T) error {
		state := initSpendScenario(t)
		state.spenderScriptKey = *asset.NUMSPubKey

		pkt := createPacket(
			state.address2, state.asset2PrevID,
			state.spenderScriptKey, state.asset2InputAssets, true,
		)
		return taroscript.PrepareOutputAssets(pkt)
	},
	err: commitment.ErrInvalidScriptKey,
}, {
	name: "full value interactive send with spendable change",
	f: func(t *testing.T) error {
		state := initSpendScenario(t)

		pkt := createPacket(
			state.address2, state.asset2PrevID,
			state.receiverPubKey, state.asset2InputAssets, true,
		)
		err := taroscript.PrepareOutputAssets(pkt)
		require.NoError(t, err)

		checkPreparedOutputsInteractive(
			t, pkt, state.address2, state.asset2PrevID,
		)
		return nil
	},
	err: nil,
}, {
	name: "full value non-interactive send with collectible",
	f: func(t *testing.T) error {
		state := initSpendScenario(t)
		state.spenderScriptKey = *asset.NUMSPubKey

		pkt := createPacket(
			state.address1CollectGroup,
			state.asset1CollectGroupPrevID,
			state.spenderScriptKey,
			state.asset1CollectGroupInputAssets, false,
		)
		err := taroscript.PrepareOutputAssets(pkt)
		require.NoError(t, err)

		checkPreparedOutputsNonInteractive(
			t, pkt, state.address1CollectGroup,
			state.spenderScriptKey,
		)
		return nil
	},
	err: nil,
}, {
	name: "asset split with incorrect script key",
	f: func(t *testing.T) error {
		state := initSpendScenario(t)

		pkt := createPacket(
			state.address2, state.asset2PrevID,
			state.spenderScriptKey, state.asset2InputAssets, false,
		)
		return taroscript.PrepareOutputAssets(pkt)
	},
	err: commitment.ErrInvalidScriptKey,
}}
