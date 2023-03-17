package taropsbt

import (
	"github.com/lightninglabs/taro/address"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightningnetwork/lnd/keychain"
)

// FromAddress creates an empty virtual transaction packet from the given
// address. Because sending to an address is always non-interactive, a change
// output is also added to the packet.
func FromAddress(receiverAddr *address.Taro, outputIndex uint32) *VPacket {
	pkt := &VPacket{
		Inputs: []*VInput{{
			PrevID: asset.PrevID{
				ID: receiverAddr.ID(),
			},
		}},
		Outputs:     make([]*VOutput, 2),
		ChainParams: receiverAddr.ChainParams,
	}

	// If we are sending the full value of the input asset, or sending a
	// collectible, we will need to create a split with un-spendable change.
	// Since we don't have any inputs selected yet, we'll use the NUMS
	// script key to avoid deriving a new key for each funding attempt. If
	// we need a change output, this un-spendable script key will be
	// identified as such and replaced with a real one during the funding
	// process.
	pkt.Outputs[0] = &VOutput{
		Amount:            0,
		IsSplitRoot:       true,
		AnchorOutputIndex: 0,
		ScriptKey:         asset.NUMSScriptKey,
	}

	// The output at index 1 is always the receiver's output.
	pkt.Outputs[1] = &VOutput{
		Amount:            receiverAddr.Amount,
		Interactive:       false,
		AnchorOutputIndex: outputIndex,
		ScriptKey: asset.NewScriptKey(
			&receiverAddr.ScriptKey,
		),
		AnchorOutputInternalKey: &receiverAddr.InternalKey,
	}

	return pkt
}

// ForInteractiveSend creates a virtual transaction packet for sending an output
// to a receiver in an interactive manner. Only one, interactive output is
// created. If the amount is not the full input amount, a change output will be
// added by the funding API.
func ForInteractiveSend(id asset.ID, amount uint64, scriptAddr asset.ScriptKey,
	outputIndex uint32, anchorInternalKey keychain.KeyDescriptor,
	chainParams *address.ChainParams) *VPacket {

	vPkt := &VPacket{
		Inputs: []*VInput{{
			PrevID: asset.PrevID{
				ID: id,
			},
		}},
		Outputs: []*VOutput{{
			Amount:            amount,
			Interactive:       true,
			AnchorOutputIndex: outputIndex,
			ScriptKey:         scriptAddr,
		}},
		ChainParams: chainParams,
	}
	vPkt.Outputs[0].SetAnchorInternalKey(
		anchorInternalKey, chainParams.HDCoinType,
	)

	return vPkt
}
