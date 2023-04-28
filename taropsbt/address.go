package taropsbt

import (
	"fmt"

	"github.com/lightninglabs/taro/address"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightningnetwork/lnd/keychain"
)

// FromAddresses creates an empty virtual transaction packet from the given
// addresses. Because sending to an address is always non-interactive, a change
// output is also added to the packet.
func FromAddresses(receiverAddrs []*address.Taro,
	firstOutputIndex uint32) (*VPacket, error) {

	// We need at least one address to send to. Any special cases or
	// interactive sends should go through the FundPacket method.
	if len(receiverAddrs) < 1 {
		return nil, fmt.Errorf("at least one address must be specified")
	}

	firstAddr := receiverAddrs[0]
	pkt := &VPacket{
		Inputs: []*VInput{{
			PrevID: asset.PrevID{
				ID: firstAddr.AssetID,
			},
		}},
		Outputs:     make([]*VOutput, 0, len(receiverAddrs)+1),
		ChainParams: firstAddr.ChainParams,
	}

	// If we are sending the full value of the input asset, or sending a
	// collectible, we will need to create a split with un-spendable change.
	// Since we don't have any inputs selected yet, we'll use the NUMS
	// script key to avoid deriving a new key for each funding attempt. If
	// we need a change output, this un-spendable script key will be
	// identified as such and replaced with a real one during the funding
	// process.
	pkt.Outputs = append(pkt.Outputs, &VOutput{
		Amount:            0,
		IsSplitRoot:       true,
		AnchorOutputIndex: 0,
		ScriptKey:         asset.NUMSScriptKey,
	})

	// We start at output index 1 because we also have the change output
	// above. We also just use continuous integers for the anchor output
	// index, but start at the first one indicated by the caller.
	for idx := range receiverAddrs {
		addr := receiverAddrs[idx]
		pkt.Outputs = append(pkt.Outputs, &VOutput{
			Amount:            addr.Amount,
			Interactive:       false,
			AnchorOutputIndex: firstOutputIndex + uint32(idx),
			ScriptKey: asset.NewScriptKey(
				&addr.ScriptKey,
			),
			AnchorOutputInternalKey: &addr.InternalKey,
		})
	}

	return pkt, nil
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

// AddOutput adds an interactive output to the given packet.
func AddOutput(pkt *VPacket, amount uint64, scriptAddr asset.ScriptKey,
	outputIndex uint32, anchorInternalKey keychain.KeyDescriptor) {

	vOut := &VOutput{
		Amount:            amount,
		Interactive:       true,
		AnchorOutputIndex: outputIndex,
		ScriptKey:         scriptAddr,
	}
	vOut.SetAnchorInternalKey(anchorInternalKey, pkt.ChainParams.HDCoinType)

	pkt.Outputs = append(pkt.Outputs, vOut)
}
