package taropsbt

import (
	"github.com/lightninglabs/taro/address"
	"github.com/lightninglabs/taro/asset"
)

// FromAddress creates an empty virtual transaction packet from the given
// address. Because sending to an address is always non-interactive, a change
// output is also added to the packet.
func FromAddress(receiverAddr *address.Taro) *VPacket {
	pkt := &VPacket{
		Input: &VInput{
			PrevID: asset.PrevID{
				ID: receiverAddr.ID(),
			},
		},
		Outputs:     make([]*VOutput, 2),
		ChainParams: receiverAddr.ChainParams,
	}

	// If we are sending the full value of the input asset, or sending a
	// collectible, we will need to create a split with un-spendable change.
	// Since we don't have any inputs selected yet, we'll use the NUMS
	// script key to avoid deriving a new key for each funding attempt.
	pkt.Outputs[0] = &VOutput{
		Amount:            0,
		IsChange:          true,
		AnchorOutputIndex: 0,
		ScriptKey:         asset.NUMSScriptKey,
	}

	// The output at index 1 is always the receiver's output.
	pkt.Outputs[1] = &VOutput{
		Amount:            receiverAddr.Amount,
		IsChange:          false,
		Interactive:       false,
		AnchorOutputIndex: 1,
		ScriptKey: asset.NewScriptKey(
			&receiverAddr.ScriptKey,
		),
		AnchorOutputInternalKey: &receiverAddr.InternalKey,
	}

	return pkt
}
