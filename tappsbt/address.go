package tappsbt

import (
	"fmt"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightningnetwork/lnd/keychain"
)

// FromAddresses creates an empty virtual transaction packet from the given
// addresses. Because sending to an address is always non-interactive, a change
// output is also added to the packet.
func FromAddresses(receiverAddrs []*address.Tap,
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
		Type:              TypeSplitRoot,
		AnchorOutputIndex: 0,
		ScriptKey:         asset.NUMSScriptKey,
	})

	// We start at output index 1 because we also have the change output
	// above. We also just use continuous integers for the anchor output
	// index, but start at the first one indicated by the caller.
	for idx := range receiverAddrs {
		addr := receiverAddrs[idx]

		schnorrInternalKey, _ := schnorr.ParsePubKey(
			schnorr.SerializePubKey(&addr.InternalKey),
		)
		pkt.Outputs = append(pkt.Outputs, &VOutput{
			Amount:            addr.Amount,
			Interactive:       false,
			AnchorOutputIndex: firstOutputIndex + uint32(idx),
			ScriptKey: asset.NewScriptKey(
				&addr.ScriptKey,
			),
			AnchorOutputInternalKey:      schnorrInternalKey,
			AnchorOutputTapscriptSibling: addr.TapscriptSibling,
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
		Type:              TypeSimple,
		Amount:            amount,
		Interactive:       true,
		AnchorOutputIndex: outputIndex,
		ScriptKey:         scriptAddr,
	}
	vOut.SetAnchorInternalKey(anchorInternalKey, pkt.ChainParams.HDCoinType)

	pkt.Outputs = append(pkt.Outputs, vOut)
}

// OwnershipProofPacket creates a virtual transaction packet that is used to
// prove ownership of an asset. It creates a 1-in-1-out transaction that spends
// the owned asset to the NUMS key. The witness is created over an empty
// previous outpoint, so it can never be used in an actual state transition.
func OwnershipProofPacket(ownedAsset *asset.Asset,
	chainParams *address.ChainParams) *VPacket {

	// We create the ownership proof by creating a virtual packet that
	// spends the full asset into a NUMS key. But in order to prevent that
	// witness to be used in an actual state transition by a malicious
	// actor, we create the signature over an empty outpoint. This means the
	// witness is fully valid, but a full transition proof can never be
	// created, as the previous outpoint would not match the one that
	// actually goes on chain.
	//
	// TODO(guggero): Revisit this proof once we support pocket universes.
	emptyOutPoint := wire.OutPoint{}
	prevId := asset.PrevID{
		ID:       ownedAsset.ID(),
		OutPoint: emptyOutPoint,
		ScriptKey: asset.ToSerialized(
			ownedAsset.ScriptKey.PubKey,
		),
	}

	outputAsset := ownedAsset.Copy()
	outputAsset.ScriptKey = asset.NUMSScriptKey
	outputAsset.PrevWitnesses = []asset.Witness{{
		PrevID: &prevId,
	}}

	vPkt := &VPacket{
		Inputs: []*VInput{{
			PrevID: prevId,
		}},
		Outputs: []*VOutput{{
			Asset:             outputAsset,
			Amount:            outputAsset.Amount,
			Interactive:       true,
			AnchorOutputIndex: 0,
			ScriptKey:         asset.NUMSScriptKey,
		}},
		ChainParams: chainParams,
	}
	vPkt.SetInputAsset(0, ownedAsset, nil)

	return vPkt
}
