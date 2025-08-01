package tappsbt

import (
	"fmt"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
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

	switch firstAddr.Version {
	case address.V0:
		pkt.Version = V0
	case address.V1:
		pkt.Version = V1
	default:
		return nil, address.ErrUnknownVersion
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
		Interactive:       false,
		Type:              TypeSplitRoot,
		AnchorOutputIndex: 0,
		ScriptKey:         asset.NUMSScriptKey,
	})

	// We start at output index 1 because we also have the change output
	// above. We also just use continuous integers for the anchor output
	// index, but start at the first one indicated by the caller.
	for idx := range receiverAddrs {
		addr := receiverAddrs[idx]
		if addr.Version != firstAddr.Version {
			return nil, fmt.Errorf("mixed address versions")
		}

		pkt.Outputs = append(pkt.Outputs, &VOutput{
			AssetVersion:      addr.AssetVersion,
			Amount:            addr.Amount,
			Interactive:       false,
			AnchorOutputIndex: firstOutputIndex + uint32(idx),
			ScriptKey: asset.NewScriptKey(
				&addr.ScriptKey,
			),
			AnchorOutputInternalKey:      &addr.InternalKey,
			AnchorOutputTapscriptSibling: addr.TapscriptSibling,
			ProofDeliveryAddress:         &addr.ProofCourierAddr,
			Address:                      addr,
		})
	}

	return pkt, nil
}

// ForInteractiveSend creates a virtual transaction packet for sending an output
// to a receiver in an interactive manner. Only one, interactive output is
// created. If the amount is not the full input amount, a change output will be
// added by the funding API.
func ForInteractiveSend(id asset.ID, amount uint64, scriptAddr asset.ScriptKey,
	lockTime uint64, relativeLockTime uint64, outputIndex uint32,
	anchorInternalKey keychain.KeyDescriptor, assetVersion asset.Version,
	chainParams *address.ChainParams) *VPacket {

	vPkt := &VPacket{
		Inputs: []*VInput{{
			PrevID: asset.PrevID{
				ID: id,
			},
		}},
		Outputs: []*VOutput{{
			Amount:            amount,
			AssetVersion:      assetVersion,
			Interactive:       true,
			AnchorOutputIndex: outputIndex,
			ScriptKey:         scriptAddr,
			LockTime:          lockTime,
			RelativeLockTime:  relativeLockTime,
		}},
		ChainParams: chainParams,
		Version:     V1,
	}
	vPkt.Outputs[0].SetAnchorInternalKey(
		anchorInternalKey, chainParams.HDCoinType,
	)

	return vPkt
}

// AddOutput adds an interactive output to the given packet.
func AddOutput(pkt *VPacket, amount uint64, scriptAddr asset.ScriptKey,
	outputIndex uint32, anchorInternalKey keychain.KeyDescriptor,
	assetVersion asset.Version) {

	vOut := &VOutput{
		AssetVersion:      assetVersion,
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
// the owned asset to the NUMS key. If a challenge is defined the NUMS key is
// modified based on that value. The witness is created over an empty previous
// outpoint, so it can never be used in an actual state transition.
func OwnershipProofPacket(ownedAsset *asset.Asset,
	challengeBytes fn.Option[[32]byte],
	chainParams *address.ChainParams) *VPacket {

	prevId, outputAsset := proof.CreateOwnershipProofAsset(
		ownedAsset, challengeBytes,
	)
	vPkt := &VPacket{
		Inputs: []*VInput{{
			PrevID: prevId,
		}},
		Outputs: []*VOutput{{
			Asset:             outputAsset,
			AssetVersion:      outputAsset.Version,
			Amount:            outputAsset.Amount,
			Interactive:       true,
			AnchorOutputIndex: 0,
			ScriptKey:         outputAsset.ScriptKey,
		}},
		ChainParams: chainParams,
		Version:     V1,
	}
	vPkt.SetInputAsset(0, ownedAsset)

	return vPkt
}

// FromProofs creates a packet from the given proofs that adds them as inputs to
// the packet.
func FromProofs(proofs []*proof.Proof, params *address.ChainParams,
	version VPacketVersion) (*VPacket, error) {

	pkt := &VPacket{
		ChainParams: params,
		Version:     version,
	}

	for idx := range proofs {
		p := proofs[idx]

		txOut := p.AnchorTx.TxOut[p.InclusionProof.OutputIndex]

		commitmentKeys, err := p.InclusionProof.DeriveByAssetInclusion(
			&p.Asset, fn.Ptr(false),
		)
		if err != nil {
			return nil, fmt.Errorf("error deriving commitment: %w",
				err)
		}

		tapCommitment, err := commitmentKeys.GetCommitment()
		if err != nil {
			return nil, err
		}
		tapProof := p.InclusionProof.CommitmentProof

		//nolint:lll
		siblingBytes, sibling, err := commitment.MaybeEncodeTapscriptPreimage(
			tapProof.TapSiblingPreimage,
		)
		if err != nil {
			return nil, fmt.Errorf("error encoding taproot "+
				"sibling: %w", err)
		}

		rootHash := tapCommitment.TapscriptRoot(sibling)
		pkt.Inputs = append(pkt.Inputs, &VInput{
			PrevID: asset.PrevID{
				OutPoint: p.OutPoint(),
				ID:       p.Asset.ID(),
				ScriptKey: asset.ToSerialized(
					p.Asset.ScriptKey.PubKey,
				),
			},
			Anchor: Anchor{
				Value:            btcutil.Amount(txOut.Value),
				PkScript:         txOut.PkScript,
				SigHashType:      txscript.SigHashDefault,
				InternalKey:      p.InclusionProof.InternalKey,
				MerkleRoot:       rootHash[:],
				TapscriptSibling: siblingBytes,
			},
			Proof: p,
		})
		pkt.SetInputAsset(len(pkt.Inputs)-1, &p.Asset)
	}

	return pkt, nil
}
