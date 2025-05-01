package rpcutils

import (
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/taprpc/universerpc"
)

// MarshalOutpoint marshals a wire.OutPoint into an RPC ready Outpoint.
func MarshalOutpoint(outPoint wire.OutPoint) *universerpc.Outpoint {
	return &universerpc.Outpoint{
		HashStr: outPoint.Hash.String(),
		Index:   int32(outPoint.Index),
	}
}

// MarshalAssetKey returns an RPC ready AssetKey.
func MarshalAssetKey(outPoint wire.OutPoint,
	scriptKeyPubKey *btcec.PublicKey) *universerpc.AssetKey {

	scriptKeyBytes := scriptKeyPubKey.SerializeCompressed()

	return &universerpc.AssetKey{
		Outpoint: &universerpc.AssetKey_Op{
			Op: MarshalOutpoint(outPoint),
		},
		ScriptKey: &universerpc.AssetKey_ScriptKeyBytes{
			ScriptKeyBytes: scriptKeyBytes,
		},
	}
}

// MarshalUniverseID returns an RPC ready universe ID.
func MarshalUniverseID(assetIDBytes []byte,
	groupKeyBytes []byte) *universerpc.ID {

	// We will marshal either a group key ID or an asset ID. If group key
	// bytes are given, we marshal a group key ID, otherwise we marshal an
	// asset ID.
	if groupKeyBytes != nil {
		return &universerpc.ID{
			Id: &universerpc.ID_GroupKey{
				GroupKey: groupKeyBytes,
			},
		}
	}

	return &universerpc.ID{
		Id: &universerpc.ID_AssetId{
			AssetId: assetIDBytes,
		},
	}
}
