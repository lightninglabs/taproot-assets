package universerpc

import (
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire"
)

// MarshalOutpoint marshals a wire.OutPoint into an RPC ready Outpoint.
//
// TODO(ffranr): Move this package's Outpoint type and this marshal function to
// somewhere more general.
func MarshalOutpoint(outPoint wire.OutPoint) *Outpoint {
	return &Outpoint{
		HashStr: outPoint.Hash.String(),
		Index:   int32(outPoint.Index),
	}
}

// MarshalAssetKey returns an RPC ready AssetKey.
func MarshalAssetKey(outPoint wire.OutPoint,
	scriptKeyPubKey *btcec.PublicKey) *AssetKey {

	scriptKeyBytes := scriptKeyPubKey.SerializeCompressed()

	return &AssetKey{
		Outpoint: &AssetKey_Op{
			Op: MarshalOutpoint(outPoint),
		},
		ScriptKey: &AssetKey_ScriptKeyBytes{
			ScriptKeyBytes: scriptKeyBytes,
		},
	}
}

// MarshalUniverseID returns an RPC ready universe ID.
func MarshalUniverseID(assetIDBytes []byte, groupKeyBytes []byte) *ID {
	// We will marshal either a group key ID or an asset ID. If group key
	// bytes are given, we marshal a group key ID, otherwise we marshal an
	// asset ID.
	if groupKeyBytes != nil {
		return &ID{
			Id: &ID_GroupKey{
				GroupKey: groupKeyBytes,
			},
		}
	}

	return &ID{
		Id: &ID_AssetId{
			AssetId: assetIDBytes,
		},
	}
}
