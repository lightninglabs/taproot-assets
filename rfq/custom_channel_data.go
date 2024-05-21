package rfq

// TODO(guggero): De-duplicate by putting into same shared package as the other
//  custom channel data structs.

// JsonAssetBalance is a struct that represents the balance of a single asset ID
// within a channel.
type JsonAssetBalance struct {
	AssetID       string `json:"asset_id"`
	Name          string `json:"name"`
	LocalBalance  uint64 `json:"local_balance"`
	RemoteBalance uint64 `json:"remote_balance"`
}

// JsonAssetGenesis is a struct that represents the genesis information of an
// asset.
type JsonAssetGenesis struct {
	GenesisPoint string `json:"genesis_point"`
	Name         string `json:"name"`
	MetaHash     string `json:"meta_hash"`
	AssetID      string `json:"asset_id"`
}

// JsonAssetUtxo is a struct that represents the UTXO information of an asset
// within a channel.
type JsonAssetUtxo struct {
	Version      int64            `json:"version"`
	AssetGenesis JsonAssetGenesis `json:"asset_genesis"`
	Amount       uint64           `json:"amount"`
	ScriptKey    string           `json:"script_key"`
}

// JsonAssetChanInfo is a struct that represents the channel information of a
// single asset within a channel.
type JsonAssetChanInfo struct {
	AssetInfo     JsonAssetUtxo `json:"asset_utxo"`
	Capacity      uint64        `json:"capacity"`
	LocalBalance  uint64        `json:"local_balance"`
	RemoteBalance uint64        `json:"remote_balance"`
}

// JsonAssetChannel is a struct that represents the channel information of all
// assets within a channel.
type JsonAssetChannel struct {
	Assets []JsonAssetChanInfo `json:"assets"`
}
