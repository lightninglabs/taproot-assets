package rfqmsg

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

// JsonAssetChannelBalances is a struct that represents the balance information
// of all assets within open and pending channels.
type JsonAssetChannelBalances struct {
	OpenChannels    map[string]*JsonAssetBalance `json:"open_channels"`
	PendingChannels map[string]*JsonAssetBalance `json:"pending_channels"`
}

// JsonCloseOutput is a struct that represents the additional co-op close output
// information of asset channels.
type JsonCloseOutput struct {
	BtcInternalKey   string            `json:"btc_internal_key"`
	AssetInternalKey string            `json:"asset_internal_key"`
	ScriptKeys       map[string]string `json:"script_keys"`
}

// JsonHtlcBalance is a struct that represents the balance of a single asset
// HTLC.
type JsonHtlcBalance struct {
	AssetID string `json:"asset_id"`
	Amount  uint64 `json:"amount"`
}

// JsonHtlc is a struct that represents the asset information that can be
// transferred via an HTLC.
type JsonHtlc struct {
	Balances []*JsonHtlcBalance `json:"balances"`
	RfqID    string             `json:"rfq_id"`
}
