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
	Version        int64            `json:"version"`
	AssetGenesis   JsonAssetGenesis `json:"asset_genesis"`
	Amount         uint64           `json:"amount"`
	ScriptKey      string           `json:"script_key"`
	DecimalDisplay uint8            `json:"decimal_display"`
}

// JsonAssetChannel is a struct that represents the channel information of all
// assets within a channel.
type JsonAssetChannel struct {
	FundingAssets       []JsonAssetUtxo    `json:"funding_assets"`
	LocalAssets         []JsonAssetTranche `json:"local_assets"`
	RemoteAssets        []JsonAssetTranche `json:"remote_assets"`
	OutgoingHtlcs       []JsonAssetTranche `json:"outgoing_htlcs"`
	IncomingHtlcs       []JsonAssetTranche `json:"incoming_htlcs"`
	Capacity            uint64             `json:"capacity"`
	LocalBalance        uint64             `json:"local_balance"`
	RemoteBalance       uint64             `json:"remote_balance"`
	OutgoingHtlcBalance uint64             `json:"outgoing_htlc_balance"`
	IncomingHtlcBalance uint64             `json:"incoming_htlc_balance"`
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

// JsonAssetTranche is a struct that represents the balance of a single asset
// tranche.
type JsonAssetTranche struct {
	AssetID string `json:"asset_id"`
	Amount  uint64 `json:"amount"`
}

// JsonHtlc is a struct that represents the asset information that can be
// transferred via an HTLC.
type JsonHtlc struct {
	Balances []*JsonAssetTranche `json:"balances"`
	RfqID    string              `json:"rfq_id"`
}
