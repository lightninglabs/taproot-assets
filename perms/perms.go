package perms

import "gopkg.in/macaroon-bakery.v2/bakery"

var (
	// RequiredPermissions is a map of all tapd RPC methods and their
	// required macaroon permissions to access tapd.
	//
	// TODO(roasbeef): re think these and go instead w/ the * approach?
	RequiredPermissions = map[string][]bakery.Op{
		"/taprpc.TaprootAssets/StopDaemon": {{
			Entity: "daemon",
			Action: "write",
		}},
		"/taprpc.TaprootAssets/DebugLevel": {{
			Entity: "daemon",
			Action: "write",
		}},
		"/taprpc.TaprootAssets/GetInfo": {{
			Entity: "daemon",
			Action: "read",
		}},
		"/taprpc.TaprootAssets/ListAssets": {{
			Entity: "assets",
			Action: "read",
		}},
		"/taprpc.TaprootAssets/ListUtxos": {{
			Entity: "assets",
			Action: "read",
		}},
		"/taprpc.TaprootAssets/ListGroups": {{
			Entity: "assets",
			Action: "read",
		}},
		"/taprpc.TaprootAssets/ListBalances": {{
			Entity: "assets",
			Action: "read",
		}},
		"/taprpc.TaprootAssets/ListTransfers": {{
			Entity: "assets",
			Action: "read",
		}},
		"/taprpc.TaprootAssets/QueryAddrs": {{
			Entity: "addresses",
			Action: "read",
		}},
		"/taprpc.TaprootAssets/NewAddr": {{
			Entity: "addresses",
			Action: "write",
		}},
		"/taprpc.TaprootAssets/DecodeAddr": {{
			Entity: "addresses",
			Action: "read",
		}},
		"/taprpc.TaprootAssets/AddrReceives": {{
			Entity: "addresses",
			Action: "read",
		}},
		"/taprpc.TaprootAssets/VerifyProof": {{
			Entity: "proofs",
			Action: "read",
		}},
		"/taprpc.TaprootAssets/DecodeProof": {{
			Entity: "proofs",
			Action: "read",
		}},
		"/taprpc.TaprootAssets/ExportProof": {{
			Entity: "proofs",
			Action: "read",
		}},
		"/taprpc.TaprootAssets/SendAsset": {{
			Entity: "assets",
			Action: "write",
		}},
		"/taprpc.TaprootAssets/BurnAsset": {{
			Entity: "assets",
			Action: "write",
		}},
		"/taprpc.TaprootAssets/FetchAssetMeta": {{
			Entity: "assets",
			Action: "read",
		}},
		"/taprpc.TaprootAssets/SubscribeSendAssetEventNtfns": {{
			Entity: "assets",
			Action: "write",
		}},
		"/taprpc.TaprootAssets/SubscribeReceiveAssetEventNtfns": {{
			Entity: "assets",
			Action: "write",
		}},
		"/assetwalletrpc.AssetWallet/FundVirtualPsbt": {{
			Entity: "assets",
			Action: "write",
		}},
		"/assetwalletrpc.AssetWallet/SignVirtualPsbt": {{
			Entity: "assets",
			Action: "write",
		}},
		"/assetwalletrpc.AssetWallet/AnchorVirtualPsbts": {{
			Entity: "assets",
			Action: "write",
		}},
		"/assetwalletrpc.AssetWallet/NextInternalKey": {{
			Entity: "assets",
			Action: "write",
		}},
		"/assetwalletrpc.AssetWallet/NextScriptKey": {{
			Entity: "assets",
			Action: "write",
		}},
		"/assetwalletrpc.AssetWallet/QueryInternalKey": {{
			Entity: "assets",
			Action: "read",
		}},
		"/assetwalletrpc.AssetWallet/QueryScriptKey": {{
			Entity: "assets",
			Action: "read",
		}},
		"/assetwalletrpc.AssetWallet/ProveAssetOwnership": {{
			Entity: "assets",
			Action: "write",
		}},
		"/assetwalletrpc.AssetWallet/VerifyAssetOwnership": {{
			Entity: "assets",
			Action: "read",
		}},
		"/assetwalletrpc.AssetWallet/RemoveUTXOLease": {{
			Entity: "assets",
			Action: "write",
		}},
		"/mintrpc.Mint/MintAsset": {{
			Entity: "mint",
			Action: "write",
		}},
		"/mintrpc.Mint/FinalizeBatch": {{
			Entity: "mint",
			Action: "write",
		}},
		"/mintrpc.Mint/CancelBatch": {{
			Entity: "mint",
			Action: "write",
		}},
		"/mintrpc.Mint/ListBatches": {{
			Entity: "mint",
			Action: "read",
		}},
		"/universerpc.Universe/MultiverseRoot": {{
			Entity: "universe",
			Action: "read",
		}},
		"/universerpc.Universe/AssetRoots": {{
			Entity: "universe",
			Action: "read",
		}},
		"/universerpc.Universe/QueryAssetRoots": {{
			Entity: "universe",
			Action: "read",
		}},
		"/universerpc.Universe/DeleteAssetRoot": {{
			Entity: "universe",
			Action: "write",
		}},
		"/universerpc.Universe/AssetLeafKeys": {{
			Entity: "universe",
			Action: "read",
		}},
		"/universerpc.Universe/AssetLeaves": {{
			Entity: "universe",
			Action: "read",
		}},
		"/universerpc.Universe/QueryProof": {{
			Entity: "universe",
			Action: "read",
		}},
		"/universerpc.Universe/InsertProof": {{
			Entity: "universe",
			Action: "write",
		}},
		"/universerpc.Universe/SyncUniverse": {{
			Entity: "universe",
			Action: "write",
		}},
		"/universerpc.Universe/ListFederationServers": {{
			Entity: "universe",
			Action: "read",
		}},
		"/universerpc.Universe/AddFederationServer": {{
			Entity: "universe",
			Action: "write",
		}},
		"/universerpc.Universe/DeleteFederationServer": {{
			Entity: "universe",
			Action: "write",
		}},
		"/universerpc.Universe/UniverseStats": {{
			Entity: "universe",
			Action: "read",
		}},
		"/universerpc.Universe/QueryAssetStats": {{
			Entity: "universe",
			Action: "read",
		}},
		"/universerpc.Universe/QueryEvents": {{
			Entity: "universe",
			Action: "read",
		}},
		"/universerpc.Universe/SetFederationSyncConfig": {{
			Entity: "universe",
			Action: "write",
		}},
		"/universerpc.Universe/QueryFederationSyncConfig": {{
			Entity: "universe",
			Action: "read",
		}},
		"/rfqrpc.Rfq/AddAssetBuyOrder": {{
			Entity: "rfq",
			Action: "write",
		}},
		"/rfqrpc.Rfq/AddAssetSellOffer": {{
			Entity: "rfq",
			Action: "write",
		}},
		"/rfqrpc.Rfq/QueryRfqAcceptedQuotes": {{
			Entity: "rfq",
			Action: "read",
		}},
		"/rfqrpc.Rfq/SubscribeRfqEventNtfns": {{
			Entity: "rfq",
			Action: "write",
		}},
		"/tapdevrpc.TapDev/ImportProof": {{
			Entity: "proofs",
			Action: "write",
		}},
	}

	// defaultMacaroonWhitelist defines a default set of RPC endpoints that
	// don't require macaroons authentication.
	//
	// For now, these are the Universe related read/write methods. We permit
	// InsertProof as a valid proof requires an on-chain transaction, so we
	// gain a layer of DoS defense.
	defaultMacaroonWhitelist = map[string]struct{}{
		"/universerpc.Universe/AssetRoots":      {},
		"/universerpc.Universe/QueryAssetRoots": {},
		"/universerpc.Universe/AssetLeafKeys":   {},
		"/universerpc.Universe/AssetLeaves":     {},
		"/universerpc.Universe/Info":            {},
	}
)

// MacaroonWhitelist returns the set of RPC endpoints that don't require
// macaroon authentication.
func MacaroonWhitelist(allowPublicUniProofCourier bool,
	allowPublicStats bool) map[string]struct{} {

	// Make a copy of the default whitelist.
	whitelist := make(map[string]struct{})
	for k, v := range defaultMacaroonWhitelist {
		whitelist[k] = v
	}

	// Conditionally add public multiverse proof courier RPC endpoints to
	// the whitelist.
	if allowPublicUniProofCourier {
		whitelist["/universerpc.Universe/QueryProof"] = struct{}{}
		whitelist["/universerpc.Universe/InsertProof"] = struct{}{}
	}

	// Conditionally add public stats RPC endpoints to the whitelist.
	if allowPublicStats {
		whitelist["/universerpc.Universe/QueryAssetStats"] = struct{}{}
		whitelist["/universerpc.Universe/UniverseStats"] = struct{}{}
		whitelist["/universerpc.Universe/QueryEvents"] = struct{}{}
	}

	return whitelist
}
