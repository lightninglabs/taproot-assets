package perms

import "gopkg.in/macaroon-bakery.v2/bakery"

var (
	// RequiredPermissions is a map of all taro RPC methods and their
	// required macaroon permissions to access tarod.
	//
	// TODO(roasbeef): re think these and go instead w/ the * approach?
	RequiredPermissions = map[string][]bakery.Op{
		"/tarorpc.Taro/StopDaemon": {{
			Entity: "daemon",
			Action: "write",
		}},
		"/tarorpc.Taro/DebugLevel": {{
			Entity: "daemon",
			Action: "write",
		}},
		"/tarorpc.Taro/ListAssets": {{
			Entity: "assets",
			Action: "read",
		}},
		"/tarorpc.Taro/ListUtxos": {{
			Entity: "assets",
			Action: "read",
		}},
		"/tarorpc.Taro/ListGroups": {{
			Entity: "assets",
			Action: "read",
		}},
		"/tarorpc.Taro/ListBalances": {{
			Entity: "assets",
			Action: "read",
		}},
		"/tarorpc.Taro/ListTransfers": {{
			Entity: "assets",
			Action: "read",
		}},
		"/tarorpc.Taro/QueryAddrs": {{
			Entity: "addresses",
			Action: "read",
		}},
		"/tarorpc.Taro/NewAddr": {{
			Entity: "addresses",
			Action: "write",
		}},
		"/tarorpc.Taro/DecodeAddr": {{
			Entity: "addresses",
			Action: "read",
		}},
		"/tarorpc.Taro/AddrReceives": {{
			Entity: "addresses",
			Action: "read",
		}},
		"/tarorpc.Taro/VerifyProof": {{
			Entity: "proofs",
			Action: "read",
		}},
		"/tarorpc.Taro/ExportProof": {{
			Entity: "proofs",
			Action: "read",
		}},
		"/tarorpc.Taro/ImportProof": {{
			Entity: "proofs",
			Action: "write",
		}},
		"/tarorpc.Taro/SendAsset": {{
			Entity: "assets",
			Action: "write",
		}},
		"/tarorpc.Taro/SubscribeSendAssetEventNtfns": {{
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
		"/assetwalletrpc.AssetWallet/ProveAssetOwnership": {{
			Entity: "assets",
			Action: "write",
		}},
		"/assetwalletrpc.AssetWallet/VerifyAssetOwnership": {{
			Entity: "assets",
			Action: "read",
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
		"/universerpc.Universe/AssetRoots": {{
			Entity: "universe",
			Action: "read",
		}},
		"/universerpc.Universe/QueryAssetRoots": {{
			Entity: "universe",
			Action: "read",
		}},
		"/universerpc.Universe/AssetLeafKeys": {{
			Entity: "universe",
			Action: "read",
		}},
		"/universerpc.Universe/AssetLeaves": {{
			Entity: "universe",
			Action: "read",
		}},
		"/universerpc.Universe/QueryIssuanceProof": {{
			Entity: "universe",
			Action: "read",
		}},
		"/universerpc.Universe/InsertIssuanceProof": {{
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
	}

	// MacaroonWhitelist defines methods that we don't require macaroons to
	// access. For now, these are the Universe related read/write methods.
	// We permit InsertIssuanceProof as a valid proof requires an on-chain
	// transaction, so we gain a layer of DoS defense.
	MacaroonWhitelist = map[string]struct{}{
		"/universerpc.Universe/AssetRoots":          {},
		"/universerpc.Universe/QueryAssetRoots":     {},
		"/universerpc.Universe/AssetLeafKeys":       {},
		"/universerpc.Universe/AssetLeaves":         {},
		"/universerpc.Universe/QueryIssuanceProof":  {},
		"/universerpc.Universe/InsertIssuanceProof": {},
	}
)
