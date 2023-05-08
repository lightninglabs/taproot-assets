//go:build itest
// +build itest

package itest

var testCases = []*testCase{
	{
		name: "mint assets",
		test: mintAssets,
	},
	{
		name: "asset name collision raises mint error",
		test: testMintAssetNameCollisionError,
	},
	{
		name: "addresses",
		test: testAddresses,
	},
	{
		name: "multi address",
		test: testMultiAddress,
	},
	{
		name:           "basic send",
		test:           testBasicSend,
		enableHashMail: true,
	},
	{
		name:           "reattempt failed asset send",
		test:           testReattemptFailedAssetSend,
		enableHashMail: true,
	},
	{
		name: "basic send passive asset",
		test: testSendPassiveAsset,
	},
	{
		name: "multi input send non-interactive single ID",
		test: testMultiInputSendNonInteractiveSingleID,
	},
	{
		name: "round trip send",
		test: testRoundTripSend,
	},
	{
		name: "full value send",
		test: testFullValueSend,
	},
	{
		name: "collectible send",
		test: testCollectibleSend,
	},
	{
		name: "reissuance",
		test: testReIssuance,
	},
	{
		name: "minting multi asset groups",
		test: testMintMultiAssetGroups,
	},
	{
		name: "re-issuance asset amount overflow",
		test: testReIssuanceAmountOverflow,
	},
	{
		name: "minting multi asset groups errors",
		test: testMintMultiAssetGroupErrors,
	},
	{
		name: "mint with group key errors",
		test: testMintWithGroupKeyErrors,
	},
	{
		name: "psbt script hash lock send",
		test: testPsbtScriptHashLockSend,
	},
	{
		name: "psbt script check sig send",
		test: testPsbtScriptCheckSigSend,
	},
	{
		name: "psbt interactive full value send",
		test: testPsbtInteractiveFullValueSend,
	},
	{
		name: "psbt interactive split send",
		test: testPsbtInteractiveSplitSend,
	},
	{
		name: "psbt interactive tapscript sibling",
		test: testPsbtInteractiveTapscriptSibling,
	},
	{
		name: "psbt multi send",
		test: testPsbtMultiSend,
	},
	{
		name: "universe REST API",
		test: testUniverseREST,
	},
	{
		name: "universe sync",
		test: testUniverseSync,
	},
}
