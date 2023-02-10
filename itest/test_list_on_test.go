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
		test: testReissuance,
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
}
