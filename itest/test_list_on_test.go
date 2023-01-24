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
}
