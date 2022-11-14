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
		name: "basic send",
		test: testBasicSend,
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
}
