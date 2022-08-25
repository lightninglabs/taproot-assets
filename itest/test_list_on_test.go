//go:build itest
// +build itest

package itest

var testCases = []*testCase{
	{
		name: "mint assets",
		test: mintAssets,
	},
}
