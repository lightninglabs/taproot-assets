//go:build itest

package itest

import (
	"github.com/lightninglabs/taproot-assets/proof"
)

var testCases = []*testCase{
	{
		name: "mint assets",
		test: testMintAssets,
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
	// For some (yet unknown) reason, the Postgres itest is much more flaky
	// if the re-org tests run last. So we run them toward the beginning to
	// reduce the flakiness of the Postgres itest.
	{
		name: "re-org mint",
		test: testReOrgMint,
	},
	{
		name: "re-org send",
		test: testReOrgSend,
	},
	{
		name: "re-org mint and send",
		test: testReOrgMintAndSend,
	},
	{
		name: "address syncer",
		test: testAddressAssetSyncer,
	},
	{
		name:             "basic send unidirectional",
		test:             testBasicSendUnidirectional,
		proofCourierType: proof.HashmailCourierType,
	},
	{
		name:             "basic send universerpc proof courier",
		test:             testBasicSendUnidirectional,
		proofCourierType: proof.UniverseRpcCourierType,
	},
	{
		name:             "resume pending package send",
		test:             testResumePendingPackageSend,
		proofCourierType: proof.HashmailCourierType,
	},
	{
		name:             "reattempt failed asset send hashmail courier",
		test:             testReattemptFailedAssetSendHashmailCourier,
		proofCourierType: proof.HashmailCourierType,
	},
	{
		name:             "reattempt failed asset send uni courier",
		test:             testReattemptFailedAssetSendUniCourier,
		proofCourierType: proof.UniverseRpcCourierType,
	},
	{
		name:             "offline receiver eventually receives",
		test:             testOfflineReceiverEventuallyReceives,
		proofCourierType: proof.HashmailCourierType,
	},
	{
		name:             "basic send passive asset",
		test:             testBasicSendPassiveAsset,
		proofCourierType: proof.HashmailCourierType,
	},
	{
		name: "send multiple coins",
		test: testSendMultipleCoins,
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
		name:             "collectible send hashmail courier",
		test:             testCollectibleSend,
		proofCourierType: proof.HashmailCourierType,
	},
	{
		name:             "collectible send rpc courier",
		test:             testCollectibleSend,
		proofCourierType: proof.UniverseRpcCourierType,
	},
	{
		name:             "collectible group send rpc courier",
		test:             testCollectibleGroupSend,
		proofCourierType: proof.UniverseRpcCourierType,
	},
	{
		name: "re-issuance",
		test: testReIssuance,
	},
	{
		name: "minting multi asset groups",
		test: testMintMultiAssetGroups,
	},
	{
		name:             "sending multi asset groups",
		test:             testMultiAssetGroupSend,
		proofCourierType: proof.HashmailCourierType,
	},
	{
		name: "re-issuance amount overflow",
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
		name: "psbt normal interactive full value send",
		test: testPsbtNormalInteractiveFullValueSend,
	},
	{
		name: "psbt grouped interactive full value send",
		test: testPsbtGroupedInteractiveFullValueSend,
	},
	{
		name: "psbt normal interactive split send",
		test: testPsbtNormalInteractiveSplitSend,
	},
	{
		name: "psbt grouped interactive split send",
		test: testPsbtGroupedInteractiveSplitSend,
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
	{
		name: "universe federation",
		test: testUniverseFederation,
	},
	{
		name: "get info",
		test: testGetInfo,
	},
	{
		name: "burn test",
		test: testBurnAssets,
	},
	{
		name: "federation sync config",
		test: testFederationSyncConfig,
	},
}

var optionalTestCases = []*testCase{
	{
		name: "mint batch 100 stress test",
		test: testMintBatch100StressTest,
	},
	{
		name: "mint batch 1k stress test",
		test: testMintBatch1kStressTest,
	},
	{
		name: "mint batch 10k stress test",
		test: testMintBatch10kStressTest,
	},
}
