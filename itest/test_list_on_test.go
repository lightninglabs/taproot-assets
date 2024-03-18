//go:build itest

package itest

import "github.com/lightninglabs/taproot-assets/proof"

var testCases = []*testCase{
	{
		name: "mint assets",
		test: testMintAssets,
	},
	{
		name: "asset meta validation",
		test: testAssetMeta,
	},
	{
		name: "asset name collision raises mint error",
		test: testMintAssetNameCollisionError,
	},
	{
		name: "mint assets with tap sibling",
		test: testMintAssetsWithTapscriptSibling,
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
		name: "address syncer",
		test: testAddressAssetSyncer,
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
		name:             "basic send unidirectional hashmail courier",
		test:             testBasicSendUnidirectional,
		proofCourierType: proof.HashmailCourierType,
	},
	{
		name: "basic send unidirectional",
		test: testBasicSendUnidirectional,
	},
	{
		name: "restart receiver check balance",
		test: testRestartReceiverCheckBalance,
	},
	{
		name: "resume pending package send hashmail " +
			"courier",
		test:             testResumePendingPackageSend,
		proofCourierType: proof.HashmailCourierType,
	},
	{
		name:             "reattempt failed send hashmail courier",
		test:             testReattemptFailedSendHashmailCourier,
		proofCourierType: proof.HashmailCourierType,
	},
	{
		name: "reattempt failed send uni courier",
		test: testReattemptFailedSendUniCourier,
	},
	{
		name: "reattempt failed receive uni courier",
		test: testReattemptFailedReceiveUniCourier,
	},
	{
		name: "offline receiver eventually receives " +
			"hashmail courier",
		test:             testOfflineReceiverEventuallyReceives,
		proofCourierType: proof.HashmailCourierType,
	},
	{
		name: "addr send no proof courier with local universe import",
		test: testSendNoCourierUniverseImport,
	},
	{
		name:             "basic send passive asset hashmail courier",
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
		name: "collectible send",
		test: testCollectibleSend,
	},
	{
		name: "collectible group send",
		test: testCollectibleGroupSend,
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
		name:             "sending multi asset groups hashmail courier",
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
		name: "psbt sighash none",
		test: testPsbtSighashNone,
	},
	{
		name: "psbt sighash none invalid",
		test: testPsbtSighashNoneInvalid,
	},
	{
		name: "psbt trustless swap",
		test: testPsbtTrustlessSwap,
	},
	{
		name: "psbt external commit",
		test: testPsbtExternalCommit,
	},
	{
		name: "multi input psbt single asset id",
		test: testMultiInputPsbtSingleAssetID,
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
		name: "universe sync manual insert",
		test: testUniverseManualSync,
	},
	{
		name: "universe federation",
		test: testUniverseFederation,
	},
	{
		name: "fee estimation",
		test: testFeeEstimation,
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
		name: "burn grouped assets",
		test: testBurnGroupedAssets,
	},
	{
		name: "federation sync config",
		test: testFederationSyncConfig,
	},
	{
		name: "universe pagination simple",
		test: testUniversePaginationSimple,
	},
	{
		name: "mint proof repeat fed sync attempt",
		test: testMintProofRepeatFedSyncAttempt,
	},

	// Request for quote (RFQ) tests.
	{
		name: "rfq asset buy htlc intercept",
		test: testRfqAssetBuyHtlcIntercept,
	},
	{
		name: "rfq asset sell htlc intercept",
		test: testRfqAssetSellHtlcIntercept,
	},

	{
		name: "multi signature on all levels",
		test: testMultiSignature,
	},
	{
		name: "anchor multiple virtual transactions",
		test: testAnchorMultipleVirtualTransactions,
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
