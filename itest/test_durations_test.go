//go:build itest

package itest

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// defaultCaseSeconds is the duration in seconds assumed for a test case that
// has no entry in testCaseSeconds.
const defaultCaseSeconds = 55

// caseSeconds returns the duration in seconds of the given test case from
// testCaseSeconds, or defaultCaseSeconds if it has no entry.
func caseSeconds(tc *testCase) int {
	if s, ok := testCaseSeconds[tc.name]; ok {
		return s
	}

	return defaultCaseSeconds
}

// testCaseSeconds holds measured durations in seconds of the test cases in
// allTestCases, keyed by name. The values are taken from the "case ...
// finished in" lines TestTaprootAssetsDaemon prints, from a CI run on the
// SQLite backend. splitTranches uses them to balance the tranches.
var testCaseSeconds = map[string]int{
	"psbt stxo exclusion proofs":                            12,
	"mint assets":                                           32,
	"mint batch resume":                                     68,
	"mint batch and transfer":                               14,
	"list assets":                                           29,
	"fetch asset":                                           48,
	"asset balances":                                        74,
	"asset meta validation":                                 47,
	"asset name collision raises mint error":                50,
	"mint assets with tap sibling":                          56,
	"mint fund seal assets":                                 18,
	"mint external group key chantools":                     55,
	"sign and finalize psbt deterministic":                  47,
	"mint asset decimal display":                            49,
	"backup restore genesis":                                50,
	"backup restore transferred":                            135,
	"backup restore grouped":                                152,
	"backup restore optimistic":                             80,
	"backup file updates":                                   113,
	"backup file reissuance":                                123,
	"backup file reissuance v1":                             98,
	"backup file legacy anchor":                             104,
	"addresses":                                             58,
	"address receives":                                      24,
	"multi address":                                         19,
	"unknown TLV type":                                      76,
	"address syncer":                                        75,
	"bake macaroon permissions":                             27,
	"re-org mint":                                           39,
	"re-org send":                                           65,
	"re-org send v2 address":                                25,
	"re-org mint and send":                                  106,
	"re-org nested history":                                 30,
	"act gated mint publication":                            34,
	"act gated supply emissions":                            29,
	"re-org send conflicting spend":                         105,
	"re-org supply commit":                                  53,
	"re-org genesis receive":                                40,
	"basic send unidirectional hashmail courier":            55,
	"basic send unidirectional":                             75,
	"min relay fee bump":                                    78,
	"zero value anchor sweep":                               59,
	"zero value anchor accumulation":                        59,
	"restart receiver check balance":                        102,
	"resume pending package send hashmail courier":          57,
	"reattempt failed send hashmail courier":                49,
	"reattempt failed send uni courier":                     65,
	"reattempt proof transfer on tapd restart":              71,
	"spend change output when proof transfer fail":          95,
	"reattempt failed receive uni courier":                  119,
	"offline receiver eventually receives hashmail courier": 74,
	"addr send no proof courier with local universe import": 33,
	"historical send events replay":                         76,
	"basic send passive asset hashmail courier":             77,
	"send multiple coins":                                   22,
	"multi input send non-interactive single ID":            56,
	"round trip send":                                       15,
	"full value send":                                       22,
	"collectible send hashmail courier":                     17,
	"collectible send":                                      77,
	"collectible group send":                                54,
	"re-issuance":                                           20,
	"minting multi asset groups":                            15,
	"sending multi asset groups hashmail courier":           44,
	"re-issuance amount overflow":                           27,
	"minting multi asset groups errors":                     47,
	"mint with group key errors":                            32,
	"psbt script hash lock send":                            75,
	"psbt script check sig send":                            15,
	"psbt normal interactive full value send":               54,
	"psbt multi version send":                               75,
	"psbt markerv0 mixed versions":                          11,
	"psbt grouped interactive full value send":              73,
	"psbt relative lock time send":                          71,
	"psbt lock time send":                                   71,
	"psbt relative lock time send with proof failure":       71,
	"psbt normal interactive split send":                    74,
	"psbt grouped interactive split send":                   75,
	"psbt interactive tapscript sibling":                    73,
	"psbt multi send":                                       15,
	"psbt sighash none":                                     74,
	"psbt sighash none invalid":                             73,
	"psbt trustless swap":                                   72,
	"psbt external commit":                                  55,
	"multi input psbt single asset id":                      77,
	"psbt alt leaf anchoring":                               71,
	"universe REST API":                                     48,
	"universe sync":                                         72,
	"universe delete leaf":                                  50,
	"universe sync manual insert":                           51,
	"universe federation":                                   51,
	"fee estimation":                                        18,
	"get info":                                              47,
	"burn assets":                                           17,
	"burn grouped assets":                                   49,
	"full burn assets":                                      49,
	"federation sync config":                                47,
	"universe pagination simple":                            15,
	"mint proof repeat fed sync attempt":                    62,
	"delete universe after fed sync":                        72,
	"rfq asset buy htlc intercept":                          122,
	"rfq asset sell htlc intercept":                         131,
	"rfq negotiation group key":                             132,
	"rfq portfolio pilot rpc":                               52,
	"rfq limit constraints":                                 121,
	"multi signature on all levels":                         72,
	"anchor multiple virtual transactions":                  15,
	"anchor multiple virtual split transactions":            14,
	"channel RPCs":                                          47,
	"ownership verification":                                73,
	"asset signing after lnd restore from seed":             121,
	"pre commit output":                                     48,
	"supply commit ignore asset":                            76,
	"supply commit mint burn":                               51,
	"supply verify peer node":                               87,
	"fetch supply leaves":                                   52,
	"auth mailbox message store and fetch":                  47,
	"auth mailbox cleanup":                                  72,
	"auth mailbox remove message":                           47,
	"script key type pedersen unique":                       51,
	"address v2 with simple asset":                          78,
	"address v2 with group key":                             56,
	"address v2 with group key multiple round trips":        25,
	"address v2 self send":                                  48,
	"address v2 with group key restart":                     142,
	"address v2 import fails without courier":               51,
	"transfer group key":                                    76,
}

// TestSplitTranches checks that splitTranches places every test case in
// exactly one tranche, in the order of allTestCases, and that the total
// durations of any two tranches differ by at most the longest case.
func TestSplitTranches(t *testing.T) {
	index := make(map[*testCase]int, len(allTestCases))
	longest := 0
	for i, tc := range allTestCases {
		index[tc] = i
		longest = max(longest, caseSeconds(tc))
	}

	for _, numTranches := range []uint{1, 4, 16} {
		tranches := splitTranches(allTestCases, numTranches)
		require.Len(t, tranches, int(numTranches))

		seen := make(map[*testCase]bool, len(allTestCases))
		minLoad, maxLoad := -1, 0
		for _, tranche := range tranches {
			load, last := 0, -1
			for _, tc := range tranche {
				require.False(t, seen[tc], tc.name)
				seen[tc] = true

				require.Greater(t, index[tc], last, tc.name)
				last = index[tc]

				load += caseSeconds(tc)
			}

			if minLoad < 0 || load < minLoad {
				minLoad = load
			}
			maxLoad = max(maxLoad, load)
		}

		require.Len(t, seen, len(allTestCases))
		require.LessOrEqual(t, maxLoad-minLoad, longest)
	}
}
