package tapdb

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightningnetwork/lnd/clock"
	"github.com/stretchr/testify/require"
)

// Common indices for universe tables.
const (
	// createUniverseRootIndex optimizes lookups on universe roots.
	createUniverseRootIndex = `
		CREATE INDEX IF NOT EXISTS idx_universe_roots_composite
		ON universe_roots(
			namespace_root,
			proof_type,
			asset_id
		);`

	// createUniverseLeavesIndex optimizes universe leaf queries.
	createUniverseLeavesIndex = `
		CREATE INDEX IF NOT EXISTS idx_universe_leaves_composite
		ON universe_leaves(
			leaf_node_namespace,
			universe_root_id,
			leaf_node_key
		);`

	// createMSMTNodesIndex optimizes MSSMT node lookups.
	createMSMTNodesIndex = `
		CREATE INDEX IF NOT EXISTS idx_mssmt_nodes_composite
		ON mssmt_nodes(
			namespace,
			key,
			hash_key,
			sum
		);`
)

// executeSQLStatements executes a list of SQL statements with logging.
func executeSQLStatements(t *testing.T, db *BaseDB, statements []string,
	action string) {

	t.Logf("%s indices...", action)

	for _, stmt := range statements {
		_, err := db.Exec(stmt)
		if err != nil {
			t.Fatalf("Failed to %s index: %v\nStatement: %s",
				action, err, stmt)
		}
	}
}

// createIndices creates all required indices on the database.
func createIndices(t *testing.T, db *BaseDB) {
	statements := []string{
		createUniverseRootIndex,
		createUniverseLeavesIndex,
		createMSMTNodesIndex,
	}

	executeSQLStatements(t, db, statements, "Creating")
}

// dropIndices removes all custom indices from the database.
func dropIndices(t *testing.T, db *BaseDB) {
	statements := []string{
		`DROP INDEX IF EXISTS idx_universe_roots_composite`,
		`DROP INDEX IF EXISTS idx_universe_leaves_composite`,
		`DROP INDEX IF EXISTS idx_mssmt_nodes_composite`,
	}

	executeSQLStatements(t, db, statements, "Dropping")
}

// Query definitions for performance testing.
const (
	// fetchUniverseRootQuery returns root info for a given namespace.
	fetchUniverseRootQuery = `
		SELECT 
			universe_roots.asset_id, 
			group_key, 
			proof_type,
			mssmt_nodes.hash_key root_hash, 
			mssmt_nodes.sum root_sum,
			genesis_assets.asset_tag asset_name
		FROM universe_roots
		JOIN mssmt_roots 
			ON universe_roots.namespace_root = mssmt_roots.namespace
		JOIN mssmt_nodes 
			ON mssmt_nodes.hash_key = mssmt_roots.root_hash 
			AND mssmt_nodes.namespace = mssmt_roots.namespace
		JOIN genesis_assets
			ON genesis_assets.asset_id = universe_roots.asset_id
		WHERE mssmt_nodes.namespace = $1`

	// queryUniverseLeavesQuery gets leaf info for a namespace.
	queryUniverseLeavesQuery = `
		SELECT 
			leaves.script_key_bytes, 
			gen.gen_asset_id, 
			nodes.value AS genesis_proof, 
			nodes.sum AS sum_amt, 
			gen.asset_id
		FROM universe_leaves AS leaves
		JOIN mssmt_nodes AS nodes
			ON leaves.leaf_node_key = nodes.key 
			AND leaves.leaf_node_namespace = nodes.namespace
		JOIN genesis_info_view AS gen
			ON leaves.asset_genesis_id = gen.gen_asset_id
		WHERE leaves.leaf_node_namespace = $1 
			AND (leaves.minting_point = $2 OR $2 IS NULL)
			AND (leaves.script_key_bytes = $3 OR $3 IS NULL)`

	// queryAssetStatsQuery gets aggregated stats for assets.
	queryAssetStatsQuery = `
		WITH asset_supply AS (
			SELECT 
				gen.asset_id, 
				SUM(nodes.sum) AS supply
			FROM universe_leaves leaves
			JOIN universe_roots roots
				ON leaves.universe_root_id = roots.id
			JOIN mssmt_nodes nodes
				ON leaves.leaf_node_key = nodes.key 
				AND leaves.leaf_node_namespace = nodes.namespace
			JOIN genesis_info_view gen
				ON leaves.asset_genesis_id = gen.gen_asset_id
			WHERE roots.proof_type = 'issuance'
			GROUP BY gen.asset_id
		)
		SELECT asset_id, supply, COUNT(*) as num_leaves
		FROM asset_supply
		GROUP BY asset_id, supply`
)

// queryTest represents a test case for performance testing.
type queryTest struct {
	name    string
	query   string
	args    func(h *uniStatsHarness) []interface{}
	dbTypes []sqlc.BackendType
}

// testQueries defines the test cases and their compatible database types.
var testQueries = []queryTest{
	{
		name:  "fetch_universe_root",
		query: fetchUniverseRootQuery,
		args: func(h *uniStatsHarness) []interface{} {
			return []interface{}{h.assetUniverses[0].id.String()}
		},
		dbTypes: []sqlc.BackendType{
			sqlc.BackendTypeSqlite,
			sqlc.BackendTypePostgres,
		},
	},

	{
		name:  "query_universe_leaves",
		query: queryUniverseLeavesQuery,
		args: func(h *uniStatsHarness) []interface{} {
			return []interface{}{
				h.assetUniverses[0].id.String(),
				nil,
				nil,
			}
		},
		dbTypes: []sqlc.BackendType{
			sqlc.BackendTypeSqlite,
			sqlc.BackendTypePostgres,
		},
	},

	{
		name:  "query_asset_stats",
		query: queryAssetStatsQuery,
		args: func(h *uniStatsHarness) []interface{} {
			return []interface{}{}
		},
		dbTypes: []sqlc.BackendType{
			sqlc.BackendTypeSqlite,
			sqlc.BackendTypePostgres,
		},
	},
}

// logPerformanceAnalysis prints performance metrics for all test queries.
func logPerformanceAnalysis(t *testing.T, results map[string]*queryStats) {
	t.Log("\n=== Performance Analysis ===")

	for name, result := range results {
		t.Logf("\nQuery: %s (%d runs)", name, result.queries)

		t.Log("Query Plan:")
		t.Log(result.queryPlan)

		t.Logf("No indices exec time: %v", result.withoutIndices)
		t.Logf("With indices exec time: %v", result.withIndices)

		// Calculate improvement factor.
		var improvement float64
		if result.withIndices > 0 {
			improvement = float64(result.withoutIndices) /
				float64(result.withIndices)
		}

		t.Logf("Improvement: %.2fx", improvement)
	}
}

// getQueryPlan retrieves the execution plan for a query from the database.
func getQueryPlan(ctx context.Context, t *testing.T, db *BaseDB,
	q queryTest, h *uniStatsHarness) string {

	var (
		explainQuery string
		plan         strings.Builder
	)

	switch db.Backend() {
	case sqlc.BackendTypeSqlite:
		explainQuery = fmt.Sprintf("EXPLAIN QUERY PLAN %s", q.query)
		rows, err := db.QueryContext(ctx, explainQuery, q.args(h)...)
		require.NoError(t, err)

		for rows.Next() {
			var (
				selectid, order, from int
				detail                string
			)
			err := rows.Scan(&selectid, &order, &from, &detail)
			require.NoError(t, err)

			plan.WriteString(fmt.Sprintf(
				"--\nid: %d order: %d from: %d\n%s\n",
				selectid, order, from, detail))
		}
		rows.Close()

	case sqlc.BackendTypePostgres:
		explainQuery = fmt.Sprintf("EXPLAIN %s", q.query)
		rows, err := db.QueryContext(ctx, explainQuery, q.args(h)...)
		require.NoError(t, err)

		for rows.Next() {
			var planLine string
			err := rows.Scan(&planLine)
			if err != nil {
				t.Fatalf("failed to scan plan line: %v", err)
			}
			plan.WriteString(planLine + "\n")
		}
		rows.Close()

	case sqlc.BackendTypeUnknown:
		return "Unknown backend type"
	}

	return plan.String()
}

// executeQuery runs a query multiple times and measures execution time.
func executeQuery(ctx context.Context, t *testing.T, db *BaseDB,
	q queryTest, h *uniStatsHarness) time.Duration {

	start := time.Now()

	for i := 0; i < numQueries; i++ {
		rows, err := db.QueryContext(ctx, q.query, q.args(h)...)
		require.NoError(t, err)
		rows.Close()
	}

	return time.Since(start)
}

// supportsQuery checks if a query is supported by the given database type.
func supportsQuery(dbType sqlc.BackendType,
	dbTypes []sqlc.BackendType) bool {

	for _, t := range dbTypes {
		if t == dbType {
			return true
		}
	}

	return false
}

// queryStats tracks performance metrics for a single query test.
type queryStats struct {
	name           string
	withoutIndices time.Duration
	withIndices    time.Duration
	queries        int
	queryPlan      string
}

// TestUniverseIndexPerformance tests the performance impact
// of database indices.
func TestUniverseIndexPerformance(t *testing.T) {
	t.Parallel()

	testResults := make(map[string]*queryStats)

	// runTest executes all queries with or without indices.
	runTest := func(withIndices bool) {
		testName := fmt.Sprintf("indices=%v", withIndices)

		t.Run(testName, func(t *testing.T) {
			// Create context with reasonable timeout.
			ctx, cancel := context.WithTimeout(
				context.Background(), 5*time.Minute,
			)
			defer cancel()

			db := NewTestDB(t)
			sqlDB := db.BaseDB

			// Set reasonable connection limits.
			sqlDB.SetMaxOpenConns(25)
			sqlDB.SetMaxIdleConns(25)
			sqlDB.SetConnMaxLifetime(time.Minute * 5)

			testClock := clock.NewTestClock(time.Now())
			statsDB, _ := newUniverseStatsWithDB(
				db.BaseDB,
				testClock,
			)

			// Add progress tracking.
			t.Logf("Gen test data: %d assets, %d leaves/tree",
				numAssets, numLeavesPerTree)

			h := newUniStatsHarness(
				t,
				numAssets,
				db.BaseDB,
				statsDB,
			)
			require.NotNil(t, h)

			if withIndices {
				createIndices(t, sqlDB)
			} else {
				dropIndices(t, sqlDB)
			}

			// Execute each test query.
			for _, q := range testQueries {
				t.Logf("\n=== Query Plan for %s ===", q.name)

				// Skip unsupported queries.
				if !supportsQuery(sqlDB.Backend(), q.dbTypes) {
					t.Skipf("Query %s unsupported "+
						"by backend %v",
						q.name, sqlDB.Backend())
					continue
				}

				plan := getQueryPlan(ctx, t, sqlDB, q, h)
				t.Logf("Query Plan:\n%s", plan)

				// Execute the query repeatedly.
				queryTime := executeQuery(ctx, t, sqlDB, q, h)

				// Record results.
				stat, ok := testResults[q.name]
				if !ok {
					stat = &queryStats{
						name: q.name,
					}
					testResults[q.name] = stat
				}

				stat.queries = numQueries
				stat.queryPlan = plan
				if withIndices {
					stat.withIndices = queryTime
				} else {
					stat.withoutIndices = queryTime
				}

				t.Logf("%s executed in: %v", q.name, queryTime)
			}

			logPerformanceAnalysis(t, testResults)
		})
	}

	// Run tests with and without indices.
	runTest(false)
	runTest(true)
}
