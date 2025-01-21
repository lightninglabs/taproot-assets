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
			namespace_root, proof_type, asset_id
		);`

	// createUniverseLeavesIndex optimizes universe leaf queries.
	createUniverseLeavesIndex = `
		CREATE INDEX IF NOT EXISTS idx_universe_leaves_asset
		ON universe_leaves(
			asset_genesis_id, universe_root_id
		);`

	// createMSMTNodesIndex optimizes MSSMT node lookups.
	createMSMTNodesIndex = `
		CREATE INDEX IF NOT EXISTS idx_mssmt_nodes_composite
		ON mssmt_nodes(
			namespace, key, hash_key, sum
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
		`DROP INDEX IF EXISTS idx_universe_leaves_asset`,
		`DROP INDEX IF EXISTS idx_mssmt_nodes_composite`,
		// Instead of dropping an index, we restore the old, inefficient
		// view that was present before migration #27.
		`DROP VIEW universe_stats`,
		`CREATE VIEW universe_stats AS
		  SELECT
		    COUNT(CASE WHEN u.event_type = 'SYNC' THEN 1 ELSE NULL END)
                      AS total_asset_syncs,
		    COUNT(CASE WHEN u.event_type = 'NEW_PROOF' THEN 1 
                      ELSE NULL END) AS total_asset_proofs,
		    roots.asset_id,
                    roots.group_key,
		    roots.proof_type
		  FROM universe_events u
		  JOIN universe_roots roots
		    ON u.universe_root_id = roots.id
		  GROUP BY roots.asset_id, roots.group_key, roots.proof_type`,
	}

	executeSQLStatements(t, db, statements, "Dropping")
}

// Query definitions for performance testing.
const (
	// queryAssetStatsQuery gets aggregated stats for assets. This
	// corresponds to the first part of the QueryUniverseAssetStats query.
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
		query: sqlc.FetchUniverseRoot,
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
		query: sqlc.QueryUniverseLeaves,
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

	{
		name:  "query_aggregated_stats",
		query: sqlc.QueryUniverseStats,
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

		closeErr := rows.Close()
		require.NoError(t, closeErr)
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

	// Create context with reasonable timeout.
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	testResults := make(map[string]*queryStats)

	// setupDB creates a new database and harness for testing, either
	// creating or dropping the supporting indices.
	setupDB := func(withIndices bool) (*BaseDB, *uniStatsHarness) {
		db := NewTestDB(t)
		sqlDB := db.BaseDB

		// Set reasonable connection limits.
		sqlDB.SetMaxOpenConns(25)
		sqlDB.SetMaxIdleConns(25)
		sqlDB.SetConnMaxLifetime(testTimeout)

		testClock := clock.NewTestClock(time.Now())
		statsDB, _ := newUniverseStatsWithDB(db.BaseDB, testClock)

		// Add progress tracking.
		t.Logf("Gen test data: %d assets, %d leaves/tree",
			numAssets, numLeavesPerTree)

		h := newUniStatsHarness(t, numAssets, db.BaseDB, statsDB)
		require.NotNil(t, h)

		// Generate some events for all assets.
		for range 10 {
			h.addEvents(numAssets)
		}

		if withIndices {
			createIndices(t, sqlDB)
		} else {
			dropIndices(t, sqlDB)
		}

		return sqlDB, h
	}

	// runTest executes a query with or without indices.
	runTest := func(t *testing.T, q queryTest, withIndices bool,
		sqlDB *BaseDB, h *uniStatsHarness) {

		t.Logf("\n=== Query Plan for %s ===", q.name)

		// Skip unsupported queries.
		if !supportsQuery(sqlDB.Backend(), q.dbTypes) {
			t.Skipf("Query %s unsupported by backend %v",
				q.name, sqlDB.Backend())
			return
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

	// Run tests with and without indices.
	for _, withIndices := range []bool{false, true} {
		sqlDB, h := setupDB(withIndices)

		for _, q := range testQueries {
			testName := fmt.Sprintf("name=%v,indices=%v", q.name,
				withIndices)
			t.Run(testName, func(t *testing.T) {
				runTest(t, q, withIndices, sqlDB, h)
			})
		}

		logPerformanceAnalysis(t, testResults)
	}
}
