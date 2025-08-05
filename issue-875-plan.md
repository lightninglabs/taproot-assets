# Implementation Plan for Issue #875

**Issue URL**: https://github.com/lightninglabs/taproot-assets/issues/875
**Title**: [feature]: Paginate `ListAssets` RPC
**Created**: 2024-04-11T09:33:13Z
**Labels**: enhancement, optimization, scalability, performance, pagination

## Issue Summary

The `ListAssets`, `ListGroups`, `ListUtxos`, and `AddrReceives` RPC calls currently return all items without pagination support. This causes significant performance issues as datasets grow - with 250 asset UTXOs taking approximately 1 second to list. The issue requires implementing pagination following existing patterns using `offset`, `limit`, and `direction` parameters to avoid bottlenecks and improve scalability.

## Technical Analysis

### Current State
- **Performance Issue**: 250 UTXOs = 1 second response time, scaling linearly
- **Memory Inefficiency**: All results loaded into memory simultaneously
- **Implementation Gap**: `/Users/roasbeef/gocode/src/github.com/lightninglabs/query-assets-pages/rpcserver.go:1162` contains TODO confirming pagination need
- **Filtering Limitation**: Current filtering happens in Go code after fetching all records from database

### Proposed Changes
- Add pagination parameters to request messages following existing patterns
- Implement database-level pagination with LIMIT/OFFSET clauses
- Move filtering logic from application layer to SQL WHERE clauses
- Add cursor-based pagination for improved performance at scale
- Implement complementary count RPCs (issue #1699) for UI support

### Affected Components
**Proto Definitions:**
- `/Users/roasbeef/gocode/src/github.com/lightninglabs/query-assets-pages/taprpc/taprootassets.proto`
  - ListAssetRequest (lines 210-255)
  - ListUtxosRequest (lines 611-621)
  - ListGroupsRequest (lines 659-660)
  - AddrReceivesRequest (lines 1471-1477)

**RPC Implementations:**
- `/Users/roasbeef/gocode/src/github.com/lightninglabs/query-assets-pages/rpcserver.go`
  - ListAssets (lines 1086-1356)
  - ListUtxos (lines 1360-1426)
  - ListGroups (lines 1429-1476)
  - AddrReceives (lines 2187-2260)

**Database Layer:**
- `/Users/roasbeef/gocode/src/github.com/lightninglabs/query-assets-pages/tapdb/assets_store.go`
- `/Users/roasbeef/gocode/src/github.com/lightninglabs/query-assets-pages/tapdb/sqlc/queries/assets.sql`
- `/Users/roasbeef/gocode/src/github.com/lightninglabs/query-assets-pages/tapdb/addrs.go`

## Implementation Strategy

### Phase 1: Proto Definition Updates
- [ ] Add PaginationParams message type with limit, offset, and cursor fields
- [ ] Add PaginationResponse message type with metadata (total_count, has_more, next_cursor)
- [ ] Update all four request messages with optional pagination field
- [ ] Update all four response messages with pagination metadata
- [ ] Regenerate protobuf bindings

### Phase 2: Database Query Updates
- [ ] Create new paginated SQL queries in `/tapdb/sqlc/queries/assets.sql`
  - [ ] QueryAssetsPaginated with LIMIT/OFFSET support
  - [ ] CountAssets for total count without fetching data
  - [ ] FetchGroupedAssetsPaginated for groups
  - [ ] FetchManagedUTXOsPaginated for UTXOs
  - [ ] FetchAddrEventsPaginated for address events
- [ ] Add database indexes for efficient pagination:
  ```sql
  CREATE INDEX assets_pagination_idx ON assets(asset_id, spent);
  CREATE INDEX utxos_pagination_idx ON managed_utxos(utxo_id);
  CREATE INDEX addr_events_pagination_idx ON addr_events(creation_time, id);
  ```
- [ ] Regenerate SQLC code

### Phase 3: Asset Store Layer Updates
- [ ] Implement FetchAllAssetsPaginated in assets_store.go
- [ ] Implement FetchGroupedAssetsPaginated 
- [ ] Implement FetchManagedUTXOsPaginated
- [ ] Implement FetchAddrEventsPaginated
- [ ] Add cursor encoding/decoding logic
- [ ] Handle edge cases (empty results, out-of-bounds)

### Phase 4: RPC Server Implementation
- [ ] Update ListAssets to use paginated database queries
- [ ] Remove in-memory filtering (line 1162 TODO)
- [ ] Update ListUtxos with pagination support
- [ ] Update ListGroups with pagination support
- [ ] Update AddrReceives with pagination support
- [ ] Implement backwards compatibility (default behavior when no pagination params)
- [ ] Add request parameter validation

### Phase 5: Count RPC Implementation (Issue #1699)
- [ ] Add CountAssets RPC method
- [ ] Add CountUtxos RPC method
- [ ] Add CountGroups RPC method
- [ ] Add CountAddrReceives RPC method
- [ ] Implement efficient COUNT queries without data fetching

### Phase 6: CLI Updates
- [ ] Update `/cmd/commands/assets.go` with pagination flags
- [ ] Update `/cmd/commands/addrs.go` with pagination flags
- [ ] Add --page-size and --page flags to relevant commands
- [ ] Update CLI output formatting for paginated results

## Technical Considerations

### Architecture Impact
- **Cursor-based pagination recommended** over offset-based for performance at scale
- **Database indexes critical** for sub-second response times
- **Connection pooling** needs optimization for concurrent paginated requests
- **Caching strategy**: 30-second TTL for consistency with limited result caching

### Security Considerations
- **Input Validation Required**:
  - Limit max page size to 1000 records
  - Validate offset/cursor parameters to prevent integer overflow
  - Sanitize cursor content to prevent injection attacks
- **Rate Limiting**: Implement per-IP rate limits to prevent DoS via rapid pagination
- **Resource Limits**: Set maximum memory usage per request (10MB recommended)
- **Privacy**: Ensure cursor doesn't leak sensitive information
- **Authorization**: Maintain existing access controls with pagination

### Performance Implications
- **Expected Improvements**:
  - Response time: 1s → 50-100ms for 250 UTXOs (20x improvement)
  - Memory usage: O(n) → O(page_size)
  - Network bandwidth: 90% reduction for typical use cases
- **Database Optimization**:
  - Use covering indexes for common query patterns
  - Implement query plan caching
  - Consider read replicas for heavy pagination loads

### Dependencies
- No external library dependencies required
- Must maintain compatibility with existing gRPC clients
- Coordinate with frontend teams for UI pagination components

## Testing Plan

### Unit Tests
- Pagination parameter validation (boundary conditions, invalid inputs)
- Cursor encoding/decoding logic
- Database query generation with various filters
- Empty result set handling
- Default parameter behavior

### Integration Tests
- Multi-page traversal consistency
- Concurrent pagination requests
- Real-time data modifications during pagination
- Backwards compatibility verification
- Large dataset handling (1000+ items)

### End-to-End Tests
- CLI pagination commands
- gRPC client pagination flows
- Performance benchmarks (250, 500, 1000 UTXOs)
- Memory usage monitoring
- Database connection pool stress testing

### Edge Cases to Test
- Page size = 0 (should use default)
- Offset beyond total count
- Invalid/tampered cursor values
- Pagination during active minting/spending
- Database transaction isolation

## Reviewer Checklist

**Important points for PR reviewers:**

- [ ] Proto changes maintain backwards compatibility
- [ ] Database queries use parameterized statements (no SQL injection risk)
- [ ] Input validation prevents DoS attacks (max limits enforced)
- [ ] Cursor implementation doesn't leak internal state
- [ ] Database indexes added for all pagination queries
- [ ] Memory usage bounded per request
- [ ] Error messages don't expose sensitive information
- [ ] Tests cover all edge cases and security scenarios
- [ ] Documentation updated with pagination examples
- [ ] Performance meets targets (<100ms for 250 UTXOs)

## Implementation Notes

### Code Conventions
- Follow existing pagination pattern from Universe RPCs
- Use established `offset`/`limit`/`direction` parameter names
- Maintain consistent error handling patterns
- Use context for request cancellation support

### Potential Gotchas
- Current in-memory filtering at line 1162 must be moved to SQL
- Asset witness data can be large - consider separate pagination
- Group pagination needs special handling for grouped results
- Address events have time-based ordering requirements

### Alternative Approaches Considered
- **gRPC Streaming**: Rejected due to poor backwards compatibility and client complexity
- **Offset-only pagination**: Rejected due to O(n) performance degradation
- **Fixed page sizes**: Rejected to maintain flexibility for different use cases

## Estimated Effort

- **Development**: 3-4 days
- **Testing**: 2 days
- **Code Review**: 1 day
- **Total**: 6-7 days

## Success Criteria

- [ ] ListAssets responds in <100ms for 250 UTXOs
- [ ] Memory usage stays below 10MB per request
- [ ] All existing clients continue to work without modifications
- [ ] Database CPU usage reduced by >50% for large asset lists
- [ ] No security vulnerabilities introduced (passes security audit)
- [ ] 100% test coverage for pagination logic
- [ ] Documentation includes clear pagination examples

## Additional Context for Implementation Agent

### Example Pagination Request
```proto
ListAssetRequest {
    with_witness: true,
    include_spent: false,
    pagination: {
        limit: 50,
        offset: 0,
        cursor: "" // For subsequent pages
    }
}
```

### Example Paginated SQL Query
```sql
-- Based on existing QueryAssets, add pagination
SELECT * FROM assets 
JOIN genesis_info_view ON assets.genesis_id = genesis_info_view.gen_asset_id
WHERE spent = false
ORDER BY asset_id
LIMIT $1 OFFSET $2;
```

### Cursor Structure (Base64 encoded JSON)
```json
{
    "last_id": 12345,
    "last_timestamp": "2024-04-11T09:33:13Z",
    "direction": "asc",
    "filter_hash": "abc123" // Hash of active filters for consistency
}
```

---
*This plan was generated with ultra-deep analysis and parallel investigation of all technical aspects.*