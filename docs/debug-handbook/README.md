# Debug Handbook

This directory contains debugging guides for common issues encountered in taproot-assets development. Each guide provides pattern recognition techniques, debugging flowcharts, and proven resolution strategies.

## Available Guides

### [PSBT Finalization Failures](./psbt-finalization-failures.md)
Comprehensive guide for debugging PSBT signing and finalization issues, particularly those involving:
- BIP32 key derivation mismatches
- Missing tapscript merkle roots
- Supply commitment key storage problems

## How to Use This Handbook

1. **Identify symptoms** - Match error messages or behaviors to guide titles
2. **Follow the flowchart** - Each guide has a decision tree for systematic debugging
3. **Check common causes** - Most issues follow predictable patterns
4. **Apply the fix pattern** - Use provided code examples as templates
5. **Verify resolution** - Run the suggested verification steps

## Contributing New Guides

When you solve a difficult debugging problem, consider adding a guide:

### Guide Template

```markdown
# [Issue Name] - Debug Handbook

## Quick Identification
- List symptoms
- Common error messages
- Affected components

## Debug Flow Chart
- Mermaid flowchart showing decision points
- Clear paths to root causes

## Detailed Debugging Steps
- Step-by-step investigation process
- Where to look in code
- What to check in logs

## Common Pitfalls
- Things that often trip people up
- Non-obvious failure modes

## Prevention Strategies
- How to avoid this issue in the future
- Best practices

## External References
- Links to relevant documentation
- Related specifications or RFCs

## Quick Checklist
- [ ] Actionable debugging steps
```

### Good Guide Characteristics

1. **Symptom-focused** - Start with what developers will see
2. **Systematic approach** - Provide clear debugging methodology
3. **Code examples** - Show both wrong and right patterns
4. **Tool commands** - Include exact commands to run
5. **Cross-references** - Link to relevant code and docs
6. **Battle-tested** - Based on actual debugging experience

## General Debugging Tips

### Enable Comprehensive Logging
```bash
# Maximum verbosity for all components
export TAPD_DEBUG_LEVEL=debug
export LND_DEBUG_LEVEL=debug
export BTCD_DEBUG_LEVEL=debug
```

### Useful Log Grep Patterns
```bash
# Find errors across all logs
grep -i "error\|fail\|skip\|warn" itest/regtest/*.log

# Track RPC calls
grep "interceptor.go.*requested" *.log

# Find state transitions
grep -i "state.*transition\|ProcessEvent" *.log

# Database operations
grep -i "insert\|update\|upsert" *.log
```

### Component Interaction Points

Key interfaces where issues often occur:
- **tapd ↔ lnd**: PSBT signing, wallet operations
- **tapd ↔ btcd**: Transaction broadcast, block notifications
- **tapd ↔ universe**: Proof synchronization, supply commits
- **Database layer**: Key storage, state persistence

### Testing Strategies

1. **Isolate the failure**
   - Run single test case: `make itest icase=specific_test`
   - Use unit tests when possible: `go test -v -run TestSpecific`

2. **Simplify the scenario**
   - Reduce to minimum inputs
   - Remove unnecessary components
   - Test with regtest before testnet/mainnet

3. **Add strategic logging**
   ```go
   log.Debugf("Key details: family=%d, index=%d, pubkey=%x", 
       key.Family, key.Index, key.PubKey.SerializeCompressed())
   ```

4. **Verify assumptions**
   - Check database state matches expectations
   - Verify RPC responses contain expected fields
   - Ensure configuration is correct

## Debugging Tools

### Database Inspection
```bash
# SQLite database inspection
sqlite3 ~/.tapd/data/regtest/tapd.db

# Common queries
.tables  # List all tables
.schema supply_commitments  # Show table structure
SELECT * FROM internal_keys WHERE key_index != 0;  # Find non-zero indices
```

### PSBT Decoding
```bash
# Decode PSBT to human-readable format
bitcoin-cli decodepsbt "cHNidP8B..."

# Using btcdecode tool
echo "cHNidP8B..." | btcdecode -psbt
```

### Transaction Analysis
```bash
# Decode raw transaction
bitcoin-cli decoderawtransaction "0200000001..."

# Get transaction details
bitcoin-cli getrawtransaction "txid" true
```

## Common Abbreviations

- **PSBT**: Partially Signed Bitcoin Transaction
- **BIP32**: Hierarchical Deterministic key derivation
- **SMT/MSSMT**: Sparse Merkle Tree / Merkle Sum Sparse Merkle Tree
- **tapd**: Taproot Assets Daemon
- **lnd**: Lightning Network Daemon

## Learning Resources

- [Bitcoin Optech](https://bitcoinops.org/) - Bitcoin technology explained
- [BIPs Repository](https://github.com/bitcoin/bips) - Bitcoin Improvement Proposals
- [Taproot Assets Docs](https://docs.lightning.engineering/the-lightning-network/taproot-assets) - Official documentation
- [lnd Developer Docs](https://dev.lightning.community/) - Lightning Network development