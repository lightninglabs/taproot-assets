# PSBT Debugging Quick Reference Card

## Error → Root Cause → Fix Mapping

| Error Message | Likely Cause | Quick Fix |
|--------------|--------------|-----------|
| `Skipping input X, derived public key XXX does not match YYY` | BIP32 path mismatch | Check KeyFamily/KeyIndex storage |
| `script path spend without tapscript merkle root` | Missing PSBT field | Set `TaprootMerkleRoot` in PInput |
| `could not finalize PSBT` | Multiple possible causes | Check lnd debug logs for specifics |
| `witness program invalid version` | Wrong address type | Verify taproot vs segwit usage |
| `non-mandatory-script-verify-flag` | Script execution failed | Check witness stack construction |

## Critical Code Locations

### Supply Commitment Keys
```go
// tapdb/supply_commit.go:905
// MUST preserve full key descriptor:
internalKeyID, err := db.UpsertInternalKey(ctx, InternalKey{
    RawKey:    internalKeyDesc.PubKey.SerializeCompressed(),
    KeyFamily: int32(internalKeyDesc.Family),  // ← CRITICAL
    KeyIndex:  int32(internalKeyDesc.Index),   // ← CRITICAL
})
```

### PSBT Input Construction
```go
// universe/supplycommit/transitions.go:464
// BIP32 derivation must match stored key:
bip32Derivation, trBip32Derivation := 
    tappsbt.Bip32DerivationFromKeyDesc(
        r.InternalKey,  // Must be full KeyDescriptor
        chainParams.HDCoinType,
    )
```

### Tapscript Root for Script Spends
```go
// For script path spends:
psbtInput.TaprootMerkleRoot = merkleRootBytes  // REQUIRED
psbtInput.TaprootLeafScript = []psbt.TaprootTapLeafScript{
    {
        ControlBlock: controlBlock,
        Script:       leafScript,
        LeafVersion:  tapscript.BaseLeafVersion,
    },
}
```

## Debug Commands

```bash
# Find signing errors in lnd logs
grep -n "SignPsbt.*Skipping" ~/.lnd/logs/bitcoin/regtest/lnd.log

# Check key storage in database
sqlite3 ~/.tapd/data/regtest/tapd.db \
  "SELECT key_family, key_index, hex(raw_key) FROM internal_keys;"

# Decode PSBT to check fields
echo "cHNidP8B..." | base64 -d | xxd  # Raw view
bitcoin-cli decodepsbt "cHNidP8B..."  # Structured view

# Track supply commit operations
grep -E "SupplyCommit|InsertSignedCommitTx|UpsertInternalKey" *.log
```

## Key Data Structures

### KeyDescriptor (ALWAYS use for signing keys)
```go
type KeyDescriptor struct {
    PubKey *btcec.PublicKey
    Family KeyFamily  // MUST preserve
    Index  uint32     // MUST preserve
}
```

### PSBT Input Fields for Taproot
```go
type PInput struct {
    WitnessUtxo       *wire.TxOut           // Required
    TaprootBip32Path  []Bip32Derivation     // For key path
    TaprootMerkleRoot []byte                // For script path
    TaprootLeafScript []TaprootTapLeafScript // Script details
}
```

## Verification Checklist

**Before PSBT Signing:**
- [ ] All inputs have WitnessUtxo set
- [ ] BIP32 derivation paths are correct
- [ ] For taproot: merkle root set if script spend
- [ ] Internal keys have Family/Index preserved

**After Fixing Issues:**
- [ ] No "Skipping input" warnings in logs
- [ ] PSBT finalizes successfully
- [ ] Transaction broadcasts without errors
- [ ] Unit tests pass: `go test ./tapdb/...`
- [ ] Integration tests pass: `make itest`

## Common Mistakes

1. **Using raw pubkey instead of KeyDescriptor**
   ```go
   // WRONG
   type CommitTxn struct {
       InternalKey *btcec.PublicKey
   }
   
   // CORRECT
   type CommitTxn struct {
       InternalKey keychain.KeyDescriptor
   }
   ```

2. **Not preserving key metadata in storage**
   ```go
   // WRONG - loses derivation info
   UpsertInternalKey(ctx, InternalKey{
       RawKey: key.SerializeCompressed(),
   })
   
   // CORRECT - preserves everything
   UpsertInternalKey(ctx, InternalKey{
       RawKey:    key.PubKey.SerializeCompressed(),
       KeyFamily: int32(key.Family),
       KeyIndex:  int32(key.Index),
   })
   ```

3. **Missing tapscript fields for script spends**
   ```go
   // Script path spends need:
   psbtInput.TaprootMerkleRoot = root  // MANDATORY
   psbtInput.TaprootLeafScript = [...]  // Script details
   ```

## Emergency Fixes

### Force Key Recovery
```sql
-- If keys lost Family/Index, try common values:
UPDATE internal_keys 
SET key_family = 300,  -- TaprootAssetsKeyFamily 
    key_index = 0 
WHERE key_family = 0 AND key_index = 0;
```

### PSBT Field Addition
```go
// Quick fix to add missing merkle root:
if isScriptSpend && psbtIn.TaprootMerkleRoot == nil {
    tree := txscript.AssembleTaprootScriptTree(tapLeaf)
    root := tree.RootNode.TapHash()
    psbtIn.TaprootMerkleRoot = root[:]
}
```

## Related Files to Check

- `tapdb/supply_commit.go` - Supply commitment storage
- `tapdb/assets_common.go` - Key parsing functions  
- `universe/supplycommit/transitions.go` - PSBT creation
- `universe/supplycommit/env.go` - Data structures
- `tappsbt/interface.go` - BIP32 derivation helpers
- `lnwallet/btcwallet/psbt.go` (lnd) - PSBT signing logic