# Taproot Assets Wallet Backup

This document describes the wallet backup system for Taproot Assets (`tapd`),
covering the binary format, the stripping/rehydration mechanism for compact
backups, stale-backup detection, and the RPC interface.

## Overview

A wallet backup captures every active (unspent, non-burned) asset together with
its proof file and key derivation info. On import, the receiving node registers
the keys and ingests the proofs, making the assets spendable.

Two backup versions exist:

| Version | Constant | Description |
|---------|----------|-------------|
| 1 | `BackupVersionOriginal` | Full proof blobs stored as-is |
| 2 | `BackupVersionStripped` | Blockchain-derivable fields stripped; rehydration hints stored instead |

---

## Binary Format

### Top-level layout

```
+-----------------+
| "TAPBAK"        |  Magic bytes (6 bytes, ASCII)
+-----------------+
| version         |  uint32, big-endian (1 or 2)
+-----------------+
| num_assets      |  varint (1-9 bytes)
+-----------------+
| asset_0         |  varint length prefix + TLV stream
+-----------------+
| ...             |
+-----------------+
| asset_N         |  varint length prefix + TLV stream
+-----------------+
| checksum        |  SHA-256 over all preceding bytes (32 bytes)
+-----------------+
```

### Per-asset TLV records

Each asset is a length-prefixed TLV stream. Records **must** appear in
ascending type order. Odd types are safe to skip by decoders that don't
recognize them.

| Type | Name | Required | Description |
|------|------|----------|-------------|
| 0 | Asset | yes | `asset.Asset` encoded blob |
| 1 | AnchorOutpoint | yes | The UTXO where the asset is anchored |
| 2 | AnchorBlockHeight | yes | Confirmation block height (`uint32`) |
| 3 | ScriptKey | no | `ScriptKeyBackup` — tweaked key + derivation info |
| 4 | AnchorInternalKey | no | `KeyDescriptorBackup` — anchor key derivation info |
| 5 | ProofFileBlob | v1 only | Complete proof file (full chain) |
| 6 | AnchorPkScript | no | `pk_script` of the anchor output (for spend detection) |
| 7 | StrippedProofBlob | v2 only | Proof file with blockchain fields removed |
| 9 | RehydrationHints | v2 only | Serialized `FileHints` needed to reconstruct stripped fields |

Types 7 and 9 are odd, so a v1-only decoder will safely skip them.

**v1 record order:** 0, 1, 2, [3], [4], 5, [6]

**v2 record order:** 0, 1, 2, [3], [4], [6], 7, 9

### ScriptKeyBackup TLV

| Type | Name | Description |
|------|------|-------------|
| 0 | PubKey | Final tweaked script key (33 bytes, compressed) |
| 1 | Family | Key family (`uint32`) |
| 2 | Index | Key index (`uint32`) |
| 3 | RawPubKey | Pre-tweak internal public key (33 bytes) |
| 4 | Tweak | Tweak bytes; absent means BIP-86 |

### KeyDescriptorBackup TLV

| Type | Name | Description |
|------|------|-------------|
| 0 | PubKey | Public key (33 bytes, compressed) |
| 1 | Family | Key family (`uint32`) |
| 2 | Index | Key index (`uint32`) |

### Decode safety limits

| Constant | Value | Purpose |
|----------|-------|---------|
| `maxBackupAssets` | 1,000,000 | Max asset count before OOM rejection |
| `maxTLVSize` | 100 MB | Max single-asset TLV payload size |

---

## Compact Backups (v2): Strip and Rehydrate

### Motivation

A full proof file stores the block header, anchor transaction, tx merkle
proof, and block height for every proof transition. These fields are
deterministically derivable from the blockchain and therefore redundant in a
backup — stripping them significantly reduces size.

### Stripped fields

| Proof TLV Type | Field | Typical Size |
|----------------|-------|-------------|
| 4 | BlockHeader | 80 bytes |
| 6 | AnchorTx | ~250-500 bytes |
| 8 | TxMerkleProof | ~200-300 bytes |
| 22 | BlockHeight | 4 bytes |

Everything else (asset leaf, inclusion/exclusion proofs, split root proof,
meta reveal, additional inputs, etc.) is kept.

### Rehydration hints

For each proof transition in the file, a `ProofHint` is stored:

```
ProofHint = [32 bytes AnchorTxHash] [4 bytes BlockHeight BE]
```

The full `FileHints` blob is:

```
[varint num_hints] [hint_0] [hint_1] ... [hint_N]
```

At 36 bytes per hint, this is far smaller than the fields it replaces.

### Strip / Rehydrate flow

```mermaid
flowchart LR
    subgraph Export
        A[Full Proof File] -->|StripProofFile| B[Stripped Blob]
        A -->|StripProofFile| C[FileHints]
    end

    subgraph Backup File
        B --> D[Type 7: StrippedProofBlob]
        C --> E[Type 9: RehydrationHints]
    end

    subgraph Import
        D --> F[RehydrateProofFile]
        E --> F
        G[Blockchain via ChainQuerier] --> F
        F --> H[Full Proof File]
    end
```

**`StripProofFile(proofBlob) -> (strippedBlob, FileHints, error)`**

1. Decode the proof file.
2. For each proof transition, record `{AnchorTxHash, BlockHeight}` as a hint.
3. Re-encode each proof omitting types 4, 6, 8, 22.
4. Return stripped blob + hints.

**`RehydrateProofFile(ctx, strippedBlob, hints, chain) -> (fullBlob, error)`**

1. Decode the stripped proof file.
2. Verify `len(hints) == numProofs`.
3. For each proof transition `i`:
   - Fetch block via `chain.GetBlockByHeight(hint.BlockHeight)`.
   - Set `BlockHeader = block.Header`.
   - Set `BlockHeight = hint.BlockHeight`.
   - Find anchor tx in block by `hint.AnchorTxHash`.
   - Set `AnchorTx` and reconstruct `TxMerkleProof`.
4. Encode the rehydrated file and return.

The `ChainQuerier` interface is:

```go
type ChainQuerier interface {
    GetBlockByHeight(ctx context.Context, blockHeight int64) (*wire.MsgBlock, error)
}
```

Satisfied by `tapgarden.ChainBridge` in production.

---

## Stale Backup Detection

When importing, the node checks on-chain whether each asset's anchor outpoint
has already been spent. A spent outpoint means the asset has moved (transferred
or re-anchored), making the backup entry stale.

```mermaid
sequenceDiagram
    participant Import as Import Handler
    participant LND as lnd ChainNotifier
    participant Chain as Bitcoin Node

    Import->>LND: RegisterSpendNtfn(outpoint, pkScript, heightHint) x N

    par For each outpoint (concurrent)
        LND->>Chain: GetTxOut (UTXO set check)

        alt Spent
            Chain-->>LND: not found
            LND-->>Import: SpendDetail (immediate)
        else Unspent
            Chain-->>LND: found
            Note over Import: 10s timeout fires
            Import-->>Import: mark as unspent
        end
    end

    Import->>Import: Skip assets with spent outpoints
```

- All outpoints are checked concurrently via goroutines.
- Each goroutine has a per-asset `10s` timeout (`spendCheckTimeout`).
- Spent outpoints resolve near-instantly (lnd checks the UTXO set
  synchronously); only unspent outpoints wait for the timeout.
- Note: the `RegisterSpendNtfn` calls are dispatched sequentially before
  the goroutines begin waiting, so for very large wallets (tens of
  thousands of assets) the dispatch loop itself adds latency on top of
  the 10s timeout window.

---

## RPC Interface

### `ExportAssetWalletBackup`

Exports all active wallet assets as a backup blob.

```protobuf
rpc ExportAssetWalletBackup(ExportAssetWalletBackupRequest)
    returns (ExportAssetWalletBackupResponse);

message ExportAssetWalletBackupRequest {
    bool compact = 1;  // true = v2 (stripped), false = v1 (full)
}

message ExportAssetWalletBackupResponse {
    bytes backup = 1;  // The binary backup blob
}
```

### `ImportAssetsFromBackup`

Imports assets from a previously exported backup blob.

```protobuf
rpc ImportAssetsFromBackup(ImportAssetsFromBackupRequest)
    returns (ImportAssetsFromBackupResponse);

message ImportAssetsFromBackupRequest {
    bytes backup = 1;  // Backup blob from ExportAssetWalletBackup
}

message ImportAssetsFromBackupResponse {
    uint32 num_imported = 1;  // Number of newly imported assets
}
```

### Export flow

```mermaid
flowchart TD
    A[ExportAssetWalletBackup] --> B[Fetch all active assets]
    B --> C[CollectAssetBackups: fetch proofs + key info]
    C --> D{compact?}
    D -->|yes| E[StripProofFile for each asset]
    E --> F[Set version = 2]
    D -->|no| F2[Set version = 1]
    F --> G[Encode WalletBackup + SHA-256 checksum]
    F2 --> G
    G --> H[Return backup blob]
```

### Import flow

```mermaid
flowchart TD
    A[ImportAssetsFromBackup] --> B[Decode + verify checksum]
    B --> C[detectSpentOutpoints — concurrent spend check]
    C --> D[For each asset]
    D --> E{Outpoint spent?}
    E -->|yes| F[Skip — log warning]
    E -->|no| G{Already exists?}
    G -->|yes| H[Skip — idempotent]
    G -->|no| I{v2 stripped?}
    I -->|yes| J[RehydrateProofFile from chain]
    I -->|no| K[Use proof blob as-is]
    J --> L[Register anchor internal key]
    K --> L
    L --> M[Register script key]
    M --> N[Import proof into archive]
    N --> O[Increment count]
    O --> D
    D -->|done| P[Return num_imported]
```

