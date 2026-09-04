# Asset Wallet Backup File

`tapd` keeps an encrypted backup of every asset the wallet owns in a single
file on disk and updates that file whenever the wallet state changes. Copying
this file somewhere safe is the recommended way to protect against the loss of
the `tapd` database. Together with the `lnd` seed it is enough to recover all
confirmed, unspent assets.

This guide explains what the file covers, how to keep a copy of it and how to
restore from it. The binary format and the update mechanism are documented in
[backup.md](backup.md).

## What the file protects

The file holds one entry per confirmed, unspent asset output the wallet
controls. Each entry contains the asset itself, the anchor outpoint, the key
derivation paths for the script key and the anchor internal key, and a compact
copy of the proof chain. That is everything a fresh `tapd` needs to recognise
the output as its own, verify its history and spend it.

The file does **not** cover:

- The `lnd` wallet. The seed still has to be backed up separately, all asset
  keys are derived from it.
- Lightning channels carrying assets. Leaves that fund asset channels are
  left out of the file, they are covered by `lnd`'s `channel.backup` and the
  channel funding state in the `tapd` database.
- Unconfirmed receives and sends. An output enters the file once its anchor
  transaction confirms.
- Addresses, universe and federation state, minting batches that have not
  confirmed yet, and transfer history.

A regular backup of the `tapd` database (see [safety.md](safety.md)) remains
the complete backup. The file is the safety net for the case where the
database is gone.

## Where the file is

By default:

```
<datadir>/<network>/assets.backup
```

which on Linux is `~/.tapd/data/mainnet/assets.backup`. The location can be
changed with the `backup.filepath` option and the file can be turned off with
`backup.disable`:

```
[backup]
backup.filepath=/mnt/secure/assets.backup
backup.disable=false
```

If the configured directory does not exist it is created on the first write.
The path has to name a file, `tapd` refuses to start if it points at a
directory.

The file is written on startup, after every wallet change, and once more on
shutdown. Writes are atomic: a new version is written next to the file and then
renamed over it, so a copy taken at any moment is either the previous or the
new complete version, never a partial one.

## How the file is protected

The file is encrypted with a key derived from the `lnd` wallet, the same key
`lnd` uses for `channel.backup`. Only a `tapd` connected to an `lnd` that was
created or restored from the same seed can read it. The file can therefore be
stored anywhere, including cloud storage, without exposing which outputs the
wallet owns.

Keep in mind that whoever holds both the seed and the file can see everything
the wallet owns. Treat the seed as the secret, the file as the data.

## Keeping a copy

The file changes whenever assets are minted, received or sent. Copy it to a
second location whenever it changes, for example with a file watcher or a
periodic sync job. An older copy is safe to restore from, it simply does not
contain outputs received after it was taken, and outputs it lists that have
since been spent are skipped on import. Outputs spent while `tapd` was not
running are removed from the file on the next start.

To check that a copy can be read, import it into the node that wrote it. This
is a no-op and reports zero imported assets if the file is readable and up to
date:

```
$ tapcli assets backup import --backup_file=/path/to/assets.backup
{
    "num_imported": 0,
    "num_skipped": 0
}
```

A copy that was taken from a node with a different seed fails instead:

```
[tapcli] unable to import backup: ... unable to decrypt backup:
chacha20poly1305: message authentication failed
```

## Restoring from the file

Restore is a three step process. It assumes the `lnd` node is already running
with the wallet restored from the same seed.

1. **Start a fresh `tapd`** against the restored `lnd`. An empty data
   directory is the clean way to do this. Removing only the database
   (`tapd.db*`) and leaving the rest of the directory in place works as
   well, leftover proof files do not affect the import. Either way the node
   has no assets yet:

   ```
   $ tapcli assets list
   {
       "assets": []
   }
   ```

2. **Import the backup file:**

   ```
   $ tapcli assets backup import --backup_file=/path/to/assets.backup
   {
       "num_imported": 3,
       "num_skipped": 0
   }
   ```

   The import checks on chain whether every listed output is still unspent
   before touching anything, so expect it to take around ten seconds.

   `num_imported` is the number of asset outputs that were recovered.
   `num_skipped` counts entries that could not be imported because their data
   did not verify. Entries whose anchor output was already spent are neither
   imported nor counted as skipped, they are silently left out since they hold
   no value.

3. **Verify:**

   ```
   $ tapcli assets list
   ```

   should now list the recovered assets, and the new node's own backup file
   picks them up shortly after.

The import registers the recovered keys with the `lnd` wallet so the outputs
can be spent right away. Importing the same file again is harmless and reports
zero imported assets.

## Manual exports

The `tapcli assets backup export` command still exists and produces a
plaintext snapshot in the format of your choice. The file and the manual
export complement each other:

| | Backup file | Manual export |
|---|---|---|
| Kept up to date | automatically | when you run it |
| Encrypted | yes, wallet key | no |
| Proof data | compact | raw, compact or optimistic |
| Import command | `tapcli assets backup import` | `tapcli assets backup import` |

Both are accepted by the same import command, which detects the format from the
file contents.

## Known limitations

- The import restores the assets but does not advance the `lnd` key family
  counters. After a restore, `tapd` derives new keys starting from where the
  restored `lnd` wallet stands, which may reuse indexes that the old node had
  already handed out. This is being addressed separately.
- A backup file at the configured path that cannot be decrypted with the
  wallet key stops `tapd` from starting:

  ```
  unable to start backup file updater: existing backup file cannot be
  decrypted with the wallet key: unable to decrypt backup: ...
  ```

  This protects a file that most likely belongs to another seed from being
  overwritten. Move the file away or point `backup.filepath` elsewhere to
  proceed.
