# Taproot Assets Operational Safety Guidelines

As of version `v0.3.0-alpha`, Taproot Assets can be used on Bitcoin's `mainnet`
network. Meaning, in any version after `v0.3.0` there won't be any breaking
changes and any assets minted with that version should be forward compatible.
But signaling readiness for `mainnet` does NOT mean that there won't be any bugs
or that all planned safety and backup measures are fully in place yet.

**That means, special care must be taken to avoid loss of funds (both assets
and BTC)!**

## How to avoid loss of funds (short version, tl;dr)

In short, there is no recovery mechanism yet that allows easy asset recovery
using only the `lnd` seed. If `tapd`'s database is lost or corrupted,
access to all assets minted or received by that `tapd` **is lost**.
Additionally, custody the BTC used to carry/anchor the assets would also be
lost.

**To avoid loss of funds:**
1. **make sure the `/home/<user>/.tapd` directory is backed up regularly.**
   If `tapd` is configured to use Postgres as the database backend, backups this
   database is sufficient to preserve access to funds.
2. `lnd`'s seed phrase has been securely backed up, as all `tapd` assets private
   keys are derived from it.

## How to avoid loss of funds (extended version)

Because the Taproot Assets Protocol is an overlay or off-chain protocol, all
data relevant to asset mints, transfers or burns are not stored in the Bitcoin
blockchain itself. Meaning, if access to that data is lost, then the assets
cannot be recovered by just using a wallet seed.

So-called Universes (public asset and proof databases) will help with storing
and later retrieving that crucial off-chain data, but the mechanisms to query
all required data by just using `lnd`'s seed are not yet implemented. See
[#426](https://github.com/lightninglabs/taproot-assets/issues/426) for more
information.

### What data do I need to back up

The following items should be backed up whenever sends or receives occur in tapd
(e.g. hourly or even more frequently depending on the number of
users/transactions of a system):

* **If the default SQLite database is used:** Then all data is in the files
  in the location `<tapddir>/data/<network>/tapd.db*` (usually `tapd.db`,
  `tapd.db-wal` and `tapd.db-shm`), where `tapddir` is the following by default,
  depending on your operating system:
   * Linux/Unix: `~/.tapd`
   * MacOS: `~/Library/Application Support/Tapd`
   * Windows: `~/AppData/Roaming/Tapd`
   * Umbrel: `${APP_DATA_DIR}/data/.tapd`
   * Or, if either the `--tapddir` or `--datadir` flags or config options are
   * set, then the file should be located there.
* **If a Postgres database is used**: Creating a backup of the database
  configured as `--postgres.dbname` flag or config option is sufficient.

Optionally, instances of the proof files in `<tapddir>/data/<network>/proofs`
can be backed up as well, but those are also all contained in the SQLite or
Postgres database and are only on the filesystem for faster access.

### Where are the private keys for assets stored?

The `tapd` database does not store any private key material. It exclusively uses
`lnd`'s wallet to derive keys for assets and their BTC anchoring transactions.
The `tapd` database only stores the public key and derivation information in
its database.

The following cryptographic keys are derived from `lnd`'s wallet:
* `internal_key`: The internal keys for BTC-level anchoring transaction outputs
  that carry asset commitments.
* `script_key`: The raw key for asset ownership keys, by default used as
  BIP-0086 keys in the asset output.


### Is it safe to restore from an outdated database backup?

Yes. Since there is no penalty mechanism involved as in Lightning, there is no
additional risk when restoring an outdated database backup.
But of course, if the database backup is out of date, it might not contain the
latest assets and access to those could still be lost.

### Is it safe to open the `tapd` RPC port to the internet?

There is normally no need to open the `tapd` RPC port (10029 by default) to the
internet. If the tapd instance is running a public Universe server, then that
port is required to be exposed. By default, all RPC methods (except for some
non-sensitive Universe related calls) are protected by macaroon credentials.

There are three flags/config options that should be evaluated though:
* `--allow-public-uni-proof-courier`: If set, then access to the Universe-based
  proof courier methods is allowed _without_ the normal macaroon requirement.
  Meaning, any other `tapd` clients can use this `tapd` instance to transmit
  transfer proofs from sender to receiver without needing any sort of
  permission credential.
* `--allow-public-stats`: If set, then access to Universe statistics RPC calls
  are allowed without the macaroon requirement. This can be useful to
  directly pull statistics over the REST interface into any website.
* `--universe.public-access`: If set, then proofs can be inserted and synced by
  other nodes. Note that `--universe.public-access` controls whether remote
  proofs should be allowed in general, while `--allow-public-uni-proof-courier`
  controls whether an authentication token is required.

## Important note for Umbrel/Lightning Terminal users

**DO NOT UNDER ANY CIRCUMSTANCE** uninstall (or re-install) the "Lightning
Terminal" app without first making a manual backup of all local `tapd` data,
if you are using Taproot Assets as part of the "Lightning Terminal" app with
Umbrel -- or any comparable node-in-a-box solution.  Uninstalling Umbrel apps
deletes application data. This Taproot Assets application data encumbers
Taproot Assets **AND** bitcoin funds. Receiving and sending `tapd` assets
updates the daemon's funds-custody material. Merely having the `lnd` seed phrase
is **NOT** enough to restore assets minted or received.
**WITHOUT BACKUP BEFORE DELETION, FUNDS ARE DESTROYED**.
