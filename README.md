# Taproot Assets

The Taproot Assets Daemon `tapd` implements the [Taproot Assets Protocol](https://github.com/Roasbeef/bips/blob/bip-tap/bip-tap.mediawiki) for issuing assets on the Bitcoin blockchain. Taproot Assets leverage Taproot transactions to commit to newly created assets and their transfers in an efficient and scalable manner. Multiple assets can be created and transferred in a single bitcoin UTXO, while witness data is transacted and stored off-chain.

## Features:

- Mint and burn assets
- Synchronize to universes
- Send and receive assets
- Export and import Taproot Asset proofs
- Create and manage CLI profiles

## How it works:

When minting a new asset, Taproot Assets will generate the relevant witness data, assign the asset to a key held by you and publish the corresponding bitcoin UTXO -- the minting transaction. 

The outpoint this minting transaction consumes becomes the `genesis_point` of the newly minted asset, acting as its unique identifier. Assets can be spent to a new recipient, who provides the sender with the necessary information encoded in their Taproot Asset address.

To transact assets, the witnesses in the prior transaction are recommitted into one or multiple taproot outputs while the necessary witness data is passed to the recipient. Similar to bitcoin transactions, the remaining balance is spent back to the sender as a change output.

[Learn more about the Taproot Assets Protocol.](https://docs.lightning.engineering/the-lightning-network/taproot-assets)

## Architecture:

Taproot Assets are implemented as the Taproot Assets Daemon `tapd` and the Taproot Assets Command Line Interface `tapcli`. Additionally, `tapd` exposes a GRPC interface to allow for a direct integration into applications.

Taproot Assets leverage several LND features including the Taproot wallet and signing capabilities. These facilities are accessed through LND’s GRPC.

### The Taproot Assets stack:

`Bitcoin blockchain backend <-> LND <-> Taproot Assets`

Custody of Taproot Assets is segmented across LND and Tapd to maximize security. LND holds the private key, which has had a taproot tweak applied to it, controlling the bitcoin UTXO holding the Taproot Asset. The taproot tweak on the other hand is held by Tapd. This increases the requirements for asset recovery as both the internal key as well as the taproot tweak are necessary to spend the output. This prevents LND from accidentally burning Taproot assets.

## Prerequisites:

Taproot Assets require [LND](https://github.com/lightningnetwork/lnd/) version `v0.16.2-beta` or later to be synced and running on the same Bitcoin network as Taproot Assets (e.g. regtest, simnet, testnet3). RPC connections need to be accepted and a [valid macaroon](https://docs.lightning.engineering/lightning-network-tools/lnd/macaroons) needs to be present.

```shell
git clone https://github.com/lightningnetwork/lnd.git
cd lnd 
make install tags="signrpc walletrpc chainrpc invoicesrpc"
```

## Installation:

### From source:

Compile Taproot Assets from source by cloning this repository. [Go version 1.19](https://go.dev/dl/) or higher is required.

```shell
git clone --recurse-submodules https://github.com/lightninglabs/taproot-assets.git
cd taproot-assets
make install
```

## Initialization:

Run Taproot Assets with the command `tapd`. Specify how Taproot Assets can reach LND and what network to run Tapd with by passing it additional flags. The Bitcoin backend and LND need to be running and synced before the Taproot Assets daemon can be started.


```shell
tapd --network=testnet --debuglevel=debug --lnd.host=localhost:10009 --lnd.macaroonpath=~/.lnd/data/chain/bitcoin/testnet/admin.macaroon --lnd.tlspath=~/.lnd/tls.cert
```

## Usage:

See a full list of options by executing:

```shell
tapd --help
```

Use `tapcli` to interact with `tapd`

```shell
tapcli assets mint --type normal --name fantasycoin --supply 100 --meta_bytes "fantastic money"
tapcli assets mint finalize
```

```shell
tapcli assets list
```

Synchronize yourself with a universe, for example the one running as part of the issuer's `tapd`.

```shell
tapcli universe sync --universe_host testnet.universe.lightning.finance
```

Add multiple universes to your local federation to always stay up to date. You can also use the universe to query existing assets and their metadata. You may also configure your tapd instance to listen to incoming requests with `--rpclisten 0.0.0.0:10029` to run your own universe.

```shell
tapcli universe federation add --universe_host testnet.universe.lightning.finance
tapcli universe roots
```

Once you have obtained the necessary proofs and asset IDs, you can generate a Taproot Asset address for a specific asset and amount.

```shell
tapcli addrs new --asset_id bab08407[...]129bf6d0 --amt 21
```

The sender can now fulfill the request by initiating the transfer.

```shell
tapcli assets send --addr taptb1q[...]tywpre3a
```
## Development

### API

Taproot Assets exposes a GRPC (port 10029) and a REST (port 8089) API. Connections are encrypted with TLS and authenticated using macaroons. [The API is documented here](https://lightning.engineering/api-docs/api/taproot-assets/). Further guides [can be found here](https://docs.lightning.engineering/lightning-network-tools/taproot-assets).

### Mainnet

Starting with the release of version `v0.3.0` the daemon does support the
Bitcoin `mainnet`.

**IMPORTANT NOTE**: To avoid loss of funds, it's imperative that you read the
[Operational Safety Guidelines](docs/safety.md) before using `tapd` on
`mainnet`!

The daemon is still in `alpha` state, which means there can still be bugs and
not all desired data safety and backup mechanisms have been implemented yet.
Releasing on `mainnet` mainly signals that there will be no breaking changes in
the future and that assets minted with `v0.3.0` will be compatible with later
versions.

#### Important note for Umbrel/Lightning Terminal users

**DO NOT UNDER ANY CIRCUMSTANCE** uninstall (or re-install) the "Lightning
Terminal" app without first making a manual backup of all local `tapd` data,
if you are using Taproot Assets as part of the "Lightning Terminal" app with
Umbrel -- or any comparable node-in-a-box solution.  Uninstalling Umbrel apps
deletes application data. This Taproot Assets application data encumbers
Taproot Assets **AND** bitcoin funds. Receiving and sending `tapd` assets
updates the daemon's funds-custody material. Merely having the `lnd` seed phrase
is **NOT** enough to restore assets minted or received.
**WITHOUT BACKUP BEFORE DELETION, FUNDS ARE DESTROYED**.

## Submit feature requests

The [GitHub issue tracker](https://github.com/lightninglabs/taproot-assets/issues) can be used to request specific improvements or report bugs.

## Join us on Slack

Join us in the [Lightning Labs Slack](https://lightning.engineering/slack.html) and join the `#taproot-assets` channel to ask questions and interact with the community.

