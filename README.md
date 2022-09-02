# Taro

The Taro Daemon `tarod` implements the [Taro protocol](https://github.com/Roasbeef/bips/blob/bip-taro/bip-taro.mediawiki) for issuing assets on the Bitcoin blockchain. Taro leverages Taproot transactions to commit to newly created assets and their transfers in an efficient and scalable manner. Multiple assets can be created and transferred in a single bitcoin UTXO, while witness data is transacted and kept off-chain.

## Features:

- Mint assets
- Export and import Taro proofs
- Create and manage profiles

## How it works:

When minting a new asset, Taro will generate the relevant witness data, assign the asset to a key held by you and publish the corresponding bitcoin UTXO -- the minting transaction. 

The outpoint this minting transaction consumes becomes the `genesis_point` of the newly minted asset, acting as its unique identifier. Assets can be spent to a new recipient, who provides the sender with the necessary information encoded in their Taro address.

To transact assets, the witnesses in the prior Taro transaction are recommitted into one or multiple taproot outputs while the necessary witness data is passed to the recipient. Similar to bitcoin transactions, the remaining balance is spent back to the sender as a change output.

[Learn more about the Taro protocol.](https://docs.lightning.engineering/the-lightning-network/taro)

## Architecture:

Taro is implemented as the Taro Daemon `tarod` and the Taro Command Line Interface `tarocli`. Additionally tarod exposes a GRPC interface to allow for a direct integration into applications.

Taro leverages several LND features including the Taproot wallet and signing capabilities. These facilities are accessed through LND’s GRPC.

### The Taro stack:

`Bitcoin blockchain backend <-> LND <-> Taro`

Custody of Taro assets is segmented across LND and Taro to maximize security. LND holds the private key, which has had a taproot tweak applied to it, controlling the bitcoin UTXO holding the Taro asset. The taproot tweak on the other hand is held by Taro. This increases the requirements for asset recovery as both the internal key as well as the taproot tweak are necessary to spend the output. This prevents LND from accidentally burning Taro assets.

## Prerequisites:

Taro requires [LND](https://github.com/lightningnetwork/lnd/) (compiled on the latest master branch) to be synced and running. RPC connections need to be accepted and a valid macaroon needs to be present.
 
## Installation:

### From source:

Compile Taro from source by cloning this repository. [Go version 1.18](https://go.dev/dl/) or higher is required.

```shell
🍠 git clone https://github.com/lightninglabs/taro.git
🍠 cd taro
🍠 make install
```

## Initialization:

Run Taro with the command `tarod`. Specify how Taro can reach LND and what network to run Taro with by passing it additional flags.


```shell
🍠 tarod --network=testnet --debuglevel=debug --lnd.host=localhost:10009 --lnd.macaroonpath=~/.lnd/data/chain/bitcoin/testnet/admin.macaroon --lnd.tlspath=~/.lnd/tls.cert
```

## Usage:

See a full list of options by executing:

```shell
🍠 tarod --help
```

Use `tarocli` to interact with `tarod`

```shell
🍠 tarocli assets mint --type normal --name fantasycoin --supply 100 --meta "fantastic money" --skip_batch
```

```shell
🍠 tarocli assets list
```

## Development

### API

Taro exposes a GRPC and a REST API. Connections are encrypted with TLS and authenticated using macaroons.

## Submit feature requests

The [GitHub issue tracker](https://github.com/lightninglabs/taro/issues) can be used to request specific improvements or report bugs.

## Join us on Slack

Join us in the [Lightning Labs Slack](https://lightning.engineering/slack.html) and join the `#taro` channel to ask questions and interact with the community.
