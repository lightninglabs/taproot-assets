# Asset Decimal Display

Within the Taproot Assets Protocol, an asset's unit is an integer (`uint64`).
That means, the protocol cannot represent fractions of an asset.
Therefore, any asset that represents a fiat currency would need to issue assets
equivalent to at least the smallest unit in use.
For example, an asset that represents the US-Dollar would need to be minted in a
way that one asset unit would represent one USD **cent**.
Or in other words, 100 units of such an asset would represent 1 US-Dollar.
Beyond the smallest unit, additional breathing room should be added to ensure
minimal precision loss during conversion arithmetic (see next chapter).

Because wallet software user interfaces aren't expected to know what
"resolution" or precision any asset in the wild represents, a new field called
`decimal_display` was added to the JSON metadata of new assets minted with
`tapd v0.4.0-alpha` and later (this field is encoded in the metadata field as a
JSON field, therefore it is only compatible with assets that have a JSON
metadata field).

An issuer can specify `tapcli assets mint --decimal_display X` to specify the
number of decimal places the comma should be shifted to the left when displaying
a sum of asset units.

For the example above, a USD asset would choose `--decimal_display 2` to
indicate that 100 units ($10^2$) should be displayed as `$1.00` in the wallet
UI. Or another example: 1234 USD cent asset units would be displayed as `$12.34`
in the UI.

An asset's decimal display can be viewed with the `tapcli assets list` command
(for an asset that's owned):
```shell
$ tapcli assets list

{
  "assets": [
    {
      "version": "ASSET_VERSION_V0",
      "asset_genesis": {
        ...
      },
      "amount": "10000000",
      ...
      "decimal_display": {
        "decimal_display": 3
      }
    }
  ]
}
```

If the `decimal_display` field is missing or showing as
`"decimal_display": null`, it means the asset is using a value of 0 (which means
no shift in decimal places).

For an asset that isn't owned by the local node (but its issuance information
was synced from a universe server), the decimal display value can be retrieved
from the asset's metadata:

```shell
$ tapcli assets meta --asset_id xyz

{
  "data": "7b22646563696d616c5f646973706c6179223a357d",
  "type": "META_TYPE_JSON",
  "meta_hash": "2ae3dc4e0430e7e19134adb516d9a59237efa0c580479c5e983ca0c1b6777c65"
}

$ tapcli assets meta --asset_id xyz | jq -r '.data' | xxd -p -r

{"decimal_display":5}
```

## Precision requirement for assets in the Lightning Network

Due to the non-divisible (integer) nature of Taproot Asset units, the smallest
asset amount that can be transferred with a Lightning Network HTLC is one asset
unit (partial units or zero units aren't possible).

If one such asset unit represents significantly more than a couple of
milli-satoshi or even full satoshi, then in some cases, due to integer division
and rounding up, the user might end up spending noticeably more assets than
necessary when paying an invoice.

**Example 1: Paying a 1 satoshi invoice**:

While writing this article, one USD cent is roughly equivalent to 19 satoshi.

So if a user with USD cent assets in their wallet attempted to pay an invoice
denominated over 1 satoshi, they would need to send a full USD cent to satisfy
the invoice (again, only full asset units can be transported over an HTLC).

Even if one cent isn't much, the overpayment would still be roughly `19x`.

**Example 2: Paying an invoice with MPP**:

Multi-Part Payments (MPP) allow a single payment to be split up into multiple
parts/paths, resulting in multiple HTLCs per payment.

Assuming a `decimal_display` value of `2` (1 unit represents 1 USD cent), if a
user wants to pay an invoice over `1,000,000` satoshi, that would be
equivalent to `$526.315789 USD` or `52,631.5789` cents
(`1 million satoshi / 19 satoshi`, showing extra decimal places to demonstrate
loss of precision).
If the user were to pay this amount in a single HTLC, they would send `52,632`
asset units (need to round up to satisfy integer asset amount and invoice
minimum amount requirements), overpaying by `0.4211` cents.

If the user's wallet decided to split up the payment into 16 parts for example,
then each part would correspond to `3,289.4737` cents. To satisfy the integer
asset amount and invoice minimum amount requirement, each of the 16 HTLCs would
send out `3290` cents. That's a full `8.4211` cents of overpayment.

## What precision should I choose when minting an asset for the Lightning Network?

To address the issue of rounding up when splitting payments or representing
small satoshi amounts as asset units, an issuer of assets should use a high
enough value for `decimal_display` when minting.

**But what is a good value for `decimal_display`?**

We recommend to use a `decimal_display` value of `6` for currencies which
use a smaller subunit with two decimal places (such as cents for USD or EUR,
penny for GBP and so on).

For currencies without smaller units (for example JPY or VND), a
`decimal_display` value of `4` is recommended.

## What if I made an asset with the wrong amount of precision?

The `decimal_display` value is stored in the `asset_meta` field of the
`genesis_asset` that creates a particular `group_key` (or `asset_id`). As a
result, the value of the `asset_meta` actually determined the original
`asset_id` and `group_key` used, therefore these values are strongly bound.

The only way to "fix" the `decimal_display` value is to burn all the existing
assets, creating new assets with the proper decimal display value. It's possible
to do this in a _single atomic transaction_ using the gRPC/REST interface.

Such a transaction would:
1. Burn referenced asset inputs
2. Create new asset units under a new group key

# RFQ

The RFQ system is responsible for acquiring real-time price quotes for
converting between asset units and satoshi (both directions) or between
different asset types.

It's important to note that the direction of "inbound/in/buy" and
"outbound/out/sell" is always seen from the point of view of the **wallet end
user**. So what is outbound for the end user would be inbound for the RFQ peer
(edge node) and vice versa.

There are two main user stories, as seen from the point of view of the wallet
end user:

1. Sending out assets: The user wants to pay a Lightning Network invoice that
   is denominated in satoshi. The user only has assets in their wallet, they
   (or their wallet software) want to find out how many asset units they need to
   send in order to satisfy the invoice amount in satoshi.
2. Receiving assets: The user wants to get paid in a specific asset. The user
   only knows about the asset, so they (or their wallet software) want to find
   out what the asset amount corresponds to in satoshi.

**NOTE**: All arithmetic conversions in the section below always use
_fixed point_ arithmetic. A `scale` (equivalent to a decimal display, but just
for computations) of either `11`, or the `decimal_display` value (which ever is
greater is used).

## Sell Order (Paying Invoices)

The sell order covers the first user story: The user wants to pay a
satoshi-denominated invoice with assets. 

The end result is that the user uses the pre-image referenced by the payment
hash in the invoice to atomically sell some of their assets units in their
channel to the RFQ per (edge node), ensuring the payment is only complete is the
receiver receives their funds.
Note that from the PoV of the edge node, they're effectively paid a routing fee
to buy asset units (more asset unit inbound) by also sending out BTC outbound
(less BTC outbound).

Formal definition:
- Use case: sending assets as a payment, selling `buxx` for `msat`
- User query: `Q = how many out_asset units for in_asset amount?` (how many
  `buxx` do I need to sell/send to pay this payment denominated in `msat`?)
- `out_asset`: `buxx` (user sells `buxx` asset to RFQ peer, sending that value
  to the edge node)
- `in_asset`: `msat` (user "receives" `msat` from RFQ peer, which are then
  routed to the network)
- `max_amount`: `in_asset` (what is the maximum amount of `msat` the RFQ peer
  has to forward to the network? Equal to invoice amount plus user-defined max
  routing fee limit)
- `price_out_asset`: `out_asset_units_per_btc` (`buxx per BTC`)
- `price_in_asset`: `in_asset_units_per_btc` (`msat per BTC`)

### Calculating asset units to send

In this case, we have an invoice denominated in mSAT, and want to convert to
asset units `U`. Given the total amount of mSAT to send (`X`), the number of
assets units per BTC (`Y`), and the total amount of mSAT in 1 BTC (`M`), we can
convert from mSAT to asset units as follows:
* U = (X / M) * Y
* where
   * `U` is the result, the number of asset units to send
   * `X` is the invoice amount in mSAT
   * `M` is the number of mSAT in a BTC (100,000,000,000), specified by
  `price_in_asset`
   * `Y` is the number of asset units per BTC, specified by `price_out_asset`

## Buy Order (Receiving via an Invoice)

The buy order covers the second user story: The user wants to get paid, they
create an invoice specifying the number of asset units they want to receive,
which is then mapped to a normal, satoshi-denominated invoice.
The end result is that the user uses the satoshis sent by the sender through the
normal LN network to _buy_ enough asset units to satisfy their invoice, using
the edge node and the atomic exchange of the pre-image.

Formal definition:
- Use case: receiving assets through an invoice, selling `msat` for `buxx`
- User query: `Q = how many out_asset units for in_asset amount?` (how many
  `msat` should I denominate my invoice with to receive a given amount of
  `buxx`?)
- `out_asset`: `msat` (user sells sats to RFQ peer, which are routed to them by
  the network)
- `in_asset`: `buxx` (user buys `buxx` from RFQ peer)
- `max_amount`: `in_asset` (what is the maximum number of `buxx` the RFQ peer
  has to sell? Equal to the amount in the user query)
- `price_out_asset`: `out_asset_units_per_btc` (`msat per BTC`)
- `price_in_asset`: `in_asset_units_per_btc` (`buxx per BTC`)

### Calculating satoshi to receive

For the receiving case, we perform the opposite computation that we did for
sending: we want to receive `U` asset units, given a rate of (`Y`) units per
BTC, we can compute the amount of satoshis that must be paid (`X`) into the edge
node as:

* `X = (U / Y) * M`
* where
    * `X` is the result, the number of mSAT to receive
    * `U` is the desired number of asset units to receive
    * `Y` is the number of asset units per BTC, specified by `price_out_asset`
    * `M` is the number of mSAT in a BTC (100,000,000,000), specified by
      `price_in_asset`

## Examples

See `TestFindDecimalDisplayBoundaries` and `TestUsdToJpy`  in 
`rfqmath/convert_test.go` for how these examples are constructed.

**Case 1**: Buying/selling USD against BTC.

```text
In Asset:       USD with decimal display = 6 (1_000_000 asset units = 1 USD)
Out Asset:      satoshi / milli-satoshi

Example 1:
----------

What is price rate when 1 BTC = 20,000.00 USD?

decimalDisplay: 6			1000000 units = 1 USD, 1 BTC = 20000000000 units
Max issuable units:			can represent 922337203 BTC
Min payable invoice amount:	5 mSAT
Max MPP rounding error:		80 mSAT (@16 shards)
Satoshi per USD:			5000
Satoshi per Asset Unit: 	0.00500
Asset Units per Satoshi: 	200
Price In Asset: 			20000000000
Price Out Asset: 			100000000000


Example 2:
----------

What is price rate when 1 BTC = 1,000,000.00 USD?

decimalDisplay: 6			1000000 units = 1 USD, 1 BTC = 1000000000000 units
Max issuable units:			can represent 18446744 BTC
Min payable invoice amount:	1 mSAT
Max MPP rounding error:		1 mSAT (@16 shards)
Satoshi per USD:			100
Satoshi per Asset Unit: 	0.00010
Asset Units per Satoshi: 	10000
Price In Asset: 			1000000000000
Price Out Asset: 			100000000000


Example 3:
----------

What is price rate when 1 BTC = 10,000,000.00 USD?

decimalDisplay: 6			1000000 units = 1 USD, 1 BTC = 10000000000000 units
Max issuable units:			can represent 1844674 BTC
Min payable invoice amount:	1 mSAT
Max MPP rounding error:		0 mSAT (@16 shards)
Satoshi per USD:			10
Satoshi per Asset Unit: 	0.00001
Asset Units per Satoshi: 	100000
Price In Asset: 			10000000000000
Price Out Asset: 			100000000000
```

**Case 2**: Buying/selling USD against JPY.

```text
In Asset:       USD with decimal display = 6 (1_000_000 asset units = 1 USD)
Out Asset:      JPY with decimal display = 4 (10_000 asset units = 1 JPY)

Assumption:     1 USD = 142 JPY

Example 1:
----------

What is price rate when 1 BTC = 20,000.00 USD (1 BTC = 2,840,000 JPY)?

Satoshi per USD:				5000
Satoshi per USD Asset Unit: 	0.00500
USD Asset Units per Satoshi: 	200
Satoshi per JPY:				35
Satoshi per JPY Asset Unit: 	0.35211
JPY Asset Units per Satoshi: 	284
Price In Asset: 				20000000000
Price Out Asset: 				28400000000
  1 USD in JPY: 				142


Example 2:
----------

What is price rate when 1 BTC = 1,000,000.00 USD (1 BTC = 142,000,000 JPY)?

Satoshi per USD:				100
Satoshi per USD Asset Unit: 	0.00010
USD Asset Units per Satoshi: 	10000
Satoshi per JPY:				0
Satoshi per JPY Asset Unit: 	0.00704
JPY Asset Units per Satoshi: 	14199
Price In Asset: 				1000000000000
Price Out Asset: 				1420000000000
500 USD in JPY: 				71000
```

# Price Oracle

The price oracle is an important component in the RFQ system, as it provides the
values for the exchange rates mentioned above.

Both parties of an asset channel (the wallet end user and the edge node) might
use a price oracle, but its role is different for those parties:
* The **Price Oracle for the edge node** is responsible for putting a price tag
  on the service that is offered by the edge node, which is an atomic swap
  between two types of assets (often one of them being BTC). In other words,
  the oracle is responsible for calculating a concrete exchange rate for a
  specific atomic swap. The inputs to that calculation are variables such as
  the official exchange rate between the asset and BTC ("official" market rate,
  potentially obtained from a third party exchange API), the size/volume of the
  swap and the requested validity duration (expiry). The output of the
  calculation is again an exchange rate, but one that is adjusted to include a
  spread vs. the input exchange rate. The spread is what allows the edge node
  to be compensated for offering the swap service, including potential exchange
  rate fluctuation risks. It is expected that the spread is adjusted by the
  price oracle implementation based on the size and validity duration of the
  swap, because those values directly correlate with the exchange rate risk.
* The **Price Oracle for the wallet end user** on the other hand is simply
  tasked with validating exchange rates offered to them by the edge node, to
  make sure they aren't proposing absurd rates (by accident or on purpose).

**NOTE**: By default, the _minimum_ quote expiry at tapd node will accept is _10
seconds_.

Due to the fundamentally different roles of the price oracle for both parties,
it is expected that the actual implementation for the price oracle is also
different among the parties.

## Edge node

Given that an edge node might want to implement their specific business logic
and rules, no default implementation for a price oracle for edge nodes is
provided. Edge node operators need to implement the RPC interface defined in
`taprpc/priceoraclerpc` and point their `tapd` to use their custom
implementation with the
`experimental.rfq.priceoracleaddress=rfqrpc://<hostname>:<port>` configuration
value.
An example implementation of a price oracle server implementing that RPC
interface with Golang can be found in
[`docs/examples/basic-price-oracle`](examples/basic-price-oracle).

## Wallet end user

The wallet end user's price oracle implementation can be quite simple. All it
needs to do is to query an exchange provider's API for the current exchange
rate of an asset. Then the maximum deviation from that "official" market rate
that is accepted from edge nodes can be configured using the
`experimental.rfq.acceptpricedeviationppm=` configuration value (which is in
parts per million and the default value is `50000` which is equal to `5%`).

Because the API endpoints of public exchange platforms aren't standardized,
there also isn't a default implementation of an end user price oracle available.
It is expected that third party developers (or at some point even the exchange
platforms themselves) will offer a gRPC (`rfqrpc`) compatible price oracle
endpoint that can directly be plugged into the
`experimental.rfq.priceoracleaddress=rfqrpc://<hostname>:<port>` configuration
value on the wallet end user side.
