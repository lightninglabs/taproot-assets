# Portfolio Pilot Guide

The portfolio pilot decides tapd's RFQ trades: which quote requests from peers
to accept and at what rate, and whether to accept the quotes peers return for
our own requests. By default tapd uses a built-in pilot that prices with the
configured price oracle. Setting `experimental.rfq.portfoliopilotaddress`
replaces it with an external pilot served over gRPC.

For the RFQ protocol itself, see [rfq.md](rfq.md) and
[rfq_architecture.md](rfq_architecture.md).

- [Safety](#safety)
- [Configuration](#configuration)
- [The Example Pilot](#the-example-pilot)
- [Writing a Pilot](#writing-a-pilot)
- [Testing](#testing)

## Safety

tapd checks RFQ messages, but not prices. The pilot is trusted with both sides
of every trade:

- **Quotes we give.** tapd sends the pilot's `ResolveRequest` answer to the
  peer as is, and honors HTLCs at the quoted rate until the quote expires. An
  accept cannot be withdrawn.
- **Quotes we take.** tapd uses a peer's quote if `VerifyAcceptQuote` returns
  `VALID_ACCEPT_QUOTE`. With an external pilot, tapd runs no checks of its
  own, so user limits such as `asset_rate_limit` are enforced on our side only
  if the pilot enforces them. `skipquoteacceptverify` skips the call and
  accepts every quote.

A pilot that accepts any rate lets the peer set the price.

### Pilot Checklist

The [example pilot](#the-example-pilot) implements each item.

1. Never quote a peer's `asset_rate_hint`. Price from a source the peer does
   not control.
2. Reject peer quotes that deviate from your reference price by more than a
   set bound. The built-in pilot allows 50,000 ppm (5%) by default.
3. Reject peer quotes with too little time left; the built-in pilot requires
   10 seconds. Keep your own quote lifetimes short, since an accept is a free
   option for the peer until it expires, but no shorter than the invoices
   they back: `AddInvoice` drops quotes that expire before the invoice, whose
   default expiry is 300 seconds.
4. Reject everything while the reference price is missing or stale. Never fall
   back to a fixed rate.
5. Quote only assets you can price, in asset units per BTC using the asset's
   decimal display. At $65,000 per BTC, a USD asset with decimal display 6 is
   65,000,000,000 units per BTC; with decimal display 2, it is 6,500,000.
6. Check the requester's [constraints](#constraints) before quoting, and our
   own request's constraints before accepting a peer's quote.
7. Bound your own downstream calls. tapd's calls to the pilot carry no
   deadline.
8. Cap the total size of your unexpired quotes, and halt on anomalies such
   as a sudden price move. A halt stops new quotes only: tapd honors quotes
   already given until they expire.
9. Watch what settles, not only what you quote. Value settled swaps against
   your reference price, and watch your channel balances. Widen spreads or
   stop the side running low before halting.

### Operator Checklist

- Verify the pilot's certificate. For a self-signed pilot, put its
  certificate in `experimental.rfq.tls.certpath`, which is shared with the
  price oracle connection and may hold several PEM certificates. Never set
  `experimental.rfq.tls.insecure` or `experimental.rfq.tls.disable` outside
  tests: anyone on the network path could then answer for the pilot.
- Set `experimental.rfq.portfoliopilotmacaroonpath`. tapd refuses to start
  with a macaroon and unverified TLS. A pilot that holds state must require
  the macaroon, or any client that reaches it can call `ResolveRequest`.
- Keep the pilot on loopback or a private network.
- Never set `experimental.rfq.skipquoteacceptverify` or use the mock price
  oracle on mainnet.

### User Limits

Users can bound their own trades:

- `AddInvoice`: `asset_rate_limit` (a floor), `asset_min_amt`,
  `execution_policy`.
- `SendPayment`: `asset_rate_limit` (a ceiling).
- `AddAssetBuyOrder`, `AddAssetSellOrder`: `asset_rate_limit`, minimum
  amounts, `execution_policy`.

## Configuration

Options under `experimental.rfq.`:

- `portfoliopilotaddress`: `portfoliopilotrpc://host:port`. Unset uses the
  built-in pilot.
- `portfoliopilotmacaroonpath`: macaroon sent to the pilot.
- `priceoracleaddress`: `rfqrpc://host:port`, used by the built-in pilot.
- `tls.certpath`, `tls.nosystemcas`: trusted certificates for the pilot and
  oracle connections. `tls.insecure`, `tls.disable`: tests only.
- `acceptpricedeviationppm`: the built-in pilot's tolerance, default 50,000.
- `sendpricehint`: attach the pilot's `QueryAssetRates` rate to outgoing
  requests.
- `priceoraclesendpeerid`: send the counterparty's pubkey to the oracle.
- `skipquoteacceptverify`: tests only.

With an external pilot, tapd still queries the price oracle directly for
`DecodeAssetPayReq` and for `AddInvoice` amounts given in satoshis. Configure
an oracle that agrees with the pilot, or those calls fail.

## The Example Pilot

[docs/examples/basic-portfolio-pilot](examples/basic-portfolio-pilot) is a
runnable pilot for one USD-pegged asset, priced from BTC/USD. It is a
demonstration, not production code. Each file covers one concern:

- [pilot.go](examples/basic-portfolio-pilot/pilot.go) quotes the reference
  rate moved by `-spreadppm` (default 5,000), ignores peer hints, checks
  constraints with the `rfq` helpers, and rejects peer quotes outside
  `-maxdeviationppm` (default 50,000) or with less than 10 seconds left.
- [price.go](examples/basic-portfolio-pilot/price.go) fetches BTC/USD from
  CoinGecko, or takes `-btcusd`, converts it to asset units with
  `-decimaldisplay`, and reports no price once it is two minutes old.
- [breaker.go](examples/basic-portfolio-pilot/breaker.go) wraps the pilot
  and sets the trading level.
- [monitor.go](examples/basic-portfolio-pilot/monitor.go) reads settled
  swaps from tapd and balances from lnd, and degrades or halts trading.
- [server.go](examples/basic-portfolio-pilot/server.go) serves TLS and
  requires a macaroon.
- [main.go](examples/basic-portfolio-pilot/main.go) parses flags and wires
  the parts together.

### Trading Levels

Trading runs at one of three levels:

- **Normal.**
- **Degraded.** The spread doubles, and below an inventory floor the
  requests that would deplete that side further are rejected. Degraded
  trading returns to normal once its conditions clear.
- **Halted.** Everything is rejected while `basic-portfolio-pilot.halt`
  exists in `-datadir`. Create the file to halt by hand, and remove it to
  resume.

The pilot halts, writing the reason to the halt file, when:

- a new quote would take the unexpired quotes above `-maxexposureusd`
  (default 1,000),
- the price moves more than `-maxpricejumpppm` (default 50,000) between
  fetches,
- `-maxbadquotes` (default 5) peer quotes fall outside tolerance within ten
  minutes, or
- the trade edge over the last hour falls below minus `-maxtradelossusd`
  (default 100). The trade edge is the value of each settled swap at the
  reference price: BTC received less asset given for a sale, asset
  received less BTC paid for a purchase.

It degrades when the trade edge falls below half that, when the local
asset balance falls below `-minassetusd` (blocking buy requests), or when
the local BTC balance falls below `-minbtcsat` (blocking sell requests).

The exposure and the trade edge window are held in memory, so a restart
resets them.

### Running

```shell
go build ./docs/examples/basic-portfolio-pilot
./basic-portfolio-pilot -assetid <hex asset ID> -decimaldisplay 6
```

On first start it writes `basic-portfolio-pilot.cert`, `.key` and `.macaroon`
to `-datadir` (default `.`). Point tapd at them:

```text
experimental.rfq.portfoliopilotaddress=portfoliopilotrpc://127.0.0.1:8096
experimental.rfq.tls.certpath=<datadir>/basic-portfolio-pilot.cert
experimental.rfq.portfoliopilotmacaroonpath=<datadir>/basic-portfolio-pilot.macaroon
```

In Docker, the data directory is `/data`, and the certificate needs the host
name tapd dials:

```shell
docker build -f docs/examples/basic-portfolio-pilot/Dockerfile -t pilot .
docker run -v "$PWD/pilot:/data" -p 127.0.0.1:8096:8096 pilot \
    -listen 0.0.0.0:8096 -tlsextradomain <host> \
    -assetid <hex asset ID> -decimaldisplay 6
```

A certificate is generated only when none exists. Delete it after changing
`-tlsextradomain`.

The trade edge and inventory checks read tapd's forwarding history and
lnd's channel balances, with read-only macaroons:

```shell
tapcli bakemacaroon --save_to=pilot-tapd.macaroon rfq:read
lncli bakemacaroon --save_to=pilot-lnd.macaroon offchain:read
./basic-portfolio-pilot -assetid <hex asset ID> -decimaldisplay 6 \
    -tapdrpcserver 127.0.0.1:10029 -tapdtlscertpath <tapd tls.cert> \
    -tapdmacaroonpath pilot-tapd.macaroon \
    -lndrpcserver 127.0.0.1:10009 -lndtlscertpath <lnd tls.cert> \
    -lndmacaroonpath pilot-lnd.macaroon
```

Without them, those checks are disabled.

## Writing a Pilot

The service is defined in
[portfolio_pilot.proto](../taprpc/portfoliopilotrpc/portfolio_pilot.proto).
The built-in pilot in [rfq/portfolio_pilot.go](../rfq/portfolio_pilot.go) and
the example pilot are reference implementations.

### Calls

- `ResolveRequest`: a peer asks us for a quote. Return an accept, with a rate,
  an expiry and an optional fill cap in `accepted_max_amount`, or a reject
  with a [reject code](#codes). Return a gRPC error only when the pilot fails
  to evaluate the request; tapd then sends the peer a generic reject.
- `VerifyAcceptQuote`: a peer quoted on one of our requests, which is
  included. Return `VALID_ACCEPT_QUOTE` to use the quote. Any other status, or
  an error, discards it.
- `QueryAssetRates`: our own rate, attached as a hint to outgoing requests
  when `sendpricehint` is set. The intent is `INTENT_PAY_INVOICE_HINT` for
  sell orders and `INTENT_RECV_PAYMENT_HINT` for buy orders. An error sends
  the request without a hint.

Calls arrive concurrently and carry no deadline. tapd does not retry. Persist
any state, such as reserved inventory, before returning an accept.

### Directions and Units

- A `BuyRequest` is a peer buying the asset from us. Its amounts are in asset
  units, and its `asset_rate_limit` is a floor.
- A `SellRequest` is a peer selling the asset to us, typically to pay an
  invoice. Its amounts are in msat, and its `asset_rate_limit` is a ceiling.
- Rates are asset units per BTC, as a `FixedPoint`: `coefficient / 10^scale`.
  The coefficient is a decimal string and may exceed 64 bits.
- `peer_id` is always the counterparty's pubkey.
- `rfq_id` is the quote's ID. rfqrpc's `ForwardingHistory` reports it for
  each HTLC settled against the quote.
- `price_oracle_metadata` is set by the requester, up to 32,768 bytes.
  Authenticate anything in it that affects the price.

### Constraints

A quote must satisfy the request's constraints, checked in this order:

1. **Rate bound:** the rate is on the right side of `asset_rate_limit`.
2. **Minimum fill:** the minimum amount converts to a non-zero amount on the
   other side at the rate.
3. **Fill-or-kill:** under `EXECUTION_POLICY_FOK`, so does the maximum.
4. **Fill cap:** a non-zero `accepted_max_amount` is at most the maximum, at
   least the minimum, and equal to the maximum under fill-or-kill.

Go pilots can run the same checks as tapd, as the example does:
`rpcutils.UnmarshalPortfolioBuyConstraints` and
`rpcutils.UnmarshalPortfolioSellConstraints` read the constraints from a
request, `rfq.CheckConstraints` checks a rate and fill against them, and
`rfq.RejectForStatus`, `rfq.MarshalPortfolioRejectErr` and
`rfq.MarshalPortfolioQuoteRespStatus` convert the result.

### Codes

A failed check gives a `QuoteRespStatus` in `VerifyAcceptQuote` and a
`RejectCode` in `ResolveRequest`:

- Rate bound: `RATE_BOUND_MISS`, `REJECT_CODE_PRICE_BOUND_MISS`.
- Minimum fill: `MIN_FILL_NOT_MET`, `REJECT_CODE_MIN_FILL_NOT_MET`.
- Fill-or-kill: `FOK_NOT_VIABLE`, `REJECT_CODE_FOK_NOT_VIABLE`.
- Fill cap above maximum: `FILL_EXCEEDS_MAX`,
  `REJECT_CODE_FILL_EXCEEDS_MAX`.
- No price: `PRICE_ORACLE_QUERY_ERR`,
  `REJECT_CODE_PRICE_ORACLE_UNAVAILABLE`.

`VerifyAcceptQuote` also returns `INVALID_ASSET_RATES` for a rate outside
tolerance, `INVALID_EXPIRY` for a quote that expires too soon, and
`PORTFOLIO_PILOT_ERR` for an internal failure. Other rejections use
`REJECT_CODE_UNSPECIFIED`.

### Circuit Breakers

Pricing checks guard each quote; a circuit breaker guards trading as a
whole. The example's breaker follows a pattern that carries over to other
pilots:

- Wrap the pricing pilot in another implementation of the same service, so
  the breaker sees every call and every answer.
- Respond in levels. Degrade on soft signals, by widening spreads or
  stopping the side that is running low, and return to normal when they
  clear. Halt on hard signals, and keep the halt, in state that survives a
  restart, until an operator clears it.
- Watch outcomes as well as quotes. rfqrpc's `ForwardingHistory` (`rfq:read`)
  lists settled swaps with their `rfq_id`, amounts and rate. lnd's
  `ListChannels` custom channel data and `ChannelBalance` (`offchain:read`)
  give the asset and BTC balances.
- Count every unexpired quote as exposure. A halt stops new quotes only.

## Testing

- [rfq/portfolio_pilot_test.go](../rfq/portfolio_pilot_test.go) specifies the
  constraint checks.
- The `testRfqPortfolioPilotRpc` itest runs tapd against the harness in
  [itest/portfolio_pilot_harness.go](../itest/portfolio_pilot_harness.go).
  The harness accepts every quote; it tests the plumbing, not a pricing
  policy.
