# RFQ (Request For Quote) Guide

This guide explains the RFQ subsystem in taproot-assets: what it does, how its
pieces fit together, and how a quote flows from negotiation to Lightning payment
execution.

---

## Why RFQ?

The Lightning Network carries payments denominated in satoshis. Taproot Assets
lets nodes hold custom assets (stablecoins, tokens, etc.) in Lightning channels,
but the broader Lightning network still speaks millisatoshis. When a wallet node
wants to pay a Lightning invoice using a Taproot Asset, or receive a Lightning
payment and settle locally in a Taproot Asset, both sides need to agree on an
exchange rate **before** the HTLC is committed.

RFQ is that price-discovery and rate-binding protocol. It gives two nodes a way
to negotiate a rate, cryptographically commit to it, and then enforce that
commitment at the HTLC layer.

**Core capabilities:**

- Asset → BTC (sell order): pay a Lightning invoice using Taproot Assets
- BTC → Asset (buy order): receive a Lightning payment and credit assets
- Rate binding: a Schnorr signature on the accepted quote prevents manipulation
  between negotiation and execution
- Policy enforcement: HTLC interceptors reject payments that violate the agreed
  terms

---

## Package Map

| Package | Role |
|---------|------|
| `rfqmsg/` | Wire protocol — message types, TLV encoding, HTLC records |
| `rfqmath/` | Fixed-point arithmetic for converting between mSat and asset units |
| `rfq/` | Business logic — manager, negotiator, order handler, oracle client |

---

## Wire Protocol (`rfqmsg/`)

All RFQ messages are encoded as TLV records and delivered over lnd's custom
message channel. The message type namespace starts at `MsgTypeOffset` (which is
`CustomTypeStart + 20116`, where `20116` encodes "tap").

### Message Types

There are three message types, each available in buy and sell variants:

**Request** (`MsgTypeRequest`): Initiates negotiation. The requester tells the
responder what asset and amounts are involved, and optionally proposes a rate
hint.

**Accept** (`MsgTypeAccept`): The responder agrees to the proposed terms at a
specific rate. The accept is Schnorr-signed over the message fields so neither
party can modify the agreed rate later.

**Reject** (`MsgTypeReject`): The responder declines, with a machine-readable
error code and human-readable message.

### The ID Type

Every RFQ session has a 32-byte random `ID`. The last 8 bytes of the ID are
interpreted as a short channel ID (SCID). When a quote is accepted, that SCID
is registered as an alias in lnd's alias manager so HTLCs routed to it can be
intercepted and matched to the quote.

```
ID[0:24]  — random session bytes
ID[24:32] — SCID bytes (must fall in lnd's allowed alias range)
```

### HTLC Custom Records

When an HTLC carries Taproot Asset value, it includes custom records:

```
HtlcAmountRecordType  (65536) — asset ID + unit amount tuples
HtlcRfqIDType         (65538) — the quote ID this HTLC redeems
AvailableRfqIDsType   (65540) — candidate quote IDs (for traffic shaping)
```

The `Htlc` struct in `rfqmsg/records.go` wraps these fields and is embedded in
each forwarded HTLC.

---

## Fixed-Point Arithmetic (`rfqmath/`)

Asset amounts involve potentially very large or very small numbers. Floating
point would introduce rounding errors. Instead, `rfqmath` uses a generic
`FixedPoint[T]` type:

```
Value = Coefficient / 10^Scale
```

The `Scale` field says how many decimal places the `Coefficient` has. For
example, a rate of 1.5 units per BTC is stored as `Coefficient=15, Scale=1`.

### mSat ↔ Asset Unit Conversions

**mSat → units** (`MilliSatoshiToUnits`):

```
units = (mSat / mSatPerBTC) * unitsPerBTC
      = (mSat / 100_000_000_000) * rate
```

**units → mSat** (`UnitsToMilliSatoshi`):

```
mSat = (units / unitsPerBTC) * mSatPerBTC
     = (units / rate) * 100_000_000_000
```

Both functions scale all operands to a common arithmetic scale before dividing
or multiplying, then scale back to avoid precision loss.

---

## Core Subsystems (`rfq/`)

The `rfq` package has three cooperating components, coordinated by a `Manager`:

```
StreamHandler  ←→  Manager  ←→  Negotiator
                      ↕
                 OrderHandler
```

### StreamHandler (`rfq/stream.go`)

Owns the peer connection. Subscribes to lnd's raw custom message stream,
deserializes incoming bytes into typed message objects, and puts them on the
`incomingMessages` channel. Conversely, picks up `outgoingMessages` and
serializes them back to wire format for `lnd.SendCustomMessage`.

The handler also maintains an `outgoingRequests` map from `ID` → `OutgoingMsg`
so that when an Accept or Reject arrives, it can be matched to the original
Request without the Manager needing to track session state.

### Negotiator (`rfq/negotiator.go`)

Implements the negotiation policy. It holds maps of open buy and sell offers
keyed by asset specifier. When the manager routes an incoming request to it, it:

1. Validates the request (version, expiry, asset specifier)
2. Calls `PortfolioPilot.ResolveRequest()` to get a rate or rejection reason
3. If accepted, creates a signed `BuyAccept`/`SellAccept` and sends it
4. If rejected, creates a `Reject` with the appropriate error code

When an Accept arrives from a peer (in response to an outgoing Request), the
negotiator validates the signature and calls `PortfolioPilot.VerifyAcceptQuote()`
to confirm the rate is within tolerance of the oracle's current price.

### OrderHandler (`rfq/order.go`)

The execution layer. After a quote is accepted, the order handler stores a
`Policy` object keyed on the quote's SCID. When lnd fires the HTLC interceptor
for a payment to that SCID, the order handler:

1. Parses custom records from the HTLC to extract `rfqmsg.Htlc`
2. Calls `Policy.CheckHtlcCompliance()`:
   - Verifies the SCID matches the accepted quote
   - Converts the HTLC amount (mSat) to asset units using the agreed rate
   - Checks the cumulative total stays within the quoted maximum
   - Verifies the quote has not expired
3. If compliant, resumes the HTLC; otherwise fails it with a policy error

Policy types:

| Type | Use case |
|------|----------|
| `AssetSalePolicy` | Selling assets to pay an invoice |
| `AssetPurchasePolicy` | Buying assets when receiving a payment |
| `AssetForwardPolicy` | Forwarding an asset-valued HTLC |

---

## Price Oracle and Portfolio Pilot

### PriceOracle (`rfq/oracle.go`)

An external (or built-in) service that returns a current `AssetRate` for a
given asset, direction, and intent. The `PriceQueryIntent` enum distinguishes
between hint queries (for rate hints in outgoing Requests) and firm queries
(for deciding whether to accept an incoming Request or validate a peer's quote):

| Intent | Meaning |
|--------|---------|
| `IntentPayInvoiceHint` | Requester wants a hint to include in its Request |
| `IntentPayInvoice` | Responder is deciding how much to offer |
| `IntentPayInvoiceQualify` | Requester is validating the peer's Accept |
| `IntentRecvPaymentHint` | Same pattern, receive direction |
| `IntentRecvPayment` | Responder deciding rate for incoming payment |
| `IntentRecvPaymentQualify` | Requester validating peer's Accept for receive |

### PortfolioPilot (`rfq/portfolio_pilot.go`)

A higher-level decision layer that wraps the oracle. It exposes three methods:

```go
ResolveRequest(ctx, request) → AssetRate or RejectErr
VerifyAcceptQuote(ctx, accept) → QuoteRespStatus
QueryAssetRates(ctx, query) → AssetRate
```

The built-in `InternalPortfolioPilot` delegates to a `PriceOracle`. Custom
implementations can add business rules: credit limits, KYC checks, spread
adjustment, etc.

### Rate Tolerance

When verifying a peer's Accept, the portfolio pilot uses
`rfqmath.FixedPoint.WithinTolerance()` to check that the offered rate is within
a configurable tolerance (default 50,000 ppm = 5%) of the oracle's current
rate. This prevents a peer from quoting a rate that was valid an instant ago
but is now wildly off-market.

---

## Manager Event Loop (`rfq/manager.go`)

The `Manager` is the central coordinator. It runs a single event loop:

```go
select {
  case incomingMsg := <-m.incomingMessages:
    route to Negotiator or store accepted quote
  case outgoingMsg := <-m.outgoingMessages:
    forward to StreamHandler
  case htlcEvent := <-m.acceptHtlcEvents:
    publish to subscribers
  case <-m.Quit:
    return
}
```

When a `BuyAccept` or `SellAccept` arrives from the stream, the manager:

1. Validates it via the negotiator
2. Stores the policy in the `OrderHandler`
3. Derives the SCID from the quote ID (`ID[24:32]`)
4. Registers the SCID as a lnd alias so future HTLCs to it are intercepted

---

## End-to-End Flow: Paying an Invoice with Assets (Sell Order)

```
Wallet Node                    Edge Node                 Price Oracle
     |                             |                          |
     | AddAssetSellOrder           |                          |
     | (assetID, paymentMaxAmt)    |                          |
     |                             |                          |
     | ─── SellRequest ──────────> |                          |
     |     (assetID, maxMsat,      | ─── QueryAssetRates ──> |
     |      optional rate hint)    | <── AssetRate ────────── |
     |                             |                          |
     | <── SellAccept ──────────── |                          |
     |     (rate R, sig)           |                          |
     |                             |                          |
     | [validate sig + rate]       |                          |
     | [register SCID alias]       |                          |
     | [build invoice w/ SCID]     |                          |
     |                             |                          |
     | ─── Lightning HTLC ───────> |                          |
     |     to SCID                 | [CheckHtlcCompliance]    |
     |                             | [convert mSat → units]   |
     |                             | [attach RFQ ID record]   |
     |                             |                          |
     | <── payment settled ─────── |                          |
```

Steps in detail:

1. The wallet calls `UpsertAssetSellOrder()` with the target asset and the
   invoice amount as `PaymentMaxAmt`.
2. The negotiator sends a `SellRequest` to the edge node, optionally including
   a rate hint from the oracle.
3. The edge node's portfolio pilot queries the oracle with
   `IntentPayInvoice`, gets a rate, and returns a signed `SellAccept`.
4. The wallet's negotiator receives the accept, checks the signature, and
   calls `VerifyAcceptQuote()` with `IntentPayInvoiceQualify` to confirm the
   rate is reasonable.
5. The manager derives the SCID from the quote ID and registers it with lnd as
   a channel alias on the edge channel.
6. The wallet builds a Lightning invoice that uses the SCID as a route hint.
7. The paying node routes an HTLC to the edge node via the SCID.
8. The edge node's HTLC interceptor fires. The `AssetSalePolicy` is loaded,
   the mSat amount is converted to asset units using rate R, and the total is
   checked against the policy limits.
9. The HTLC is accepted, custom records are attached, and the payment settles.

---

## End-to-End Flow: Receiving a Payment as Assets (Buy Order)

```
Wallet Node                    Edge Node                 Price Oracle
     |                             |                          |
     | AddAssetBuyOrder            |                          |
     | (assetID, assetMaxAmt)      |                          |
     |                             |                          |
     | ─── BuyRequest ───────────> |                          |
     |                             | ─── QueryAssetRates ──> |
     |                             | <── AssetRate ────────── |
     |                             |                          |
     | <── BuyAccept ──────────── |                          |
     |     (rate R, sig)           |                          |
     |                             |                          |
     | [compute mSat for invoice]  |                          |
     | mSat = units/rate * M       |                          |
     | [create Lightning invoice]  |                          |
     |                             |                          |
     | ─── Lightning HTLC ───────> |                          |
     |     (mSat amount)           | [CheckHtlcCompliance]    |
     |                             | [convert mSat → units]   |
     |                             | [attach RFQ ID record]   |
     |                             |                          |
     | <── settled with assets ─── |                          |
```

The key difference: the wallet knows ahead of time how many asset units it
wants. It gets a rate from the edge node, converts units to mSat to determine
what invoice amount to request, and then the HTLC interceptor on the edge node
performs the reverse conversion to settle in assets.

---

## Rejection Codes

When an edge node cannot fulfill a request, it sends a `Reject` with one of
these codes:

| Code | Meaning |
|------|---------|
| `ErrCodeUnspecified` | Generic failure |
| `ErrCodeUnavailableOracle` | Price oracle is unreachable |
| `ErrCodeMinFillNotMet` | Requested amount below the responder's minimum |
| `ErrCodePriceBoundMiss` | Requester's rate limit cannot be satisfied |

---

## Execution Policies

Requests can specify an `ExecutionPolicy`:

- **IOC (Immediate-or-Cancel)**: Accept partial fills up to the maximum amount.
  The `AcceptedMaxAmount` field in the accept can be less than the requested
  maximum.
- **FOK (Fill-or-Kill)**: Either the full amount is quoted or nothing. No
  partial fills.

---

## Key Files at a Glance

| File | Contents |
|------|---------|
| `rfqmsg/messages.go` | `ID`, `AssetRate`, `WireMessage`, message type constants |
| `rfqmsg/request.go` | `BuyRequest`, `SellRequest` structs and TLV encoding |
| `rfqmsg/accept.go` | `BuyAccept`, `SellAccept` structs and signature handling |
| `rfqmsg/reject.go` | `Reject`, `RejectErr`, `RejectCode` |
| `rfqmsg/records.go` | `Htlc` struct and HTLC custom record TLV types |
| `rfqmath/fixed_point.go` | `FixedPoint[T]` generic type, arithmetic ops |
| `rfqmath/convert.go` | `MilliSatoshiToUnits`, `UnitsToMilliSatoshi` |
| `rfq/manager.go` | `Manager`: central coordinator and event loop |
| `rfq/negotiator.go` | `Negotiator`: quote acceptance/rejection logic |
| `rfq/order.go` | `OrderHandler` and `Policy` types for HTLC enforcement |
| `rfq/stream.go` | `StreamHandler`: peer message I/O |
| `rfq/oracle.go` | `PriceOracle` interface and oracle client |
| `rfq/portfolio_pilot.go` | `PortfolioPilot` interface and built-in implementation |
| `rfq/interface.go` | `PolicyStore`, `ForwardStore`, and other abstractions |
