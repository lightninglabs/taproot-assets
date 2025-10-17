# Forwarding History Implementation Plan

This document outlines the plan to implement a forwarding history feature for edge nodes in the taproot-assets system.

## 1. Database Schema

A new SQL table named `forwarding_events` will be created to store the history of forwarded HTLCs. The schema for this table will be as follows:

```sql
CREATE TABLE forwarding_events (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL,
    incoming_htlc_id BIGINT NOT NULL,
    outgoing_htlc_id BIGINT NOT NULL,
    asset_id BYTEA NOT NULL,
    amount_in BIGINT NOT NULL,
    amount_out BIGINT NOT NULL,
    rate DECIMAL NOT NULL,
    fee BIGINT NOT NULL
);
```

## 2. OrderHandler Integration

The `OrderHandler` will be modified to insert a new record into the `forwarding_events` table whenever an `AcceptHtlcEvent` is handled. The `AcceptHtlcEvent` contains all the necessary information to populate the new table, including the incoming HTLC, the outgoing HTLC, the asset ID, the amounts, the rate, and the fee.

## 3. RPC Endpoint

A new RPC endpoint will be added to the `rfqrpc` service to allow users to query the `forwarding_events` table. The endpoint will support pagination and filtering by asset ID and time range.

## 4. tapcli Command

A new command will be added to `tapcli` that calls the new RPC endpoint and displays the forwarding history to the user. The command will support the same filtering options as the RPC endpoint.
